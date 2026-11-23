package passkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	"github.com/MarioShatterhand/pb-passkeys/internal/store"
	"github.com/MarioShatterhand/pb-passkeys/internal/testauthn"
)

// logCapture is a slog handler that keeps everything logged, at every level,
// as text: the message and all attributes, nested ones included.
type logCapture struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	text slog.Handler
}

func newLogCapture() *logCapture {
	c := &logCapture{}
	c.text = slog.NewTextHandler(&c.buf, &slog.HandlerOptions{Level: slog.LevelDebug})

	return c
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(ctx context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.text.Handle(ctx, r)
}

func (c *logCapture) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logCaptureView{parent: c, handler: c.text.WithAttrs(attrs)}
}

func (c *logCapture) WithGroup(name string) slog.Handler {
	return &logCaptureView{parent: c, handler: c.text.WithGroup(name)}
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.buf.String()
}

// logCaptureView is a derived logger that writes into the same buffer.
type logCaptureView struct {
	parent  *logCapture
	handler slog.Handler
}

func (v *logCaptureView) Enabled(context.Context, slog.Level) bool { return true }

func (v *logCaptureView) Handle(ctx context.Context, r slog.Record) error {
	v.parent.mu.Lock()
	defer v.parent.mu.Unlock()

	return v.handler.Handle(ctx, r)
}

func (v *logCaptureView) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logCaptureView{parent: v.parent, handler: v.handler.WithAttrs(attrs)}
}

func (v *logCaptureView) WithGroup(name string) slog.Handler {
	return &logCaptureView{parent: v.parent, handler: v.handler.WithGroup(name)}
}

// loggedApp is the test app with its logger replaced, so that everything the
// request handlers log through e.App.Logger() can be inspected: the module's
// own lines and PocketBase's request log.
type loggedApp struct {
	core.App
	logger *slog.Logger
}

func (a *loggedApp) Logger() *slog.Logger { return a.logger }

// newLoggedServer is newTestServer with all logging captured and PocketBase's
// request log switched on.
func newLoggedServer(t *testing.T, edit func(*Config)) (*testServer, *logCapture) {
	t.Helper()

	s := newTestServer(t, edit)
	capture := newLogCapture()

	// The test app turns the request log off; it is wanted here, because it
	// records the error message and data of every failed request.
	s.app.Settings().Logs.MaxDays = 7
	s.app.Settings().Logs.MinLevel = int(slog.LevelDebug)

	app := &loggedApp{App: s.app, logger: slog.New(capture)}

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	// Bind the module's routes on the new router without running startup twice.
	event := new(core.ServeEvent)
	event.App = app
	event.Router = router
	s.module.bindRoutes(event)

	mux, err := router.BuildMux()
	if err != nil {
		t.Fatalf("BuildMux: %v", err)
	}

	s.handler = mux

	return s, capture
}

// responseFields returns the base64url values inside credential.response
// (clientDataJSON, attestationObject, authenticatorData, signature, ...).
func responseFields(t *testing.T, credential []byte) map[string]string {
	t.Helper()

	var doc struct {
		Response map[string]any `json:"response"`
	}
	if err := json.Unmarshal(credential, &doc); err != nil {
		t.Fatalf("decode credential: %v", err)
	}

	out := map[string]string{}
	for k, v := range doc.Response {
		if s, ok := v.(string); ok && len(s) >= 16 {
			out[k] = s
		}
	}

	return out
}

// Security invariant 17: tokens, challenges, session data and raw client data
// never reach the log, on success or on failure, at any log level.
func TestLogsContainNoSecrets(t *testing.T) {
	s, capture := newLoggedServer(t, nil)

	// Everything that must not appear in the log, by a name for the report.
	secrets := map[string]string{}
	add := func(name, value string) {
		if len(value) >= 12 {
			secrets[name] = value
		}
	}
	addCredential := func(name string, credential []byte) {
		for field, value := range responseFields(t, credential) {
			add(name+" "+field, value)

			// The decoded client data is also raw client data.
			if field == "clientDataJSON" {
				if raw, err := base64.RawURLEncoding.DecodeString(value); err == nil {
					add(name+" clientDataJSON (decoded)", string(raw))
				}
			}
		}
	}

	alice, aliceToken := s.newRecord("members", "alice@example.com")
	add("alice's auth token", aliceToken)

	auth := testauthn.New()

	// --- registration: success
	opts := s.registerOptions(aliceToken)
	add("registration challenge", opts.Challenge)

	attestation := s.attest(auth, opts, testOrigin)
	addCredential("registration", attestation)

	if status, body := s.registerVerify(aliceToken, attestation, "Phone"); status != http.StatusOK {
		t.Fatalf("register/verify: status %d, body %s", status, body)
	}

	stored := s.storedCredential(alice)
	add("stored public key", stored.GetString(store.FieldPublicKey))

	// --- registration: failures
	// The same response again (challenge already used).
	if status, _ := s.registerVerify(aliceToken, attestation, "Phone"); status != http.StatusBadRequest {
		t.Fatalf("replayed registration: status %d, want 400", status)
	}

	// A response from another origin.
	opts = s.registerOptions(aliceToken)
	add("second registration challenge", opts.Challenge)

	wrongOrigin := s.attest(testauthn.New(), opts, "https://evil.example")
	addCredential("wrong-origin registration", wrongOrigin)

	if status, _ := s.registerVerify(aliceToken, wrongOrigin, "x"); status != http.StatusBadRequest {
		t.Fatalf("wrong-origin registration: status %d, want 400", status)
	}

	// A response without user verification.
	opts = s.registerOptions(aliceToken)
	add("third registration challenge", opts.Challenge)

	noUV := testauthn.New()
	noUV.UserVerified = false

	noUVAttestation := s.attest(noUV, opts, testOrigin)
	addCredential("no-UV registration", noUVAttestation)

	if status, _ := s.registerVerify(aliceToken, noUVAttestation, "x"); status != http.StatusBadRequest {
		t.Fatalf("no-UV registration: status %d, want 400", status)
	}

	// A body that is not a WebAuthn response at all.
	s.post("/api/passkeys/members/register/verify", aliceToken, `{"credential":{"id":"AAAA"},"name":"x"}`)

	// --- login: success
	loginOpts := s.loginOptions("members")
	add("login challenge", loginOpts.Challenge)

	assertion := s.assert(auth, loginOpts, testOrigin)
	addCredential("login", assertion)

	status, body := s.loginVerify("members", assertion)
	if status != http.StatusOK {
		t.Fatalf("login/verify: status %d, body %s", status, body)
	}

	var authResponse struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &authResponse); err != nil || authResponse.Token == "" {
		t.Fatalf("no token in the login response: %s", body)
	}
	add("token issued by the login", authResponse.Token)

	// --- login: failures
	if status, _ := s.loginVerify("members", assertion); status != http.StatusBadRequest {
		t.Fatalf("replayed login: status %d, want 400", status)
	}

	loginOpts = s.loginOptions("members")
	add("second login challenge", loginOpts.Challenge)

	wrongOriginAssertion := s.assert(auth, loginOpts, "https://evil.example")
	addCredential("wrong-origin login", wrongOriginAssertion)

	if status, _ := s.loginVerify("members", wrongOriginAssertion); status != http.StatusBadRequest {
		t.Fatalf("wrong-origin login: status %d, want 400", status)
	}

	loginOpts = s.loginOptions("members")
	add("third login challenge", loginOpts.Challenge)

	tampered := setResponseField(t, s.assert(auth, loginOpts, testOrigin), "signature", []byte("forged signature bytes"))
	addCredential("tampered login", tampered)

	if status, _ := s.loginVerify("members", tampered); status != http.StatusBadRequest {
		t.Fatalf("tampered login: status %d, want 400", status)
	}

	// A login refused by an application hook.
	loginOpts = s.loginOptions("members")
	add("fourth login challenge", loginOpts.Challenge)

	hookID := s.module.OnBeforeLogin().BindFunc(func(*BeforeLoginEvent) error {
		return errors.New("refused by the application")
	})

	refused := s.assert(auth, loginOpts, testOrigin)
	addCredential("hook-refused login", refused)

	if status, _ := s.loginVerify("members", refused); status != http.StatusBadRequest {
		t.Fatalf("hook-refused login: status %d, want 400", status)
	}

	s.module.OnBeforeLogin().Unbind(hookID)

	// A ceremony left pending: its challenge and session data stay in the database.
	pending := s.loginOptions("members")
	add("pending login challenge", pending.Challenge)

	// --- the log
	log := capture.String()

	// The capture must be working, or the test proves nothing.
	for _, want := range []string{
		"passkeys: registration refused",
		"passkeys: login refused",
		"evil.example", // the reason of an origin mismatch is logged
		"refused by the application",
		"/api/passkeys/members/login/verify", // PocketBase's request log
		"Failed to authenticate.",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("the captured log does not contain %q; the capture may be broken", want)
		}
	}

	for name, secret := range secrets {
		if strings.Contains(log, secret) {
			t.Errorf("the log contains %s", name)
		}

		// The same value inside a JSON-encoded attribute would have its
		// quotes escaped.
		if escaped := strings.Trim(fmt.Sprintf("%q", secret), `"`); escaped != secret && strings.Contains(log, escaped) {
			t.Errorf("the log contains %s (escaped)", name)
		}
	}

	if t.Failed() {
		t.Logf("captured log:\n%s", log)
	}
}

// Secrets travel in JSON bodies only (hard rule 4 and security invariant 17):
// no route of the module has a path parameter other than the collection, and
// no handler reads the query string.
func TestRoutesTakeNoSecretsFromTheURL(t *testing.T) {
	s := newTestServer(t, nil)
	_, token := s.newRecord("members", "alice@example.com")
	auth := testauthn.New()
	s.register(auth, token, "Phone")

	// A valid login response moved from the body into the query string is not accepted.
	credential := s.assert(auth, s.loginOptions("members"), testOrigin)

	req := httptest.NewRequest(http.MethodPost, "/api/passkeys/members/login/verify?credential="+base64.RawURLEncoding.EncodeToString(credential), strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)

	wantLoginFailed(t, rec.Code, rec.Body.Bytes())

	// The routes the module binds: each is {prefix}/{collection}/<fixed words>.
	for _, path := range modulePaths {
		if strings.Count(path, "{") != 0 {
			t.Errorf("route %q has a path parameter besides the collection", path)
		}
	}
}
