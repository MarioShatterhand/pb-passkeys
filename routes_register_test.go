package passkeys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"

	"github.com/MarioShatterhand/pb-passkeys/internal/store"
	"github.com/MarioShatterhand/pb-passkeys/internal/testauthn"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

// testServer is an in-process PocketBase with the module registered and its
// HTTP handler built, so that tests can run whole ceremonies over HTTP.
type testServer struct {
	t       *testing.T
	app     *tests.TestApp
	module  *Module
	handler http.Handler
}

// newTestServer registers the module for the "members" collection. A second
// auth collection, "partners", exists but is not configured for passkeys.
func newTestServer(t *testing.T, edit func(*Config)) *testServer {
	t.Helper()

	app := newTestApp(t)

	if err := app.Save(core.NewAuthCollection("partners")); err != nil {
		t.Fatalf("create partners collection: %v", err)
	}

	cfg := testConfig("members")
	if edit != nil {
		edit(&cfg)
	}

	module, err := Register(app, cfg)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	event := new(core.ServeEvent)
	event.App = app
	event.Router = router

	var handler http.Handler

	err = app.OnServe().Trigger(event, func(e *core.ServeEvent) error {
		mux, err := e.Router.BuildMux()
		handler = mux

		return err
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}

	return &testServer{t: t, app: app, module: module, handler: handler}
}

// post sends a JSON POST request and returns the status and the body.
func (s *testServer) post(path, token string, body any) (int, []byte) {
	s.t.Helper()

	var reader io.Reader

	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	case []byte:
		reader = bytes.NewReader(b)
	default:
		encoded, err := json.Marshal(b)
		if err != nil {
			s.t.Fatalf("encode request body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req := httptest.NewRequest(http.MethodPost, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)

	return rec.Code, rec.Body.Bytes()
}

// newRecord creates a user in an auth collection and returns it with an auth token.
func (s *testServer) newRecord(collection, email string) (*core.Record, string) {
	s.t.Helper()

	c, err := s.app.FindCollectionByNameOrId(collection)
	if err != nil {
		s.t.Fatalf("find %s: %v", collection, err)
	}

	record := core.NewRecord(c)
	record.SetEmail(email)
	record.SetRandomPassword()

	if err := s.app.Save(record); err != nil {
		s.t.Fatalf("create %s: %v", email, err)
	}

	token, err := record.NewAuthToken()
	if err != nil {
		s.t.Fatalf("NewAuthToken: %v", err)
	}

	return record, token
}

func (s *testServer) count(collection string) int {
	s.t.Helper()

	n, err := s.app.CountRecords(collection)
	if err != nil {
		s.t.Fatalf("count %s: %v", collection, err)
	}

	return int(n)
}

// creationOptions are the fields of the registration options the tests read.
type creationOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Exclude []struct {
		ID string `json:"id"`
	} `json:"excludeCredentials"`
}

// registerOptions calls register/options and requires success.
func (s *testServer) registerOptions(token string) creationOptions {
	s.t.Helper()

	status, body := s.post("/api/passkeys/members/register/options", token, nil)
	if status != http.StatusOK {
		s.t.Fatalf("register/options: status %d, body %s", status, body)
	}

	var opts creationOptions
	if err := json.Unmarshal(body, &opts); err != nil {
		s.t.Fatalf("register/options: body is not JSON: %v\n%s", err, body)
	}
	if opts.Challenge == "" {
		s.t.Fatalf("register/options: no challenge in %s", body)
	}

	return opts
}

// attest lets the authenticator answer registration options.
func (s *testServer) attest(auth *testauthn.Authenticator, opts creationOptions, origin string) []byte {
	s.t.Helper()

	handle, err := base64.RawURLEncoding.DecodeString(opts.User.ID)
	if err != nil {
		s.t.Fatalf("user.id is not base64url: %v", err)
	}

	resp, err := auth.Create(testauthn.CreateOptions{
		RPID:       opts.RP.ID,
		Origin:     origin,
		Challenge:  opts.Challenge,
		UserHandle: handle,
	})
	if err != nil {
		s.t.Fatalf("authenticator: %v", err)
	}

	return resp.JSON
}

// registerVerify calls register/verify with a credential and a name.
func (s *testServer) registerVerify(token string, credential []byte, name string) (int, []byte) {
	s.t.Helper()

	return s.post("/api/passkeys/members/register/verify", token, map[string]any{
		"credential": json.RawMessage(credential),
		"name":       name,
	})
}

// register runs a whole registration ceremony and requires success.
func (s *testServer) register(auth *testauthn.Authenticator, token, name string) map[string]any {
	s.t.Helper()

	opts := s.registerOptions(token)

	status, body := s.registerVerify(token, s.attest(auth, opts, testOrigin), name)
	if status != http.StatusOK {
		s.t.Fatalf("register/verify: status %d, body %s", status, body)
	}

	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		s.t.Fatalf("register/verify: body is not JSON: %v", err)
	}

	return record
}

// wantGenericFailure asserts the single response all refused registrations share.
func wantGenericFailure(t *testing.T, status int, body []byte) {
	t.Helper()

	const want = `{"data":{},"message":"Failed to register the passkey.","status":400}`

	if status != http.StatusBadRequest || strings.TrimSpace(string(body)) != want {
		t.Errorf("status %d, body %s\nwant 400 and %s", status, body, want)
	}
}

func TestRegisterCeremony(t *testing.T) {
	s := newTestServer(t, nil)
	alice, token := s.newRecord("members", "alice@example.com")
	auth := testauthn.New()

	opts := s.registerOptions(token)

	if opts.RP.ID != testRPID {
		t.Errorf("rp.id = %q, want %q", opts.RP.ID, testRPID)
	}
	if want := base64.RawURLEncoding.EncodeToString([]byte(alice.Id)); opts.User.ID != want {
		t.Errorf("user.id = %q, want the base64url record ID %q", opts.User.ID, want)
	}
	if opts.User.Name != "alice@example.com" || opts.User.DisplayName != "alice@example.com" {
		t.Errorf("user = %+v, want the email as name and display name", opts.User)
	}
	if len(opts.Exclude) != 0 {
		t.Errorf("excludeCredentials = %v, want none for the first passkey", opts.Exclude)
	}
	if n := s.count(DefaultChallengesCollection); n != 1 {
		t.Fatalf("stored challenges = %d, want 1", n)
	}

	status, body := s.registerVerify(token, s.attest(auth, opts, testOrigin), "  Phone  ")
	if status != http.StatusOK {
		t.Fatalf("register/verify: status %d, body %s", status, body)
	}

	// The response is the credential record as the collection API would return it.
	for _, want := range []string{`"name":"Phone"`, `"recordRef":"` + alice.Id + `"`, `"collectionName":"passkey_credentials"`, `"signCount":1`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("response does not contain %s\n%s", want, body)
		}
	}
	if strings.Contains(string(body), "publicKey") {
		t.Errorf("response exposes the public key:\n%s", body)
	}

	if n := s.count(DefaultChallengesCollection); n != 0 {
		t.Errorf("challenges after verification = %d, want 0", n)
	}

	records, err := store.ListCredentials(s.app, s.module.names, alice.Collection().Id, alice.Id)
	if err != nil || len(records) != 1 {
		t.Fatalf("stored credentials = %d, %v; want 1", len(records), err)
	}

	got := records[0]
	if want := base64.RawURLEncoding.EncodeToString(auth.CredentialIDs()[0]); got.GetString(store.FieldCredentialID) != want {
		t.Errorf("credentialId = %q, want %q", got.GetString(store.FieldCredentialID), want)
	}
	if got.GetString(store.FieldPublicKey) == "" {
		t.Error("no public key stored")
	}

	var transports []string
	_ = got.UnmarshalJSONField(store.FieldTransports, &transports)

	if got.GetString(store.FieldAAGUID) != "00000000-0000-0000-0000-000000000000" ||
		got.GetString(store.FieldAuthenticatorAttachment) != "platform" ||
		got.GetString(store.FieldAttestationFormat) != "none" ||
		got.GetBool(store.FieldBackupEligible) || got.GetBool(store.FieldBackupState) ||
		len(transports) != 1 || transports[0] != "internal" {
		t.Errorf("stored authenticator data is wrong: %v", got.PublicExport())
	}

	// The stored record converts back into what the ceremonies need.
	back, err := credentialFromRecord(got)
	if err != nil {
		t.Fatalf("credentialFromRecord: %v", err)
	}
	if !bytes.Equal(back.ID, auth.CredentialIDs()[0]) || back.SignCount != 1 || len(back.AAGUID) != 16 {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestRegisterSecondPasskey(t *testing.T) {
	s := newTestServer(t, nil)
	alice, token := s.newRecord("members", "alice@example.com")

	first := s.register(testauthn.New(), token, "Phone")

	opts := s.registerOptions(token)
	if len(opts.Exclude) != 1 || opts.Exclude[0].ID != first["credentialId"] {
		t.Errorf("excludeCredentials = %v, want the first passkey %v", opts.Exclude, first["credentialId"])
	}

	s.register(testauthn.New(), token, "Laptop")

	n, err := store.CountCredentials(s.app, s.module.names, alice.Collection().Id, alice.Id)
	if err != nil || n != 2 {
		t.Errorf("credentials = %d, %v; want 2", n, err)
	}

	synced := testauthn.New()
	synced.BackupEligible, synced.BackupState, synced.ZeroSignCount = true, true, true
	synced.Attachment, synced.Transports = "cross-platform", []string{"hybrid", "internal"}

	third := s.register(synced, token, "")
	if third["backupEligible"] != true || third["backupState"] != true || third["authenticatorAttachment"] != "cross-platform" || third["name"] != "" {
		t.Errorf("third passkey = %v, want the synced flags, cross-platform and no name", third)
	}
}

// Security invariant 3: a credential ID that is already registered is refused,
// for another user and for the same one.
func TestRegisterExistingCredentialIDRejected(t *testing.T) {
	s := newTestServer(t, nil)
	_, aliceToken := s.newRecord("members", "alice@example.com")
	_, bobToken := s.newRecord("members", "bob@example.com")

	original := testauthn.New()
	s.register(original, aliceToken, "Phone")
	takenID := original.CredentialIDs()[0]

	for name, token := range map[string]string{"another user": bobToken, "the same user": aliceToken} {
		t.Run(name, func(t *testing.T) {
			forger := testauthn.New()
			forger.NextCredentialID = takenID

			opts := s.registerOptions(token)
			status, body := s.registerVerify(token, s.attest(forger, opts, testOrigin), "Forged")
			wantGenericFailure(t, status, body)

			if n := s.count(DefaultCredentialsCollection); n != 1 {
				t.Errorf("credentials = %d, want only the original", n)
			}
		})
	}
}

func TestRegisterCredentialLimit(t *testing.T) {
	const limitBody = `{"data":{},"message":"The passkey limit for this account is reached.","status":400}`

	t.Run("options refused at the limit", func(t *testing.T) {
		s := newTestServer(t, func(c *Config) { c.MaxCredentialsPerUser = 1 })
		_, token := s.newRecord("members", "alice@example.com")
		s.register(testauthn.New(), token, "Phone")

		status, body := s.post("/api/passkeys/members/register/options", token, nil)
		if status != http.StatusBadRequest || strings.TrimSpace(string(body)) != limitBody {
			t.Errorf("status %d, body %s; want the limit error", status, body)
		}
		if n := s.count(DefaultChallengesCollection); n != 0 {
			t.Errorf("challenges = %d, want none stored for a refused request", n)
		}
	})

	// Two ceremonies started below the limit: only the first to finish gets in.
	t.Run("limit enforced again at verification", func(t *testing.T) {
		s := newTestServer(t, func(c *Config) { c.MaxCredentialsPerUser = 1 })
		_, token := s.newRecord("members", "alice@example.com")

		first, second := s.registerOptions(token), s.registerOptions(token)

		if status, body := s.registerVerify(token, s.attest(testauthn.New(), first, testOrigin), "One"); status != http.StatusOK {
			t.Fatalf("first verification: status %d, body %s", status, body)
		}

		status, body := s.registerVerify(token, s.attest(testauthn.New(), second, testOrigin), "Two")
		if status != http.StatusBadRequest || strings.TrimSpace(string(body)) != limitBody {
			t.Errorf("second verification: status %d, body %s; want the limit error", status, body)
		}
		if n := s.count(DefaultCredentialsCollection); n != 1 {
			t.Errorf("credentials = %d, want 1", n)
		}
	})
}

func TestRegisterAccessControl(t *testing.T) {
	s := newTestServer(t, nil)
	_, memberToken := s.newRecord("members", "alice@example.com")
	_, partnerToken := s.newRecord("partners", "carol@example.com")

	superuser, err := s.app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatalf("find superuser: %v", err)
	}
	superuserToken, err := superuser.NewAuthToken()
	if err != nil {
		t.Fatalf("superuser token: %v", err)
	}

	members, err := s.app.FindCollectionByNameOrId("members")
	if err != nil {
		t.Fatalf("find members: %v", err)
	}

	tests := []struct {
		name       string
		collection string
		token      string
		want       int
	}{
		{"no token", "members", "", http.StatusUnauthorized},
		{"invalid token", "members", "not-a-token", http.StatusUnauthorized},
		{"token of another auth collection", "members", partnerToken, http.StatusForbidden},
		{"superuser token", "members", superuserToken, http.StatusForbidden},
		{"auth collection without passkeys", "partners", partnerToken, http.StatusNotFound},
		{"base collection", "notes", memberToken, http.StatusNotFound},
		{"unknown collection", "nobody", memberToken, http.StatusNotFound},
		{"superusers collection", core.CollectionNameSuperusers, superuserToken, http.StatusNotFound},
		{"collection by ID", members.Id, memberToken, http.StatusOK},
		{"collection name in another case", "MEMBERS", memberToken, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := s.post("/api/passkeys/"+tt.collection+"/register/options", tt.token, nil)
			if status != tt.want {
				t.Errorf("register/options: status %d, want %d (%s)", status, tt.want, body)
			}

			if tt.want != http.StatusOK {
				status, body = s.post("/api/passkeys/"+tt.collection+"/register/verify", tt.token, `{"credential":{}}`)
				if status != tt.want {
					t.Errorf("register/verify: status %d, want %d (%s)", status, tt.want, body)
				}
			}
		})
	}

	if n := s.count(DefaultCredentialsCollection); n != 0 {
		t.Errorf("credentials = %d, want 0", n)
	}
}

func TestRegisterVerifyRejected(t *testing.T) {
	// Each case starts a ceremony for alice and then does something wrong.
	type scenario struct {
		s          *testServer
		aliceToken string
		bobToken   string
		opts       creationOptions
	}

	tests := []struct {
		name string
		cfg  func(*Config)
		run  func(sc scenario) (int, []byte)
	}{
		{
			name: "response from another origin",
			run: func(sc scenario) (int, []byte) {
				return sc.s.registerVerify(sc.aliceToken, sc.s.attest(testauthn.New(), sc.opts, "https://evil.example"), "x")
			},
		},
		{
			name: "response without user verification",
			run: func(sc scenario) (int, []byte) {
				auth := testauthn.New()
				auth.UserVerified = false

				return sc.s.registerVerify(sc.aliceToken, sc.s.attest(auth, sc.opts, testOrigin), "x")
			},
		},
		{
			// Security invariant 2: a challenge is single-use.
			name: "response sent twice",
			run: func(sc scenario) (int, []byte) {
				credential := sc.s.attest(testauthn.New(), sc.opts, testOrigin)
				if status, body := sc.s.registerVerify(sc.aliceToken, credential, "x"); status != http.StatusOK {
					sc.s.t.Fatalf("first use: status %d, body %s", status, body)
				}

				status, body := sc.s.registerVerify(sc.aliceToken, credential, "x")
				if n := sc.s.count(DefaultCredentialsCollection); n != 1 {
					sc.s.t.Errorf("credentials = %d, want 1", n)
				}

				// Remove the legitimate credential so the shared check below sees none.
				records, _ := sc.s.app.FindAllRecords(DefaultCredentialsCollection)
				for _, r := range records {
					_ = sc.s.app.Delete(r)
				}

				return status, body
			},
		},
		{
			name: "ceremony of another user",
			run: func(sc scenario) (int, []byte) {
				return sc.s.registerVerify(sc.bobToken, sc.s.attest(testauthn.New(), sc.opts, testOrigin), "x")
			},
		},
		{
			name: "challenge that was never issued",
			run: func(sc scenario) (int, []byte) {
				forged := sc.opts
				forged.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

				return sc.s.registerVerify(sc.aliceToken, sc.s.attest(testauthn.New(), forged, testOrigin), "x")
			},
		},
		{
			name: "expired ceremony",
			cfg:  func(c *Config) { c.ChallengeTTL = 40 * time.Millisecond; c.Timeout = 40 * time.Millisecond },
			run: func(sc scenario) (int, []byte) {
				credential := sc.s.attest(testauthn.New(), sc.opts, testOrigin)
				time.Sleep(80 * time.Millisecond)

				return sc.s.registerVerify(sc.aliceToken, credential, "x")
			},
		},
		{
			name: "body without a credential",
			run: func(sc scenario) (int, []byte) {
				return sc.s.post("/api/passkeys/members/register/verify", sc.aliceToken, `{"name":"x"}`)
			},
		},
		{
			name: "body that is not JSON",
			run: func(sc scenario) (int, []byte) {
				return sc.s.post("/api/passkeys/members/register/verify", sc.aliceToken, `{"credential":`)
			},
		},
		{
			name: "credential that is not a WebAuthn response",
			run: func(sc scenario) (int, []byte) {
				return sc.s.post("/api/passkeys/members/register/verify", sc.aliceToken, `{"credential":{"id":"AAAA"}}`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.cfg)
			_, aliceToken := s.newRecord("members", "alice@example.com")
			_, bobToken := s.newRecord("members", "bob@example.com")

			status, body := tt.run(scenario{s: s, aliceToken: aliceToken, bobToken: bobToken, opts: s.registerOptions(aliceToken)})
			wantGenericFailure(t, status, body)

			if n := s.count(DefaultCredentialsCollection); n != 0 {
				t.Errorf("credentials = %d, want 0", n)
			}
		})
	}
}

// A challenge is used up by the attempt that presents it, even a failed one.
func TestRegisterFailedAttemptConsumesChallenge(t *testing.T) {
	s := newTestServer(t, nil)
	_, token := s.newRecord("members", "alice@example.com")
	opts := s.registerOptions(token)

	status, body := s.registerVerify(token, s.attest(testauthn.New(), opts, "https://evil.example"), "x")
	wantGenericFailure(t, status, body)

	// The same ceremony, now answered correctly, is gone.
	status, body = s.registerVerify(token, s.attest(testauthn.New(), opts, testOrigin), "x")
	wantGenericFailure(t, status, body)

	if n := s.count(DefaultChallengesCollection); n != 0 {
		t.Errorf("challenges = %d, want 0", n)
	}
}

func TestRegisterNameValidation(t *testing.T) {
	s := newTestServer(t, nil)
	_, token := s.newRecord("members", "alice@example.com")

	t.Run("too long", func(t *testing.T) {
		opts := s.registerOptions(token)

		status, body := s.registerVerify(token, s.attest(testauthn.New(), opts, testOrigin), strings.Repeat("x", 65))
		if status != http.StatusBadRequest || !strings.Contains(string(body), "name is too long") {
			t.Errorf("status %d, body %s; want the name error", status, body)
		}
	})

	t.Run("64 characters of any script accepted", func(t *testing.T) {
		name := strings.Repeat("ż", 64)

		if got := s.register(testauthn.New(), token, name); got["name"] != name {
			t.Errorf("name = %v, want it stored unchanged", got["name"])
		}
	})
}

func TestRegisterPendingChallengesCap(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.MaxPendingChallenges = 2 })
	_, token := s.newRecord("members", "alice@example.com")

	s.registerOptions(token)
	s.registerOptions(token)

	status, body := s.post("/api/passkeys/members/register/options", token, nil)
	if status != http.StatusTooManyRequests {
		t.Errorf("status %d, body %s; want 429", status, body)
	}
	if n := s.count(DefaultChallengesCollection); n != 2 {
		t.Errorf("challenges = %d, want 2", n)
	}
}

func TestRegistrationOptionsHook(t *testing.T) {
	t.Run("can change the names shown to the user", func(t *testing.T) {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")

		var seen *core.Record

		s.module.OnRegistrationOptions().BindFunc(func(e *RegistrationOptionsEvent) error {
			seen = e.Record
			e.UserName, e.UserDisplayName = "alice", "Alice A."

			return e.Next()
		})

		opts := s.registerOptions(token)
		if opts.User.Name != "alice" || opts.User.DisplayName != "Alice A." {
			t.Errorf("user = %+v, want the names set by the hook", opts.User)
		}
		if seen == nil || seen.Id != alice.Id {
			t.Error("the hook did not receive the signed-in record")
		}
	})

	t.Run("can refuse with a plain error", func(t *testing.T) {
		s := newTestServer(t, nil)
		_, token := s.newRecord("members", "alice@example.com")

		s.module.OnRegistrationOptions().BindFunc(func(*RegistrationOptionsEvent) error {
			return errors.New("internal reason that must not reach the client")
		})

		status, body := s.post("/api/passkeys/members/register/options", token, nil)
		wantGenericFailure(t, status, body)

		if n := s.count(DefaultChallengesCollection); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
	})

	t.Run("can refuse with its own API error", func(t *testing.T) {
		s := newTestServer(t, nil)
		_, token := s.newRecord("members", "alice@example.com")

		s.module.OnRegistrationOptions().BindFunc(func(e *RegistrationOptionsEvent) error {
			return e.ForbiddenError("Passkeys are not enabled for this account.", nil)
		})

		status, body := s.post("/api/passkeys/members/register/options", token, nil)
		if status != http.StatusForbidden || !strings.Contains(string(body), "Passkeys are not enabled for this account.") {
			t.Errorf("status %d, body %s; want the hook's 403", status, body)
		}
	})
}

func TestCredentialRegisteredHook(t *testing.T) {
	t.Run("runs with the saved credential", func(t *testing.T) {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")

		var got *CredentialRegisteredEvent

		s.module.OnCredentialRegistered().BindFunc(func(e *CredentialRegisteredEvent) error {
			got = e

			// The credential is visible inside the transaction.
			if n, err := e.App.CountRecords(DefaultCredentialsCollection); err != nil || n != 1 {
				t.Errorf("credentials inside the hook = %d, %v; want 1", n, err)
			}

			return e.Next()
		})

		s.register(testauthn.New(), token, "Phone")

		if got == nil {
			t.Fatal("the hook did not run")
		}
		if got.Record.Id != alice.Id || got.Credential.GetString(store.FieldName) != "Phone" || got.Request == nil {
			t.Errorf("event = %+v, want alice, her new credential and the request", got)
		}
	})

	t.Run("an error rolls the registration back", func(t *testing.T) {
		s := newTestServer(t, nil)
		_, token := s.newRecord("members", "alice@example.com")

		s.module.OnCredentialRegistered().BindFunc(func(*CredentialRegisteredEvent) error {
			return errors.New("audit log unavailable")
		})

		opts := s.registerOptions(token)
		status, body := s.registerVerify(token, s.attest(testauthn.New(), opts, testOrigin), "Phone")
		wantGenericFailure(t, status, body)

		if n := s.count(DefaultCredentialsCollection); n != 0 {
			t.Errorf("credentials = %d, want the registration rolled back", n)
		}
	})
}

func TestSignCountFromInt(t *testing.T) {
	for in, want := range map[int64]uint32{
		-1:             0,
		0:              0,
		7:              7,
		math.MaxUint32: math.MaxUint32,
		1 << 40:        math.MaxUint32,
	} {
		if got := signCountFromInt(in); got != want {
			t.Errorf("signCountFromInt(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestAAGUIDFormatting(t *testing.T) {
	raw := []byte{0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4}

	text := formatAAGUID(raw)
	if text != "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4" {
		t.Errorf("formatAAGUID = %q", text)
	}
	if back := parseAAGUID(text); !bytes.Equal(back, raw) {
		t.Errorf("parseAAGUID(%q) = %x, want %x", text, back, raw)
	}

	if got := formatAAGUID([]byte{1, 2, 3}); got != "" {
		t.Errorf("formatAAGUID(short) = %q, want empty", got)
	}
	for _, bad := range []string{"", "not-a-guid", "ea9b8d66"} {
		if got := parseAAGUID(bad); got != nil {
			t.Errorf("parseAAGUID(%q) = %x, want nil", bad, got)
		}
	}
}
