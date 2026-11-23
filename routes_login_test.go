package passkeys

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"

	"github.com/MarioShatterhand/pb-passkeys/internal/store"
	"github.com/MarioShatterhand/pb-passkeys/internal/testauthn"
)

// loginFailedBody is the single response every failed login shares.
const loginFailedBody = `{"data":{},"message":"Failed to authenticate.","status":400}`

// requestOptions are the fields of the login options the tests read.
type requestOptions struct {
	Challenge        string `json:"challenge"`
	RPID             string `json:"rpId"`
	UserVerification string `json:"userVerification"`
	AllowCredentials []any  `json:"allowCredentials"`
}

func (s *testServer) get(path, token string) (int, []byte) {
	s.t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)

	return rec.Code, rec.Body.Bytes()
}

// loginOptions calls login/options without any credentials and requires success.
func (s *testServer) loginOptions(collection string) requestOptions {
	s.t.Helper()

	status, body := s.post("/api/passkeys/"+collection+"/login/options", "", nil)
	if status != http.StatusOK {
		s.t.Fatalf("login/options: status %d, body %s", status, body)
	}

	var opts requestOptions
	if err := json.Unmarshal(body, &opts); err != nil {
		s.t.Fatalf("login/options: body is not JSON: %v\n%s", err, body)
	}
	if opts.Challenge == "" {
		s.t.Fatalf("login/options: no challenge in %s", body)
	}

	return opts
}

// assert lets the authenticator answer login options.
func (s *testServer) assert(auth *testauthn.Authenticator, opts requestOptions, origin string) []byte {
	s.t.Helper()

	resp, err := auth.Get(testauthn.GetOptions{RPID: opts.RPID, Origin: origin, Challenge: opts.Challenge})
	if err != nil {
		s.t.Fatalf("authenticator: %v", err)
	}

	return resp.JSON
}

func (s *testServer) loginVerify(collection string, credential []byte) (int, []byte) {
	s.t.Helper()

	return s.post("/api/passkeys/"+collection+"/login/verify", "", map[string]any{"credential": json.RawMessage(credential)})
}

// login runs a whole login ceremony for the members collection.
func (s *testServer) login(auth *testauthn.Authenticator) (int, []byte) {
	s.t.Helper()

	return s.loginVerify("members", s.assert(auth, s.loginOptions("members"), testOrigin))
}

// setResponseField replaces response.<field> of a credential with the base64url form of value.
func setResponseField(t *testing.T, credential []byte, field string, value []byte) []byte {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(credential, &doc); err != nil {
		t.Fatalf("decode credential: %v", err)
	}

	response := doc["response"].(map[string]any)
	if value == nil {
		delete(response, field)
	} else {
		response[field] = base64.RawURLEncoding.EncodeToString(value)
	}

	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode credential: %v", err)
	}

	return out
}

func wantLoginFailed(t *testing.T, status int, body []byte) {
	t.Helper()

	if status != http.StatusBadRequest || strings.TrimSpace(string(body)) != loginFailedBody {
		t.Errorf("status %d, body %s\nwant 400 and %s", status, body, loginFailedBody)
	}
}

// storedCredential returns the single credential record of a user.
func (s *testServer) storedCredential(owner *core.Record) *core.Record {
	s.t.Helper()

	records, err := store.ListCredentials(s.app, s.module.names, owner.Collection().Id, owner.Id)
	if err != nil || len(records) != 1 {
		s.t.Fatalf("credentials of %s = %d, %v; want 1", owner.Email(), len(records), err)
	}

	return records[0]
}

func TestLoginCeremony(t *testing.T) {
	s := newTestServer(t, nil)
	alice, registerToken := s.newRecord("members", "alice@example.com")
	auth := testauthn.New()
	s.register(auth, registerToken, "Phone")

	var authMethod string

	s.app.OnRecordAuthRequest().BindFunc(func(e *core.RecordAuthRequestEvent) error {
		authMethod = e.AuthMethod
		return e.Next()
	})

	opts := s.loginOptions("members")
	if opts.RPID != testRPID || opts.UserVerification != "required" || len(opts.AllowCredentials) != 0 {
		t.Errorf("options = %+v, want the RP ID, required user verification and no allowCredentials", opts)
	}

	before := time.Now().Add(-time.Second)

	status, body := s.loginVerify("members", s.assert(auth, opts, testOrigin))
	if status != http.StatusOK {
		t.Fatalf("login/verify: status %d, body %s", status, body)
	}

	// The standard PocketBase auth response.
	var response struct {
		Token  string `json:"token"`
		Record struct {
			ID             string `json:"id"`
			CollectionName string `json:"collectionName"`
			Email          string `json:"email"`
		} `json:"record"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if response.Token == "" || response.Record.ID != alice.Id || response.Record.CollectionName != "members" || response.Record.Email != "alice@example.com" {
		t.Errorf("auth response = %s, want a token and alice's record", body)
	}
	if authMethod != AuthMethod {
		t.Errorf("OnRecordAuthRequest saw method %q, want %q", authMethod, AuthMethod)
	}

	// The token is an ordinary PocketBase token: API rules work with it.
	status, list := s.get("/api/collections/passkey_credentials/records", response.Token)
	if status != http.StatusOK || !strings.Contains(string(list), `"totalItems":1`) || !strings.Contains(string(list), `"name":"Phone"`) {
		t.Errorf("collection API with the new token: status %d, body %s", status, list)
	}

	credential := s.storedCredential(alice)
	if got := credential.GetInt(store.FieldSignCount); got != 2 {
		t.Errorf("stored sign count = %d, want 2", got)
	}
	if used := credential.GetDateTime(store.FieldLastUsedAt).Time(); used.Before(before) {
		t.Errorf("lastUsedAt = %s, want it set by the login", used)
	}
	if n := s.count(DefaultChallengesCollection); n != 0 {
		t.Errorf("challenges after login = %d, want 0", n)
	}

	// A second login with the same passkey works and moves the counter on.
	if status, body := s.login(auth); status != http.StatusOK {
		t.Fatalf("second login: status %d, body %s", status, body)
	}
	if got := s.storedCredential(alice).GetInt(store.FieldSignCount); got != 3 {
		t.Errorf("stored sign count after the second login = %d, want 3", got)
	}
}

func TestLoginUpdatesBackupState(t *testing.T) {
	s := newTestServer(t, nil)
	alice, token := s.newRecord("members", "alice@example.com")

	auth := testauthn.New()
	auth.BackupEligible, auth.ZeroSignCount = true, true
	s.register(auth, token, "Synced")

	auth.BackupState = true // the passkey has been synced since

	if status, body := s.login(auth); status != http.StatusOK {
		t.Fatalf("login: status %d, body %s", status, body)
	}
	if !s.storedCredential(alice).GetBool(store.FieldBackupState) {
		t.Error("backupState was not updated from the login")
	}
}

func TestLoginRejected(t *testing.T) {
	type scenario struct {
		s    *testServer
		auth *testauthn.Authenticator // holds alice's registered passkey
		bob  *core.Record
	}

	tests := []struct {
		name string
		cfg  func(*Config)
		run  func(sc scenario) (int, []byte)
	}{
		{
			name: "response from another origin",
			run: func(sc scenario) (int, []byte) {
				return sc.s.loginVerify("members", sc.s.assert(sc.auth, sc.s.loginOptions("members"), "https://evil.example"))
			},
		},
		{
			name: "response without user verification",
			run: func(sc scenario) (int, []byte) {
				sc.auth.UserVerified = false
				return sc.s.login(sc.auth)
			},
		},
		{
			// Security invariant 23.
			name: "backup-eligible flag changed",
			run: func(sc scenario) (int, []byte) {
				sc.auth.BackupEligible = true
				return sc.s.login(sc.auth)
			},
		},
		{
			name: "tampered signature",
			run: func(sc scenario) (int, []byte) {
				credential := sc.s.assert(sc.auth, sc.s.loginOptions("members"), testOrigin)
				return sc.s.loginVerify("members", setResponseField(sc.s.t, credential, "signature", []byte("not a signature")))
			},
		},
		{
			// Security invariant 4: the user handle must name the owner of the credential.
			name: "user handle of another user",
			run: func(sc scenario) (int, []byte) {
				credential := sc.s.assert(sc.auth, sc.s.loginOptions("members"), testOrigin)
				return sc.s.loginVerify("members", setResponseField(sc.s.t, credential, "userHandle", []byte(sc.bob.Id)))
			},
		},
		{
			// Security invariant 4: the user handle is required.
			name: "no user handle",
			run: func(sc scenario) (int, []byte) {
				credential := sc.s.assert(sc.auth, sc.s.loginOptions("members"), testOrigin)
				return sc.s.loginVerify("members", setResponseField(sc.s.t, credential, "userHandle", nil))
			},
		},
		{
			// Security invariant 2: a challenge is single-use.
			name: "response sent twice",
			run: func(sc scenario) (int, []byte) {
				credential := sc.s.assert(sc.auth, sc.s.loginOptions("members"), testOrigin)
				if status, body := sc.s.loginVerify("members", credential); status != http.StatusOK {
					sc.s.t.Fatalf("first use: status %d, body %s", status, body)
				}

				return sc.s.loginVerify("members", credential)
			},
		},
		{
			name: "challenge that was never issued",
			run: func(sc scenario) (int, []byte) {
				opts := sc.s.loginOptions("members")
				opts.Challenge = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

				return sc.s.loginVerify("members", sc.s.assert(sc.auth, opts, testOrigin))
			},
		},
		{
			name: "expired ceremony",
			cfg:  func(c *Config) { c.ChallengeTTL = 40 * time.Millisecond; c.Timeout = 40 * time.Millisecond },
			run: func(sc scenario) (int, []byte) {
				credential := sc.s.assert(sc.auth, sc.s.loginOptions("members"), testOrigin)
				time.Sleep(80 * time.Millisecond)

				return sc.s.loginVerify("members", credential)
			},
		},
		{
			// Security invariant 2: a registration challenge cannot finish a login.
			name: "challenge of a registration ceremony",
			run: func(sc scenario) (int, []byte) {
				_, token := sc.s.newRecord("members", "carol@example.com")
				registration := sc.s.registerOptions(token)

				return sc.s.loginVerify("members", sc.s.assert(sc.auth, requestOptions{Challenge: registration.Challenge, RPID: testRPID}, testOrigin))
			},
		},
		{
			name: "body without a credential",
			run: func(sc scenario) (int, []byte) {
				return sc.s.post("/api/passkeys/members/login/verify", "", `{}`)
			},
		},
		{
			name: "body that is not JSON",
			run: func(sc scenario) (int, []byte) {
				return sc.s.post("/api/passkeys/members/login/verify", "", `{"credential":`)
			},
		},
		{
			name: "credential that is not a WebAuthn response",
			run: func(sc scenario) (int, []byte) {
				return sc.s.post("/api/passkeys/members/login/verify", "", `{"credential":{"id":"AAAA"}}`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, tt.cfg)
			_, token := s.newRecord("members", "alice@example.com")
			bob, _ := s.newRecord("members", "bob@example.com")

			auth := testauthn.New()
			s.register(auth, token, "Phone")

			status, body := tt.run(scenario{s: s, auth: auth, bob: bob})
			wantLoginFailed(t, status, body)

			if strings.Contains(string(body), "token") {
				t.Errorf("a failed login returned a token: %s", body)
			}
		})
	}
}

// Security invariant 7: the answer for a credential the server has never seen
// is the same as for a known credential with a wrong signature.
func TestLoginDoesNotRevealWhetherCredentialExists(t *testing.T) {
	s := newTestServer(t, nil)
	alice, token := s.newRecord("members", "alice@example.com")

	known := testauthn.New()
	s.register(known, token, "Phone")

	// A passkey for the same RP and user handle that was never registered here.
	unknown := testauthn.New()
	if _, err := unknown.Create(testauthn.CreateOptions{RPID: testRPID, Origin: testOrigin, Challenge: "AAAA", UserHandle: []byte(alice.Id)}); err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	unknownStatus, unknownBody := s.login(unknown)

	tampered := setResponseField(t, s.assert(known, s.loginOptions("members"), testOrigin), "signature", []byte("x"))
	knownStatus, knownBody := s.loginVerify("members", tampered)

	wantLoginFailed(t, unknownStatus, unknownBody)

	if unknownStatus != knownStatus || string(unknownBody) != string(knownBody) {
		t.Errorf("unknown credential: %d %s\nknown credential, bad signature: %d %s\nwant identical answers",
			unknownStatus, unknownBody, knownStatus, knownBody)
	}
}

// Security invariant 4: a passkey registered for a record of one collection
// cannot log in through another collection.
func TestLoginThroughAnotherCollectionRejected(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AuthCollections = []string{"members", "partners"} })
	_, token := s.newRecord("members", "alice@example.com")

	auth := testauthn.New()
	s.register(auth, token, "Phone")

	t.Run("ceremony started and finished on the other collection", func(t *testing.T) {
		status, body := s.loginVerify("partners", s.assert(auth, s.loginOptions("partners"), testOrigin))
		wantLoginFailed(t, status, body)
	})

	t.Run("challenge of one collection presented to the other", func(t *testing.T) {
		status, body := s.loginVerify("partners", s.assert(auth, s.loginOptions("members"), testOrigin))
		wantLoginFailed(t, status, body)
	})

	// The same passkey still works where it belongs.
	if status, body := s.login(auth); status != http.StatusOK {
		t.Errorf("login through its own collection: status %d, body %s", status, body)
	}
}

func TestLoginRoutesAreScopedToConfiguredCollections(t *testing.T) {
	s := newTestServer(t, nil)

	for _, collection := range []string{"partners", "notes", "nobody", core.CollectionNameSuperusers} {
		if status, _ := s.post("/api/passkeys/"+collection+"/login/options", "", nil); status != http.StatusNotFound {
			t.Errorf("login/options for %q: status %d, want 404", collection, status)
		}
		if status, _ := s.post("/api/passkeys/"+collection+"/login/verify", "", `{"credential":{}}`); status != http.StatusNotFound {
			t.Errorf("login/verify for %q: status %d, want 404", collection, status)
		}
	}

	if n := s.count(DefaultChallengesCollection); n != 0 {
		t.Errorf("challenges = %d, want 0", n)
	}
}

// Security invariant 21: above the cap login/options answers 429 and writes nothing.
func TestLoginPendingChallengesCap(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.MaxPendingChallenges = 2 })

	s.loginOptions("members")
	s.loginOptions("members")

	status, body := s.post("/api/passkeys/members/login/options", "", nil)
	if status != http.StatusTooManyRequests {
		t.Errorf("status %d, body %s; want 429", status, body)
	}
	if n := s.count(DefaultChallengesCollection); n != 2 {
		t.Errorf("challenges = %d, want 2", n)
	}
}

// Security invariant 6: a signature counter that does not increase triggers
// the configured policy.
func TestLoginSignCountPolicy(t *testing.T) {
	tests := []struct {
		policy       SignCountPolicy
		wantStatus   int
		wantHook     bool
		wantRejected bool
	}{
		{SignCountWarn, http.StatusOK, true, false},
		{SignCountReject, http.StatusBadRequest, true, true},
		{SignCountIgnore, http.StatusOK, false, false},
	}

	for _, tt := range tests {
		t.Run(map[SignCountPolicy]string{SignCountWarn: "warn", SignCountReject: "reject", SignCountIgnore: "ignore"}[tt.policy], func(t *testing.T) {
			s := newTestServer(t, func(c *Config) { c.SignCountPolicy = tt.policy })
			alice, token := s.newRecord("members", "alice@example.com")

			auth := testauthn.New()
			s.register(auth, token, "Key")

			// The server has seen counter 10; a clone answers with 4.
			credential := s.storedCredential(alice)
			credential.Set(store.FieldSignCount, 10)
			if err := s.app.Save(credential); err != nil {
				t.Fatalf("set stored counter: %v", err)
			}
			auth.SetSignCount(auth.CredentialIDs()[0], 3)

			var anomaly *SignCountAnomalyEvent

			s.module.OnSignCountAnomaly().BindFunc(func(e *SignCountAnomalyEvent) error {
				anomaly = e
				return e.Next()
			})

			status, body := s.login(auth)
			if status != tt.wantStatus {
				t.Fatalf("status %d, body %s; want %d", status, body, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusBadRequest {
				wantLoginFailed(t, status, body)
			}

			if (anomaly != nil) != tt.wantHook {
				t.Fatalf("hook fired = %v, want %v", anomaly != nil, tt.wantHook)
			}
			if anomaly != nil && (anomaly.Rejected != tt.wantRejected || anomaly.Record.Id != alice.Id || anomaly.Credential.Id != credential.Id) {
				t.Errorf("event = %+v, want Rejected=%v for alice's credential", anomaly, tt.wantRejected)
			}

			if got := s.storedCredential(alice).GetInt(store.FieldSignCount); got != 10 {
				t.Errorf("stored sign count = %d, want it to stay at 10", got)
			}
		})
	}
}

func TestBeforeLoginHook(t *testing.T) {
	setup := func(t *testing.T) (*testServer, *core.Record, *testauthn.Authenticator) {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")
		auth := testauthn.New()
		s.register(auth, token, "Phone")

		return s, alice, auth
	}

	t.Run("receives the verified user and credential", func(t *testing.T) {
		s, alice, auth := setup(t)

		var got *BeforeLoginEvent

		s.module.OnBeforeLogin().BindFunc(func(e *BeforeLoginEvent) error {
			got = e
			return e.Next()
		})

		if status, body := s.login(auth); status != http.StatusOK {
			t.Fatalf("login: status %d, body %s", status, body)
		}
		if got == nil || got.Record.Id != alice.Id || got.Credential.GetString(store.FieldName) != "Phone" || !got.UserVerified {
			t.Errorf("event = %+v, want alice, her credential and UserVerified", got)
		}
	})

	t.Run("a plain error refuses the login with the generic answer", func(t *testing.T) {
		s, alice, auth := setup(t)

		s.module.OnBeforeLogin().BindFunc(func(*BeforeLoginEvent) error {
			return errors.New("account is suspended")
		})

		var failed *LoginFailedEvent

		s.module.OnLoginFailed().BindFunc(func(e *LoginFailedEvent) error {
			failed = e
			return e.Next()
		})

		status, body := s.login(auth)
		wantLoginFailed(t, status, body)

		if failed == nil || failed.Record == nil || failed.Record.Id != alice.Id || !strings.Contains(failed.Reason, "account is suspended") {
			t.Errorf("OnLoginFailed event = %+v, want alice and the hook's reason", failed)
		}

		// The assertion itself was valid, so the counter still moved.
		if got := s.storedCredential(alice).GetInt(store.FieldSignCount); got != 2 {
			t.Errorf("stored sign count = %d, want 2", got)
		}
	})

	t.Run("an API error is passed through", func(t *testing.T) {
		s, _, auth := setup(t)

		s.module.OnBeforeLogin().BindFunc(func(e *BeforeLoginEvent) error {
			return e.ForbiddenError("Sign-in is not allowed from this network.", nil)
		})

		status, body := s.login(auth)
		if status != http.StatusForbidden || !strings.Contains(string(body), "Sign-in is not allowed from this network.") {
			t.Errorf("status %d, body %s; want the hook's 403", status, body)
		}
	})
}

func TestLoginFailedHook(t *testing.T) {
	s := newTestServer(t, nil)
	_, token := s.newRecord("members", "alice@example.com")
	auth := testauthn.New()
	s.register(auth, token, "Phone")

	var events []*LoginFailedEvent

	s.module.OnLoginFailed().BindFunc(func(e *LoginFailedEvent) error {
		events = append(events, e)
		return e.Next()
	})

	if status, body := s.login(auth); status != http.StatusOK {
		t.Fatalf("login: status %d, body %s", status, body)
	}
	if len(events) != 0 {
		t.Fatalf("the hook fired for a successful login: %+v", events[0])
	}

	status, body := s.loginVerify("members", s.assert(auth, s.loginOptions("members"), "https://evil.example"))
	wantLoginFailed(t, status, body)

	if len(events) != 1 {
		t.Fatalf("hook fired %d times, want 1", len(events))
	}
	if e := events[0]; e.Collection.Name != "members" || e.Record != nil || !strings.Contains(strings.ToLower(e.Reason), "origin") {
		t.Errorf("event = %+v, want the members collection, no record and a reason about the origin", e)
	}

	// The reason is for the server only.
	if strings.Contains(string(body), "origin") {
		t.Errorf("the response reveals the reason: %s", body)
	}
}

// What PocketBase itself decides about an authenticated record is kept.
func TestLoginKeepsPocketBaseAuthBehaviour(t *testing.T) {
	t.Run("auth rule of the collection", func(t *testing.T) {
		s := newTestServer(t, nil)
		_, token := s.newRecord("members", "alice@example.com")
		auth := testauthn.New()
		s.register(auth, token, "Phone")

		members, err := s.app.FindCollectionByNameOrId("members")
		if err != nil {
			t.Fatalf("find members: %v", err)
		}
		members.AuthRule = types.Pointer("verified = true") // alice is not verified
		if err := s.app.Save(members); err != nil {
			t.Fatalf("set auth rule: %v", err)
		}

		status, body := s.login(auth)
		if status != http.StatusForbidden || strings.Contains(string(body), `"token"`) {
			t.Errorf("status %d, body %s; want PocketBase's 403 and no token", status, body)
		}
	})

	t.Run("MFA asks for a second method", func(t *testing.T) {
		s := newTestServer(t, nil)
		_, token := s.newRecord("members", "alice@example.com")
		auth := testauthn.New()
		s.register(auth, token, "Phone")

		members, err := s.app.FindCollectionByNameOrId("members")
		if err != nil {
			t.Fatalf("find members: %v", err)
		}
		members.MFA.Enabled = true
		members.OTP.Enabled = true
		if err := s.app.Save(members); err != nil {
			t.Fatalf("enable MFA: %v", err)
		}

		status, body := s.login(auth)
		if status != http.StatusUnauthorized || !strings.Contains(string(body), `"mfaId"`) || strings.Contains(string(body), `"token"`) {
			t.Errorf("status %d, body %s; want PocketBase's 401 with an mfaId and no token", status, body)
		}
	})
}
