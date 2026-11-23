package ceremony_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/MarioShatterhand/pb-passkeys/internal/ceremony"
	"github.com/MarioShatterhand/pb-passkeys/internal/testauthn"
)

const (
	rpID   = "example.com"
	origin = "https://example.com"
)

func newService(t *testing.T, edit func(*ceremony.Config)) *ceremony.Service {
	t.Helper()

	cfg := ceremony.Config{
		RPID:             rpID,
		RPDisplayName:    "Example",
		RPOrigins:        []string{origin},
		UserVerification: ceremony.UVRequired,
		Algorithms:       []int{-7, -8, -257},
		Timeout:          2 * time.Minute,
		ChallengeTTL:     5 * time.Minute,
	}
	if edit != nil {
		edit(&cfg)
	}

	svc, err := ceremony.New(cfg)
	if err != nil {
		t.Fatalf("ceremony.New: %v", err)
	}

	return svc
}

func newUser(handle string) *ceremony.User {
	return &ceremony.User{Handle: []byte(handle), Name: "alice@example.com", DisplayName: "Alice"}
}

// stored sends a session through JSON, as it travels through the database
// between the two steps of a ceremony.
func stored(t *testing.T, s ceremony.Session) ceremony.Session {
	t.Helper()

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}

	var out ceremony.Session
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode session: %v", err)
	}

	return out
}

// register runs a registration ceremony and returns its outcome.
func register(t *testing.T, svc *ceremony.Service, auth *testauthn.Authenticator, user *ceremony.User, ceremonyOrigin string) (*ceremony.Credential, error) {
	t.Helper()

	started, err := svc.BeginRegistration(user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	resp, err := auth.Create(testauthn.CreateOptions{
		RPID:       rpID,
		Origin:     ceremonyOrigin,
		Challenge:  started.Challenge,
		UserHandle: user.Handle,
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	return svc.FinishRegistration(user, stored(t, started.Session), resp.JSON)
}

// mustRegister registers a credential and adds it to the user.
func mustRegister(t *testing.T, svc *ceremony.Service, auth *testauthn.Authenticator, user *ceremony.User) *ceremony.Credential {
	t.Helper()

	cred, err := register(t, svc, auth, user, origin)
	if err != nil {
		t.Fatalf("registration failed: %v (%s)", err, ceremony.Reason(err))
	}

	user.Credentials = append(user.Credentials, *cred)

	return cred
}

// lookupOf returns a lookup that knows exactly the given users.
func lookupOf(users ...*ceremony.User) ceremony.UserLookup {
	return func(_, userHandle []byte) (*ceremony.User, error) {
		for _, u := range users {
			if bytes.Equal(u.Handle, userHandle) {
				return u, nil
			}
		}

		return nil, errors.New("no such user")
	}
}

// login runs an authentication ceremony and returns its outcome.
func login(t *testing.T, svc *ceremony.Service, auth *testauthn.Authenticator, ceremonyOrigin string, lookup ceremony.UserLookup) (*ceremony.LoginResult, error) {
	t.Helper()

	started, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	resp, err := auth.Get(testauthn.GetOptions{RPID: rpID, Origin: ceremonyOrigin, Challenge: started.Challenge})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	return svc.FinishLogin(stored(t, started.Session), resp.JSON, lookup)
}

// wantRejected asserts that err is a verification failure whose reason mentions want.
func wantRejected(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Fatal("ceremony succeeded, want it rejected")
	}
	if !errors.Is(err, ceremony.ErrVerification) {
		t.Errorf("error does not wrap ErrVerification: %v", err)
	}
	if reason := ceremony.Reason(err); !strings.Contains(strings.ToLower(reason), strings.ToLower(want)) {
		t.Errorf("reason = %q, want it to mention %q", reason, want)
	}
}

func TestRegistrationAndLogin(t *testing.T) {
	svc := newService(t, nil)
	auth := testauthn.New()
	alice := newUser("record-alice")

	cred := mustRegister(t, svc, auth, alice)

	if len(cred.ID) == 0 || len(cred.PublicKey) == 0 {
		t.Fatalf("credential has no ID or public key: %+v", cred)
	}
	if cred.SignCount != 1 || cred.BackupEligible || cred.BackupState {
		t.Errorf("credential = %+v, want sign count 1 and no backup flags", cred)
	}
	if cred.AttestationFormat != "none" || cred.Attachment != "platform" {
		t.Errorf("format = %q, attachment = %q; want none and platform", cred.AttestationFormat, cred.Attachment)
	}
	if len(cred.Transports) != 1 || cred.Transports[0] != "internal" {
		t.Errorf("transports = %v, want [internal]", cred.Transports)
	}

	var gotID, gotHandle []byte

	result, err := login(t, svc, auth, origin, func(credentialID, userHandle []byte) (*ceremony.User, error) {
		gotID, gotHandle = credentialID, userHandle
		return alice, nil
	})
	if err != nil {
		t.Fatalf("login failed: %v (%s)", err, ceremony.Reason(err))
	}

	if !bytes.Equal(gotID, cred.ID) || !bytes.Equal(gotHandle, alice.Handle) {
		t.Errorf("lookup got id %x and handle %q, want the credential ID and alice's handle", gotID, gotHandle)
	}
	if result.User != alice {
		t.Error("result does not carry the user returned by the lookup")
	}
	if !bytes.Equal(result.Credential.ID, cred.ID) {
		t.Error("result carries another credential")
	}
	if result.Credential.SignCount != 2 || result.SignCountRegression {
		t.Errorf("sign count = %d, regression = %v; want 2 and false", result.Credential.SignCount, result.SignCountRegression)
	}
	if !result.UserVerified {
		t.Error("UserVerified = false, want true")
	}
}

func TestRegistrationOptions(t *testing.T) {
	svc := newService(t, func(c *ceremony.Config) { c.Algorithms = []int{-8, -7} })
	alice := newUser("record-alice")
	existing := mustRegister(t, svc, testauthn.New(), alice)

	started, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	var opts struct {
		Challenge string `json:"challenge"`
		RP        struct{ ID, Name string }
		User      struct{ ID, Name, DisplayName string }
		Params    []struct {
			Type string `json:"type"`
			Alg  int    `json:"alg"`
		} `json:"pubKeyCredParams"`
		Timeout   int `json:"timeout"`
		Selection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		Attestation string `json:"attestation"`
		Exclude     []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	}
	if err := json.Unmarshal(started.Options, &opts); err != nil {
		t.Fatalf("options are not JSON: %v\n%s", err, started.Options)
	}

	// The options are the bare PublicKeyCredentialCreationOptions, without a "publicKey" wrapper.
	if opts.Challenge == "" || opts.Challenge != started.Challenge {
		t.Errorf("challenge in options = %q, Started.Challenge = %q", opts.Challenge, started.Challenge)
	}
	if opts.RP.ID != rpID || opts.RP.Name != "Example" {
		t.Errorf("rp = %+v", opts.RP)
	}
	if want := base64.RawURLEncoding.EncodeToString(alice.Handle); opts.User.ID != want {
		t.Errorf("user.id = %q, want the base64url user handle %q", opts.User.ID, want)
	}
	if opts.User.Name != alice.Name || opts.User.DisplayName != alice.DisplayName {
		t.Errorf("user = %+v", opts.User)
	}
	if len(opts.Params) != 2 || opts.Params[0].Alg != -8 || opts.Params[1].Alg != -7 || opts.Params[0].Type != "public-key" {
		t.Errorf("pubKeyCredParams = %+v, want EdDSA then ES256", opts.Params)
	}
	if opts.Timeout != 120000 {
		t.Errorf("timeout = %d ms, want 120000", opts.Timeout)
	}
	if opts.Selection.ResidentKey != "required" || opts.Selection.UserVerification != "required" {
		t.Errorf("authenticatorSelection = %+v, want resident key and user verification required", opts.Selection)
	}
	if opts.Attestation != "none" {
		t.Errorf("attestation = %q, want none", opts.Attestation)
	}
	if want := base64.RawURLEncoding.EncodeToString(existing.ID); len(opts.Exclude) != 1 || opts.Exclude[0].ID != want {
		t.Errorf("excludeCredentials = %+v, want the user's existing credential", opts.Exclude)
	}

	if started.Session.Challenge != started.Challenge {
		t.Error("session does not hold the challenge")
	}
	if d := time.Until(started.ExpiresAt); d < 4*time.Minute || d > 5*time.Minute {
		t.Errorf("ExpiresAt is %s away, want about 5 minutes", d)
	}
	if !started.Session.Expires.Equal(started.ExpiresAt) {
		t.Error("session expiry differs from Started.ExpiresAt")
	}
}

func TestLoginOptions(t *testing.T) {
	svc := newService(t, func(c *ceremony.Config) { c.UserVerification = ceremony.UVPreferred })

	started, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	var opts map[string]any
	if err := json.Unmarshal(started.Options, &opts); err != nil {
		t.Fatalf("options are not JSON: %v", err)
	}

	if opts["challenge"] != started.Challenge || opts["rpId"] != rpID {
		t.Errorf("options = %v", opts)
	}
	if opts["userVerification"] != "preferred" {
		t.Errorf("userVerification = %v, want preferred", opts["userVerification"])
	}
	if list, ok := opts["allowCredentials"]; ok && list != nil {
		t.Errorf("allowCredentials = %v, want none for a discoverable login", list)
	}

	another, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if another.Challenge == started.Challenge {
		t.Error("two ceremonies got the same challenge")
	}
}

// Security invariant 1: an origin outside RPOrigins is rejected.
func TestWrongOriginRejected(t *testing.T) {
	for _, bad := range []string{"https://evil.example", "https://example.com.evil.example", "http://example.com", "https://example.com:8443"} {
		t.Run(bad, func(t *testing.T) {
			svc := newService(t, nil)
			auth := testauthn.New()
			alice := newUser("record-alice")

			// A separate authenticator: this one keeps the credential it
			// created even though the server refused it.
			_, err := register(t, svc, testauthn.New(), alice, bad)
			wantRejected(t, err, "origin")

			mustRegister(t, svc, auth, alice)

			_, err = login(t, svc, auth, bad, lookupOf(alice))
			wantRejected(t, err, "origin")
		})
	}
}

// Security invariant 5: with user verification required, the UV flag is
// checked on the server and not only requested from the authenticator.
func TestUserVerificationEnforced(t *testing.T) {
	t.Run("registration without UV rejected", func(t *testing.T) {
		svc := newService(t, nil)
		auth := testauthn.New()
		auth.UserVerified = false

		_, err := register(t, svc, auth, newUser("record-alice"), origin)
		wantRejected(t, err, "user verification")
	})

	t.Run("login without UV rejected", func(t *testing.T) {
		svc := newService(t, nil)
		auth := testauthn.New()
		alice := newUser("record-alice")
		mustRegister(t, svc, auth, alice)

		auth.UserVerified = false

		_, err := login(t, svc, auth, origin, lookupOf(alice))
		wantRejected(t, err, "user verification")
	})

	t.Run("accepted without UV when only preferred", func(t *testing.T) {
		svc := newService(t, func(c *ceremony.Config) { c.UserVerification = ceremony.UVPreferred })
		auth := testauthn.New()
		auth.UserVerified = false
		alice := newUser("record-alice")
		mustRegister(t, svc, auth, alice)

		result, err := login(t, svc, auth, origin, lookupOf(alice))
		if err != nil {
			t.Fatalf("login failed: %v (%s)", err, ceremony.Reason(err))
		}
		if result.UserVerified {
			t.Error("UserVerified = true for a response without the UV flag")
		}
	})
}

// Security invariant 6: a signature counter that does not increase is
// reported, and the stored counter is not moved backwards.
func TestSignCount(t *testing.T) {
	t.Run("regression is reported", func(t *testing.T) {
		svc := newService(t, nil)
		auth := testauthn.New()
		alice := newUser("record-alice")
		cred := mustRegister(t, svc, auth, alice)

		alice.Credentials[0].SignCount = 10 // what the server has seen
		auth.SetSignCount(cred.ID, 3)       // a clone answers with 4

		result, err := login(t, svc, auth, origin, lookupOf(alice))
		if err != nil {
			t.Fatalf("login failed: %v (%s)", err, ceremony.Reason(err))
		}
		if !result.SignCountRegression {
			t.Error("SignCountRegression = false after the counter went from 10 to 4")
		}
		if result.Credential.SignCount != 10 {
			t.Errorf("sign count = %d, want it to stay at 10", result.Credential.SignCount)
		}
	})

	t.Run("equal counter is a regression", func(t *testing.T) {
		svc := newService(t, nil)
		auth := testauthn.New()
		alice := newUser("record-alice")
		cred := mustRegister(t, svc, auth, alice)

		alice.Credentials[0].SignCount = 5
		auth.SetSignCount(cred.ID, 4) // answers with 5 again

		result, err := login(t, svc, auth, origin, lookupOf(alice))
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		if !result.SignCountRegression {
			t.Error("SignCountRegression = false for a repeated counter value")
		}
	})

	t.Run("zero counter of a synced passkey is not a regression", func(t *testing.T) {
		svc := newService(t, nil)
		auth := testauthn.New()
		auth.BackupEligible, auth.BackupState, auth.ZeroSignCount = true, true, true
		alice := newUser("record-alice")
		cred := mustRegister(t, svc, auth, alice)

		if !cred.BackupEligible || !cred.BackupState || cred.SignCount != 0 {
			t.Fatalf("credential = %+v, want backup flags set and sign count 0", cred)
		}

		for range 2 {
			result, err := login(t, svc, auth, origin, lookupOf(alice))
			if err != nil {
				t.Fatalf("login failed: %v", err)
			}
			if result.SignCountRegression || result.Credential.SignCount != 0 {
				t.Errorf("regression = %v, sign count = %d; want false and 0", result.SignCountRegression, result.Credential.SignCount)
			}
		}
	})

	t.Run("backup state is updated from the response", func(t *testing.T) {
		svc := newService(t, nil)
		auth := testauthn.New()
		auth.BackupEligible = true
		alice := newUser("record-alice")
		mustRegister(t, svc, auth, alice)

		auth.BackupState = true // the passkey got synced after registration

		result, err := login(t, svc, auth, origin, lookupOf(alice))
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		if !result.Credential.BackupState || !result.Credential.BackupEligible {
			t.Errorf("credential = %+v, want backup state set", result.Credential)
		}
	})
}

// Security invariant 23: the backup-eligible flag is fixed at registration.
func TestBackupEligibleChangeRejected(t *testing.T) {
	for _, registeredAs := range []bool{false, true} {
		svc := newService(t, nil)
		auth := testauthn.New()
		auth.BackupEligible = registeredAs
		alice := newUser("record-alice")
		mustRegister(t, svc, auth, alice)

		auth.BackupEligible = !registeredAs

		_, err := login(t, svc, auth, origin, lookupOf(alice))
		wantRejected(t, err, "backup eligible")
	}
}

func TestChallengeLifetime(t *testing.T) {
	t.Run("response after ChallengeTTL rejected", func(t *testing.T) {
		svc := newService(t, func(c *ceremony.Config) { c.ChallengeTTL = 30 * time.Millisecond; c.Timeout = 10 * time.Millisecond })
		auth := testauthn.New()
		alice := newUser("record-alice")

		started, err := svc.BeginRegistration(alice)
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		resp, err := auth.Create(testauthn.CreateOptions{RPID: rpID, Origin: origin, Challenge: started.Challenge, UserHandle: alice.Handle})
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}

		time.Sleep(60 * time.Millisecond)

		_, err = svc.FinishRegistration(alice, stored(t, started.Session), resp.JSON)
		wantRejected(t, err, "expired")
	})

	// The browser timeout is only a hint; the ceremony lives as long as ChallengeTTL.
	t.Run("response after Timeout but within ChallengeTTL accepted", func(t *testing.T) {
		svc := newService(t, func(c *ceremony.Config) { c.Timeout = 10 * time.Millisecond })
		auth := testauthn.New()
		alice := newUser("record-alice")
		mustRegister(t, svc, auth, alice)

		started, err := svc.BeginLogin()
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		resp, err := auth.Get(testauthn.GetOptions{RPID: rpID, Origin: origin, Challenge: started.Challenge})
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}

		time.Sleep(40 * time.Millisecond)

		if _, err := svc.FinishLogin(stored(t, started.Session), resp.JSON, lookupOf(alice)); err != nil {
			t.Fatalf("login failed: %v (%s)", err, ceremony.Reason(err))
		}
	})

	t.Run("expired login rejected", func(t *testing.T) {
		svc := newService(t, func(c *ceremony.Config) { c.ChallengeTTL = 30 * time.Millisecond; c.Timeout = 10 * time.Millisecond })
		auth := testauthn.New()
		alice := newUser("record-alice")
		mustRegister(t, svc, auth, alice)

		started, err := svc.BeginLogin()
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		resp, err := auth.Get(testauthn.GetOptions{RPID: rpID, Origin: origin, Challenge: started.Challenge})
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}

		time.Sleep(60 * time.Millisecond)

		_, err = svc.FinishLogin(stored(t, started.Session), resp.JSON, lookupOf(alice))
		wantRejected(t, err, "expired")
	})
}

func TestResponseToAnotherCeremonyRejected(t *testing.T) {
	svc := newService(t, nil)
	auth := testauthn.New()
	alice := newUser("record-alice")
	mustRegister(t, svc, auth, alice)

	first, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	second, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	resp, err := auth.Get(testauthn.GetOptions{RPID: rpID, Origin: origin, Challenge: second.Challenge})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	_, err = svc.FinishLogin(stored(t, first.Session), resp.JSON, lookupOf(alice))
	wantRejected(t, err, "challenge")
}

func TestLoginLookup(t *testing.T) {
	svc := newService(t, nil)
	auth := testauthn.New()
	alice := newUser("record-alice")
	mustRegister(t, svc, auth, alice)

	t.Run("unknown user rejected", func(t *testing.T) {
		_, err := login(t, svc, auth, origin, lookupOf())
		wantRejected(t, err, "lookup")
	})

	t.Run("nil user rejected", func(t *testing.T) {
		_, err := login(t, svc, auth, origin, func(_, _ []byte) (*ceremony.User, error) { return nil, nil })
		wantRejected(t, err, "lookup")
	})

	// The lookup hands back an account that does not own the credential.
	t.Run("user without the credential rejected", func(t *testing.T) {
		bob := newUser("record-alice") // same handle, but no credentials
		_, err := login(t, svc, auth, origin, lookupOf(bob))
		wantRejected(t, err, "credential")
	})

	// The lookup hands back an account with another handle than the response claims.
	t.Run("user with another handle rejected", func(t *testing.T) {
		mallory := newUser("record-mallory")
		mallory.Credentials = alice.Credentials

		_, err := login(t, svc, auth, origin, func(_, _ []byte) (*ceremony.User, error) { return mallory, nil })
		wantRejected(t, err, "user handle")
	})
}

func TestRegistrationFinishedForAnotherUserRejected(t *testing.T) {
	svc := newService(t, nil)
	auth := testauthn.New()
	alice, bob := newUser("record-alice"), newUser("record-bob")

	started, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	resp, err := auth.Create(testauthn.CreateOptions{RPID: rpID, Origin: origin, Challenge: started.Challenge, UserHandle: alice.Handle})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	_, err = svc.FinishRegistration(bob, stored(t, started.Session), resp.JSON)
	wantRejected(t, err, "mismatch")
}

func TestAlgorithmNotOfferedRejected(t *testing.T) {
	// The authenticator creates an ES256 key although only RS256 was offered.
	svc := newService(t, func(c *ceremony.Config) { c.Algorithms = []int{-257} })

	_, err := register(t, svc, testauthn.New(), newUser("record-alice"), origin)
	if !errors.Is(err, ceremony.ErrVerification) {
		t.Fatalf("err = %v, want a verification error", err)
	}
	t.Logf("rejected: %s", ceremony.Reason(err))
}

func TestMalformedResponsesRejected(t *testing.T) {
	svc := newService(t, nil)
	alice := newUser("record-alice")

	started, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	for _, body := range []string{"", "{", "null", "{}", `{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{}}`} {
		if _, err := svc.FinishRegistration(alice, started.Session, []byte(body)); !errors.Is(err, ceremony.ErrVerification) {
			t.Errorf("FinishRegistration(%q): err = %v, want a verification error", body, err)
		}
		if _, err := svc.FinishLogin(started.Session, []byte(body), lookupOf(alice)); !errors.Is(err, ceremony.ErrVerification) {
			t.Errorf("FinishLogin(%q): err = %v, want a verification error", body, err)
		}
	}
}

func TestChallengeOf(t *testing.T) {
	svc := newService(t, nil)
	auth := testauthn.New()
	alice := newUser("record-alice")

	started, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	created, err := auth.Create(testauthn.CreateOptions{RPID: rpID, Origin: origin, Challenge: started.Challenge, UserHandle: alice.Handle})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	if got, err := ceremony.ChallengeOf(created.JSON); err != nil || got != started.Challenge {
		t.Errorf("ChallengeOf(registration response) = %q, %v; want %q", got, err, started.Challenge)
	}

	loginStarted, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	asserted, err := auth.Get(testauthn.GetOptions{RPID: rpID, Origin: origin, Challenge: loginStarted.Challenge})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	if got, err := ceremony.ChallengeOf(asserted.JSON); err != nil || got != loginStarted.Challenge {
		t.Errorf("ChallengeOf(login response) = %q, %v; want %q", got, err, loginStarted.Challenge)
	}

	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

	// Browsers send base64url without padding; padded input is tolerated.
	padded := `{"response":{"clientDataJSON":"` + base64.URLEncoding.EncodeToString([]byte(`{"challenge":"abcd"}`)) + `"}}`
	if got, err := ceremony.ChallengeOf([]byte(padded)); err != nil || got != "abcd" {
		t.Errorf("ChallengeOf(padded) = %q, %v; want abcd", got, err)
	}

	for name, body := range map[string]string{
		"empty":                "",
		"not JSON":             "{",
		"no response":          "{}",
		"client data not b64":  `{"response":{"clientDataJSON":"***"}}`,
		"client data not JSON": `{"response":{"clientDataJSON":"` + b64("nope") + `"}}`,
		"no challenge":         `{"response":{"clientDataJSON":"` + b64(`{"type":"webauthn.get"}`) + `"}}`,
		"empty challenge":      `{"response":{"clientDataJSON":"` + b64(`{"challenge":""}`) + `"}}`,
	} {
		if got, err := ceremony.ChallengeOf([]byte(body)); !errors.Is(err, ceremony.ErrMalformedResponse) || got != "" {
			t.Errorf("ChallengeOf(%s) = %q, %v; want ErrMalformedResponse", name, got, err)
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	base := ceremony.Config{
		RPID: rpID, RPDisplayName: "Example", RPOrigins: []string{origin},
		UserVerification: ceremony.UVRequired, Algorithms: []int{-7},
		Timeout: time.Minute, ChallengeTTL: time.Minute,
	}

	if _, err := ceremony.New(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	for name, edit := range map[string]func(*ceremony.Config){
		"no timeout":                func(c *ceremony.Config) { c.Timeout = 0 },
		"no challenge TTL":          func(c *ceremony.Config) { c.ChallengeTTL = 0 },
		"no algorithms":             func(c *ceremony.Config) { c.Algorithms = nil },
		"unknown user verification": func(c *ceremony.Config) { c.UserVerification = "always" },
		"no RP ID":                  func(c *ceremony.Config) { c.RPID = "" },
		"no origins":                func(c *ceremony.Config) { c.RPOrigins = nil },
	} {
		cfg := base
		edit(&cfg)

		if _, err := ceremony.New(cfg); err == nil {
			t.Errorf("%s: config accepted, want an error", name)
		}
	}
}

func TestReason(t *testing.T) {
	if got := ceremony.Reason(nil); got != "" {
		t.Errorf("Reason(nil) = %q, want empty", got)
	}
	if got := ceremony.Reason(errors.New("plain")); got != "plain" {
		t.Errorf("Reason(plain error) = %q", got)
	}

	// go-webauthn reports a challenge mismatch with both challenges in the
	// developer info. They must not reach the log.
	mismatch := protocol.ErrVerification.
		WithDetails("Error validating challenge").
		WithInfo("Expected b Value: \"expected-challenge-value\"\nReceived b: \"received-challenge-value\"\n")

	got := ceremony.Reason(mismatch)
	if strings.Contains(got, "expected-challenge-value") || strings.Contains(got, "received-challenge-value") {
		t.Errorf("Reason leaks challenges: %q", got)
	}
	if !strings.Contains(got, "Error validating challenge") {
		t.Errorf("Reason = %q, want it to keep the description", got)
	}

	// Other developer info is kept; it is what makes the log useful.
	origin := protocol.ErrVerification.
		WithDetails("Error validating origin").
		WithInfo("Expected Values: [https://example.com], Received: https://evil.example")

	if got := ceremony.Reason(origin); !strings.Contains(got, "https://evil.example") {
		t.Errorf("Reason = %q, want it to keep the received origin", got)
	}
}
