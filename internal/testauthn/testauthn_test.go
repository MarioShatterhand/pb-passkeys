package testauthn_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/MarioShatterhand/pb-passkeys/internal/testauthn"
)

const (
	rpID   = "example.com"
	origin = "https://example.com"
)

// user is a minimal webauthn.User.
type user struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return "alice@example.com" }
func (u *user) WebAuthnDisplayName() string                { return "Alice" }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func newRelyingParty(t *testing.T) *webauthn.WebAuthn {
	t.Helper()

	rp, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Example",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}

	return rp
}

func uvRequired() webauthn.RegistrationOption {
	return webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
		ResidentKey:      protocol.ResidentKeyRequirementRequired,
		UserVerification: protocol.VerificationRequired,
	})
}

// register runs a full registration ceremony against go-webauthn and returns
// its result. The ceremony origin can be overridden to test rejection.
func register(t *testing.T, rp *webauthn.WebAuthn, auth *testauthn.Authenticator, u *user, ceremonyOrigin string) (*webauthn.Credential, error) {
	t.Helper()

	creation, session, err := rp.BeginRegistration(u, uvRequired())
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	resp, err := auth.Create(testauthn.CreateOptions{
		RPID:       rpID,
		Origin:     ceremonyOrigin,
		Challenge:  creation.Response.Challenge.String(),
		UserHandle: u.id,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp.JSON)
	if err != nil {
		return nil, err
	}

	return rp.CreateCredential(u, *session, parsed)
}

// mustRegister registers a credential and stores it on the user.
func mustRegister(t *testing.T, rp *webauthn.WebAuthn, auth *testauthn.Authenticator, u *user) *webauthn.Credential {
	t.Helper()

	cred, err := register(t, rp, auth, u, origin)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	u.credentials = append(u.credentials, *cred)

	return cred
}

// login runs a discoverable login ceremony against go-webauthn. mutate, if not
// nil, can change the response JSON before the server sees it.
func login(t *testing.T, rp *webauthn.WebAuthn, auth *testauthn.Authenticator, u *user, ceremonyOrigin string, mutate func([]byte) []byte) (*webauthn.Credential, error) {
	t.Helper()

	assertion, session, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	resp, err := auth.Get(testauthn.GetOptions{
		RPID:      rpID,
		Origin:    ceremonyOrigin,
		Challenge: assertion.Response.Challenge.String(),
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	body := resp.JSON
	if mutate != nil {
		body = mutate(body)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, err
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if string(userHandle) != string(u.id) {
			return nil, errors.New("unknown user handle")
		}

		return u, nil
	}

	_, cred, err := rp.ValidatePasskeyLogin(handler, *session, parsed)

	return cred, err
}

func TestRegistrationAndLogin(t *testing.T) {
	rp := newRelyingParty(t)
	auth := testauthn.New()
	u := &user{id: []byte("user-0001")}

	cred := mustRegister(t, rp, auth, u)

	if got := auth.CredentialIDs(); len(got) != 1 || string(got[0]) != string(cred.ID) {
		t.Fatalf("credential ID mismatch: authenticator has %x, server stored %x", got, cred.ID)
	}
	if !cred.Flags.UserPresent || !cred.Flags.UserVerified {
		t.Errorf("flags = %+v, want UP and UV set", cred.Flags)
	}
	if cred.Flags.BackupEligible || cred.Flags.BackupState {
		t.Errorf("flags = %+v, want BE and BS clear", cred.Flags)
	}
	if cred.AttestationFormat != "none" {
		t.Errorf("attestation format = %q, want none", cred.AttestationFormat)
	}
	if cred.Authenticator.SignCount != 1 {
		t.Errorf("sign count after registration = %d, want 1", cred.Authenticator.SignCount)
	}

	got, err := login(t, rp, auth, u, origin, nil)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if got.Authenticator.SignCount != 2 {
		t.Errorf("sign count after login = %d, want 2", got.Authenticator.SignCount)
	}
	if got.Authenticator.CloneWarning {
		t.Error("unexpected clone warning")
	}
}

func TestSyncedPasskeyFlags(t *testing.T) {
	rp := newRelyingParty(t)
	auth := testauthn.New()
	auth.BackupEligible = true
	auth.BackupState = true
	auth.ZeroSignCount = true
	u := &user{id: []byte("user-0002")}

	cred := mustRegister(t, rp, auth, u)

	if !cred.Flags.BackupEligible || !cred.Flags.BackupState {
		t.Errorf("flags = %+v, want BE and BS set", cred.Flags)
	}

	got, err := login(t, rp, auth, u, origin, nil)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if got.Authenticator.SignCount != 0 || got.Authenticator.CloneWarning {
		t.Errorf("sign count = %d, clone warning = %v; want 0 and false for a zero counter",
			got.Authenticator.SignCount, got.Authenticator.CloneWarning)
	}
}

func TestRegistrationRejected(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		setup  func(*testauthn.Authenticator)
	}{
		{name: "wrong origin", origin: "https://evil.example"},
		{name: "user verification missing", origin: origin, setup: func(a *testauthn.Authenticator) { a.UserVerified = false }},
		{name: "user presence missing", origin: origin, setup: func(a *testauthn.Authenticator) { a.UserPresent = false }},
		{name: "backup state without eligibility", origin: origin, setup: func(a *testauthn.Authenticator) { a.BackupState = true }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := newRelyingParty(t)
			auth := testauthn.New()
			if tt.setup != nil {
				tt.setup(auth)
			}

			_, err := register(t, rp, auth, &user{id: []byte("user-0003")}, tt.origin)
			if err == nil {
				t.Fatal("registration succeeded, want an error")
			}

			t.Logf("rejected: %s", describe(err))
		})
	}
}

func TestLoginRejected(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		setup  func(*testauthn.Authenticator)
		mutate func([]byte) []byte
	}{
		{name: "wrong origin", origin: "https://evil.example"},
		{name: "user verification missing", origin: origin, setup: func(a *testauthn.Authenticator) { a.UserVerified = false }},
		{name: "backup eligible flag changed", origin: origin, setup: func(a *testauthn.Authenticator) { a.BackupEligible = true }},
		{name: "signature tampered", origin: origin, mutate: func(body []byte) []byte {
			return mutateResponseField(t, body, "signature", func(b []byte) { b[len(b)-1] ^= 0x01 })
		}},
		{name: "authenticator data tampered", origin: origin, mutate: func(body []byte) []byte {
			// Raise the sign counter after signing: the signature no longer covers the data.
			return mutateResponseField(t, body, "authenticatorData", func(b []byte) { b[36] ^= 0x10 })
		}},
		{name: "user handle of another user", origin: origin, mutate: func(body []byte) []byte {
			return replaceResponseField(t, body, "userHandle", []byte("user-9999"))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := newRelyingParty(t)
			auth := testauthn.New()
			u := &user{id: []byte("user-0004")}
			mustRegister(t, rp, auth, u)

			if tt.setup != nil {
				tt.setup(auth)
			}

			_, err := login(t, rp, auth, u, tt.origin, tt.mutate)
			if err == nil {
				t.Fatal("login succeeded, want an error")
			}

			t.Logf("rejected: %s", describe(err))
		})
	}
}

func TestLoginWithChallengeOfAnotherSession(t *testing.T) {
	rp := newRelyingParty(t)
	auth := testauthn.New()
	u := &user{id: []byte("user-0005")}
	mustRegister(t, rp, auth, u)

	_, session, err := rp.BeginDiscoverableLogin()
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	other, _, err := rp.BeginDiscoverableLogin()
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	resp, err := auth.Get(testauthn.GetOptions{RPID: rpID, Origin: origin, Challenge: other.Response.Challenge.String()})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(resp.JSON)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) { return u, nil }
	if _, _, err := rp.ValidatePasskeyLogin(handler, *session, parsed); err == nil {
		t.Fatal("login with a challenge from another session succeeded, want an error")
	}
}

func TestSignCountRegressionSetsCloneWarning(t *testing.T) {
	rp := newRelyingParty(t)
	auth := testauthn.New()
	u := &user{id: []byte("user-0006")}
	cred := mustRegister(t, rp, auth, u)

	// The server has seen counter 10; a clone answers with 4.
	u.credentials[0].Authenticator.SignCount = 10
	if !auth.SetSignCount(cred.ID, 3) {
		t.Fatal("SetSignCount: credential not found")
	}

	got, err := login(t, rp, auth, u, origin, nil)
	if err != nil {
		t.Fatalf("login failed: %v (go-webauthn reports a counter regression as a warning, not an error)", err)
	}
	if !got.Authenticator.CloneWarning {
		t.Error("clone warning not set after a sign counter regression")
	}
	if got.Authenticator.SignCount != 10 {
		t.Errorf("stored sign count = %d, want it to stay at 10", got.Authenticator.SignCount)
	}
}

func TestGetSelectsCredential(t *testing.T) {
	rp := newRelyingParty(t)
	auth := testauthn.New()
	alice := &user{id: []byte("user-0007")}
	bob := &user{id: []byte("user-0008")}
	aliceCred := mustRegister(t, rp, auth, alice)
	bobCred := mustRegister(t, rp, auth, bob)

	base := testauthn.GetOptions{RPID: rpID, Origin: origin, Challenge: "AAAA"}

	if _, err := auth.Get(base); !errors.Is(err, testauthn.ErrAmbiguousCredential) {
		t.Errorf("Get with two matching credentials: err = %v, want ErrAmbiguousCredential", err)
	}

	byID := base
	byID.CredentialID = bobCred.ID
	if resp, err := auth.Get(byID); err != nil || string(resp.CredentialID) != string(bobCred.ID) {
		t.Errorf("Get by CredentialID: id = %x, err = %v; want bob's credential", resp, err)
	}

	byAllowList := base
	byAllowList.AllowCredentials = [][]byte{aliceCred.ID}
	if resp, err := auth.Get(byAllowList); err != nil || string(resp.CredentialID) != string(aliceCred.ID) {
		t.Errorf("Get by AllowCredentials: id = %x, err = %v; want alice's credential", resp, err)
	}

	otherRP := base
	otherRP.RPID = "other.example"
	if _, err := auth.Get(otherRP); !errors.Is(err, testauthn.ErrNoCredential) {
		t.Errorf("Get for another RP ID: err = %v, want ErrNoCredential", err)
	}
}

// describe returns the detailed reason carried by a go-webauthn error, so the
// test log shows why a response was rejected.
func describe(err error) string {
	var perr *protocol.Error
	if errors.As(err, &perr) {
		return perr.Type + ": " + perr.Details + " " + perr.DevInfo
	}

	return err.Error()
}

// mutateResponseField decodes response.<field> from base64url, lets fn change
// the bytes, and writes the field back.
func mutateResponseField(t *testing.T, body []byte, field string, fn func([]byte)) []byte {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	response := doc["response"].(map[string]any)

	raw, err := base64.RawURLEncoding.DecodeString(response[field].(string))
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}

	fn(raw)

	return replaceResponseField(t, body, field, raw)
}

// replaceResponseField sets response.<field> to the base64url form of value.
func replaceResponseField(t *testing.T, body []byte, field string, value []byte) []byte {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	doc["response"].(map[string]any)[field] = base64.RawURLEncoding.EncodeToString(value)

	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}

	return out
}
