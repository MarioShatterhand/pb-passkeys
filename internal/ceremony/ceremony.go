// Package ceremony runs WebAuthn registration and authentication ceremonies.
//
// It is a thin layer over github.com/go-webauthn/webauthn: it builds the
// options sent to the browser and hands the browser's response to go-webauthn
// for verification. It contains no cryptography of its own and knows nothing
// about PocketBase; storage and HTTP live in other packages.
package ceremony

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Errors returned by the ceremony functions.
var (
	// ErrVerification is wrapped by every error that means the browser's
	// response was not accepted. Callers answer it with a generic error;
	// [Reason] gives the detail for the server log.
	ErrVerification = errors.New("ceremony: verification failed")

	// ErrMalformedResponse means the response body could not be read far
	// enough to find the ceremony it belongs to.
	ErrMalformedResponse = errors.New("ceremony: malformed response")
)

// UserVerification is the user verification requirement of a ceremony.
type UserVerification string

// User verification requirements, with the values WebAuthn defines.
const (
	UVRequired    UserVerification = "required"
	UVPreferred   UserVerification = "preferred"
	UVDiscouraged UserVerification = "discouraged"
)

// Config holds the relying party settings. The caller validates them.
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string

	// UserVerification is requested from the authenticator and, when it is
	// UVRequired, enforced on the response.
	UserVerification UserVerification

	// Algorithms lists the accepted COSE algorithm identifiers in order of preference.
	Algorithms []int

	// Timeout is the hint sent to the browser for how long to wait for the user.
	Timeout time.Duration

	// ChallengeTTL is how long a ceremony may take. It is written into the
	// session data, and go-webauthn rejects a response that arrives later.
	ChallengeTTL time.Duration
}

// Credential is a stored passkey, in the form the ceremonies need.
type Credential struct {
	// ID is the raw credential ID.
	ID []byte

	// PublicKey is the credential public key in COSE format.
	PublicKey []byte

	// SignCount is the signature counter last seen from the authenticator.
	SignCount uint32

	// AAGUID identifies the authenticator model. May be all zero.
	AAGUID []byte

	// Transports are the transport hints reported at registration.
	Transports []string

	// Attachment is the authenticator attachment reported at registration
	// ("platform", "cross-platform" or empty).
	Attachment string

	// BackupEligible is the BE flag. It is fixed at registration; a login
	// with a different value is rejected.
	BackupEligible bool

	// BackupState is the BS flag as last seen.
	BackupState bool

	// AttestationFormat is the attestation statement format seen at registration.
	AttestationFormat string
}

// User is the account a ceremony is for.
type User struct {
	// Handle is the WebAuthn user handle, at most 64 bytes. It must not
	// contain personal data.
	Handle []byte

	// Name and DisplayName are shown by the browser or authenticator when a
	// passkey is created.
	Name        string
	DisplayName string

	// Credentials are all passkeys of the user.
	Credentials []Credential
}

// Session is the server-side state of a ceremony in progress. It is
// JSON-serializable and must be kept between the two steps of a ceremony and
// never sent to the client.
type Session = webauthn.SessionData

// Started is the result of beginning a ceremony.
type Started struct {
	// Options is the JSON for the browser: PublicKeyCredentialCreationOptions
	// or PublicKeyCredentialRequestOptions in their JSON form, as accepted by
	// PublicKeyCredential.parseCreationOptionsFromJSON and
	// parseRequestOptionsFromJSON.
	Options json.RawMessage

	// Challenge is the challenge inside Options (base64url). The response
	// carries it back, which is how the ceremony is found again.
	Challenge string

	// Session must be stored until the ceremony is finished.
	Session Session

	// ExpiresAt is when the ceremony stops being valid.
	ExpiresAt time.Time
}

// LoginResult is the outcome of a verified authentication ceremony.
type LoginResult struct {
	// User is the account that owns the credential, as returned by the lookup.
	User *User

	// Credential is the credential that signed, with SignCount and
	// BackupState updated from the response. The caller persists them.
	Credential Credential

	// SignCountRegression is true when the authenticator's signature counter
	// did not increase although it uses one. It may mean the authenticator
	// was cloned. go-webauthn accepts such a login; the caller applies its
	// policy. Credential.SignCount is left unchanged in this case.
	SignCountRegression bool

	// UserVerified is the UV flag of the response.
	UserVerified bool
}

// UserLookup finds the account for a discoverable login. It gets the raw
// credential ID and the user handle from the response and returns the user
// with all of their credentials. Any error makes the login fail.
type UserLookup func(credentialID, userHandle []byte) (*User, error)

// Service runs ceremonies for one relying party configuration.
type Service struct {
	wa  *webauthn.WebAuthn
	cfg Config
}

// New returns a Service for cfg.
func New(cfg Config) (*Service, error) {
	if cfg.RPID == "" || cfg.RPDisplayName == "" || len(cfg.RPOrigins) == 0 {
		return nil, errors.New("ceremony: RPID, RPDisplayName and RPOrigins are required")
	}
	if cfg.Timeout <= 0 || cfg.ChallengeTTL <= 0 {
		return nil, errors.New("ceremony: Timeout and ChallengeTTL must be positive")
	}
	if len(cfg.Algorithms) == 0 {
		return nil, errors.New("ceremony: at least one algorithm is required")
	}

	switch cfg.UserVerification {
	case UVRequired, UVPreferred, UVDiscouraged:
	default:
		return nil, fmt.Errorf("ceremony: unknown user verification requirement %q", cfg.UserVerification)
	}

	// go-webauthn can derive the session expiry from the browser timeout
	// ("Enforce"). The module wants the expiry to follow ChallengeTTL instead,
	// so enforcement stays off here and the Begin functions set it themselves.
	timeout := webauthn.TimeoutConfig{Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             cfg.RPOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Discoverable credentials make login without a username possible.
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.UserVerificationRequirement(cfg.UserVerification),
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	})
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}

	return &Service{wa: wa, cfg: cfg}, nil
}

// BeginRegistration starts a registration ceremony for user. The user's
// existing credentials are excluded, so an authenticator that already holds
// one of them refuses to create another.
func (s *Service) BeginRegistration(user *User) (*Started, error) {
	params := make([]protocol.CredentialParameter, len(s.cfg.Algorithms))
	for i, alg := range s.cfg.Algorithms {
		params[i] = protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.COSEAlgorithmIdentifier(alg),
		}
	}

	exclusions := make([]protocol.CredentialDescriptor, len(user.Credentials))
	for i, c := range user.Credentials {
		wc := toWebAuthn(c)
		exclusions[i] = wc.Descriptor()
	}

	creation, session, err := s.wa.BeginRegistration(
		webAuthnUser{user},
		webauthn.WithCredentialParameters(params),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		return nil, fmt.Errorf("ceremony: begin registration: %w", err)
	}

	return s.started(creation.Response, creation.Response.Challenge.String(), session)
}

// FinishRegistration verifies the browser's response to a registration
// ceremony and returns the new credential. user and session must be the ones
// the ceremony was started with.
func (s *Service) FinishRegistration(user *User, session Session, response []byte) (*Credential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, verificationError(err)
	}

	created, err := s.wa.CreateCredential(webAuthnUser{user}, session, parsed)
	if err != nil {
		return nil, verificationError(err)
	}

	credential := fromWebAuthn(*created)

	return &credential, nil
}

// BeginLogin starts a discoverable authentication ceremony: the options name
// no credentials, so the authenticator offers the passkeys it holds for the
// relying party and the response says who the user is.
func (s *Service) BeginLogin() (*Started, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.UserVerificationRequirement(s.cfg.UserVerification)),
	)
	if err != nil {
		return nil, fmt.Errorf("ceremony: begin login: %w", err)
	}

	return s.started(assertion.Response, assertion.Response.Challenge.String(), session)
}

// FinishLogin verifies the browser's response to an authentication ceremony.
// lookup resolves the credential ID and user handle from the response to an
// account; the signature is then checked against that account's credential.
func (s *Service) FinishLogin(session Session, response []byte, lookup UserLookup) (*LoginResult, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, verificationError(err)
	}

	var found *User

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := lookup(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, errors.New("user not found")
		}

		found = user

		return webAuthnUser{user}, nil
	}

	_, verified, err := s.wa.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil {
		return nil, verificationError(err)
	}

	return &LoginResult{
		User:                found,
		Credential:          fromWebAuthn(*verified),
		SignCountRegression: verified.Authenticator.CloneWarning,
		UserVerified:        parsed.Response.AuthenticatorData.Flags.HasUserVerified(),
	}, nil
}

// started packages the result of a Begin function and sets the session expiry.
func (s *Service) started(options any, challenge string, session *webauthn.SessionData) (*Started, error) {
	encoded, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("ceremony: encode options: %w", err)
	}

	expiresAt := time.Now().Add(s.cfg.ChallengeTTL)
	session.Expires = expiresAt

	return &Started{
		Options:   encoded,
		Challenge: challenge,
		Session:   *session,
		ExpiresAt: expiresAt,
	}, nil
}

// ChallengeOf extracts the challenge from a registration or authentication
// response without verifying anything. The result is only good for finding
// the stored ceremony; the response is verified against that ceremony's own
// challenge afterwards.
func ChallengeOf(response []byte) (string, error) {
	var body struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}

	if err := json.Unmarshal(response, &body); err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body.Response.ClientDataJSON, "="))
	if err != nil {
		return "", fmt.Errorf("%w: clientDataJSON is not base64url", ErrMalformedResponse)
	}

	var clientData struct {
		Challenge string `json:"challenge"`
	}

	if err := json.Unmarshal(raw, &clientData); err != nil {
		return "", fmt.Errorf("%w: clientDataJSON is not JSON", ErrMalformedResponse)
	}
	if clientData.Challenge == "" {
		return "", fmt.Errorf("%w: no challenge in clientDataJSON", ErrMalformedResponse)
	}

	return clientData.Challenge, nil
}

// Reason describes why a response was rejected, for the server log. It
// contains protocol details such as the expected and received origin, and no
// secrets. It must not be sent to the client.
func Reason(err error) string {
	var perr *protocol.Error
	if errors.As(err, &perr) {
		parts := []string{perr.Type, perr.Details, perr.DevInfo}

		// go-webauthn puts the expected and the received challenge into the
		// developer info of a challenge mismatch. Challenges are never logged.
		if strings.Contains(strings.ToLower(perr.Details), "challenge") || strings.Contains(strings.ToLower(perr.DevInfo), "challenge") {
			parts = []string{perr.Type, perr.Details}
		}

		return strings.Join(slicesDeleteEmpty(parts), ": ")
	}

	if err == nil {
		return ""
	}

	return err.Error()
}

func verificationError(err error) error {
	return fmt.Errorf("%w: %w", ErrVerification, err)
}

func slicesDeleteEmpty(parts []string) []string {
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, strings.TrimSpace(p))
		}
	}

	return out
}

// webAuthnUser adapts User to the interface go-webauthn expects.
type webAuthnUser struct{ u *User }

func (w webAuthnUser) WebAuthnID() []byte          { return w.u.Handle }
func (w webAuthnUser) WebAuthnName() string        { return w.u.Name }
func (w webAuthnUser) WebAuthnDisplayName() string { return w.u.DisplayName }

func (w webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(w.u.Credentials))
	for i, c := range w.u.Credentials {
		out[i] = toWebAuthn(c)
	}

	return out
}

func toWebAuthn(c Credential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}

	return webauthn.Credential{
		ID:                c.ID,
		PublicKey:         c.PublicKey,
		AttestationFormat: c.AttestationFormat,
		Transport:         transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:     c.AAGUID,
			SignCount:  c.SignCount,
			Attachment: protocol.AuthenticatorAttachment(c.Attachment),
		},
	}
}

func fromWebAuthn(c webauthn.Credential) Credential {
	transports := make([]string, len(c.Transport))
	for i, t := range c.Transport {
		transports[i] = string(t)
	}

	return Credential{
		ID:                c.ID,
		PublicKey:         c.PublicKey,
		SignCount:         c.Authenticator.SignCount,
		AAGUID:            c.Authenticator.AAGUID,
		Transports:        transports,
		Attachment:        string(c.Authenticator.Attachment),
		BackupEligible:    c.Flags.BackupEligible,
		BackupState:       c.Flags.BackupState,
		AttestationFormat: c.AttestationFormat,
	}
}
