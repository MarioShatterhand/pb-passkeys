// Package testauthn is a software WebAuthn authenticator for tests.
//
// It plays the role of the browser and the authenticator together: given the
// challenge, relying party ID and origin of a ceremony it returns the JSON a
// browser would send to the server (PublicKeyCredential.toJSON()). The
// responses carry real ES256 signatures, so tests exercise the server's actual
// verification instead of mocks.
//
// Credentials use ES256 (ECDSA P-256 with SHA-256) and "none" attestation.
// The exported fields of [Authenticator] can be changed between calls to
// produce the responses a test needs, including invalid ones (user
// verification missing, a changed backup-eligible flag, a sign counter that
// does not advance).
//
// This package must only be used from tests. Private keys are kept in memory
// and never leave the process.
package testauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// Authenticator data flag bits (WebAuthn Level 3, section 6.1).
const (
	flagUserPresent    = 0x01
	flagUserVerified   = 0x04
	flagBackupEligible = 0x08
	flagBackupState    = 0x10
	flagAttestedData   = 0x40
)

// Errors returned by [Authenticator.Get].
var (
	// ErrNoCredential means the authenticator holds no credential that matches the request.
	ErrNoCredential = errors.New("testauthn: no matching credential")

	// ErrAmbiguousCredential means several credentials match and the request does not say which to use.
	ErrAmbiguousCredential = errors.New("testauthn: several credentials match, set GetOptions.CredentialID")
)

// Authenticator is an in-memory authenticator. The zero value is not usable; call [New].
//
// It is not safe for concurrent use.
type Authenticator struct {
	// AAGUID identifies the authenticator model. All zero by default, which is
	// what some platforms report with "none" attestation.
	AAGUID [16]byte

	// UserPresent and UserVerified set the UP and UV flags of every response.
	UserPresent  bool
	UserVerified bool

	// BackupEligible and BackupState set the BE and BS flags of every response.
	// A synced passkey has both set.
	BackupEligible bool
	BackupState    bool

	// ZeroSignCount makes the authenticator always report a sign counter of 0,
	// as synced passkeys do. Otherwise the counter starts at 1 and grows by one
	// with every assertion.
	ZeroSignCount bool

	// Attachment is reported as authenticatorAttachment ("platform" or
	// "cross-platform"). Empty omits the field.
	Attachment string

	// Transports is reported in the registration response.
	Transports []string

	// NextCredentialID, if set, is used as the ID of the next credential
	// instead of a random one, and then cleared. Use it to present a
	// credential ID that is already registered elsewhere.
	NextCredentialID []byte

	credentials []*credential
}

type credential struct {
	id         []byte
	rpID       string
	userHandle []byte
	key        *ecdsa.PrivateKey
	signCount  uint32
}

// New returns an authenticator that behaves like a device-bound platform
// authenticator with user verification.
func New() *Authenticator {
	return &Authenticator{
		UserPresent:  true,
		UserVerified: true,
		Attachment:   "platform",
		Transports:   []string{"internal"},
	}
}

// CreateOptions describes a registration ceremony, with the values the server
// put into PublicKeyCredentialCreationOptions.
type CreateOptions struct {
	// RPID is the relying party ID (rp.id).
	RPID string

	// Origin is the origin the "browser" reports in clientDataJSON, for example "https://example.com".
	Origin string

	// Challenge is the challenge exactly as it appears in the options JSON (base64url, no padding).
	Challenge string

	// UserHandle is the decoded user.id.
	UserHandle []byte
}

// GetOptions describes an authentication ceremony, with the values the server
// put into PublicKeyCredentialRequestOptions.
type GetOptions struct {
	// RPID is the relying party ID (rpId).
	RPID string

	// Origin is the origin the "browser" reports in clientDataJSON.
	Origin string

	// Challenge is the challenge exactly as it appears in the options JSON (base64url, no padding).
	Challenge string

	// AllowCredentials restricts the choice to these credential IDs. Empty
	// means a discoverable login: any credential for RPID may be used.
	AllowCredentials [][]byte

	// CredentialID selects one credential when several match.
	CredentialID []byte
}

// Response is the result of a ceremony.
type Response struct {
	// CredentialID is the raw ID of the credential that was created or used.
	CredentialID []byte

	// JSON is the request body a browser would send: the JSON form of the PublicKeyCredential.
	JSON []byte
}

// Create runs a registration ceremony: it generates a new discoverable
// credential bound to opts.RPID and opts.UserHandle and returns the
// registration response.
func (a *Authenticator) Create(opts CreateOptions) (*Response, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("testauthn: generate key: %w", err)
	}

	id := a.NextCredentialID
	a.NextCredentialID = nil

	if len(id) == 0 {
		id = make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			return nil, fmt.Errorf("testauthn: generate credential id: %w", err)
		}
	}

	cred := &credential{
		id:         id,
		rpID:       opts.RPID,
		userHandle: append([]byte(nil), opts.UserHandle...),
		key:        key,
	}

	coseKey, err := encodePublicKey(key)
	if err != nil {
		return nil, err
	}

	// Attested credential data: AAGUID, credential ID length, credential ID, public key.
	authData := a.authenticatorData(opts.RPID, flagAttestedData, cred.nextSignCount(a.ZeroSignCount))
	authData = append(authData, a.AAGUID[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(authData, id...)
	authData = append(authData, coseKey...)

	attestationObject, err := webauthncbor.Marshal(struct {
		Format       string         `cbor:"fmt"`
		AttStatement map[string]any `cbor:"attStmt"`
		AuthData     []byte         `cbor:"authData"`
	}{
		Format:       "none",
		AttStatement: map[string]any{},
		AuthData:     authData,
	})
	if err != nil {
		return nil, fmt.Errorf("testauthn: encode attestation object: %w", err)
	}

	clientData, err := clientDataJSON("webauthn.create", opts.Challenge, opts.Origin)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(publicKeyCredential{
		ID:                      b64(id),
		RawID:                   b64(id),
		Type:                    "public-key",
		AuthenticatorAttachment: a.Attachment,
		ClientExtensionResults:  map[string]any{},
		Response: map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attestationObject),
			"transports":        a.transports(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("testauthn: encode response: %w", err)
	}

	a.credentials = append(a.credentials, cred)

	return &Response{CredentialID: append([]byte(nil), id...), JSON: body}, nil
}

// Get runs an authentication ceremony with one of the stored credentials and
// returns the assertion response.
func (a *Authenticator) Get(opts GetOptions) (*Response, error) {
	cred, err := a.pick(opts)
	if err != nil {
		return nil, err
	}

	authData := a.authenticatorData(opts.RPID, 0, cred.nextSignCount(a.ZeroSignCount))

	clientData, err := clientDataJSON("webauthn.get", opts.Challenge, opts.Origin)
	if err != nil {
		return nil, err
	}

	// The signature covers authenticatorData || SHA-256(clientDataJSON).
	clientDataHash := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte(nil), authData...), clientDataHash[:]...))

	signature, err := ecdsa.SignASN1(rand.Reader, cred.key, signed[:])
	if err != nil {
		return nil, fmt.Errorf("testauthn: sign assertion: %w", err)
	}

	body, err := json.Marshal(publicKeyCredential{
		ID:                      b64(cred.id),
		RawID:                   b64(cred.id),
		Type:                    "public-key",
		AuthenticatorAttachment: a.Attachment,
		ClientExtensionResults:  map[string]any{},
		Response: map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64(cred.userHandle),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("testauthn: encode response: %w", err)
	}

	return &Response{CredentialID: append([]byte(nil), cred.id...), JSON: body}, nil
}

// SetSignCount sets the stored sign counter of a credential, so that the next
// assertion reports count+1. Use it to simulate a cloned authenticator whose
// counter runs behind the server's. It reports whether the credential exists.
func (a *Authenticator) SetSignCount(credentialID []byte, count uint32) bool {
	for _, c := range a.credentials {
		if bytes.Equal(c.id, credentialID) {
			c.signCount = count
			return true
		}
	}

	return false
}

// CredentialIDs returns the raw IDs of all stored credentials, in creation order.
func (a *Authenticator) CredentialIDs() [][]byte {
	ids := make([][]byte, 0, len(a.credentials))
	for _, c := range a.credentials {
		ids = append(ids, append([]byte(nil), c.id...))
	}

	return ids
}

// pick chooses the credential for an assertion.
func (a *Authenticator) pick(opts GetOptions) (*credential, error) {
	var matches []*credential

	for _, c := range a.credentials {
		if c.rpID != opts.RPID {
			continue
		}

		if len(opts.CredentialID) > 0 && !bytes.Equal(c.id, opts.CredentialID) {
			continue
		}

		if len(opts.AllowCredentials) > 0 && !contains(opts.AllowCredentials, c.id) {
			continue
		}

		matches = append(matches, c)
	}

	switch len(matches) {
	case 0:
		return nil, ErrNoCredential
	case 1:
		return matches[0], nil
	default:
		return nil, ErrAmbiguousCredential
	}
}

// authenticatorData builds the fixed 37-byte prefix: RP ID hash, flags, sign counter.
func (a *Authenticator) authenticatorData(rpID string, extraFlags byte, signCount uint32) []byte {
	flags := extraFlags
	if a.UserPresent {
		flags |= flagUserPresent
	}
	if a.UserVerified {
		flags |= flagUserVerified
	}
	if a.BackupEligible {
		flags |= flagBackupEligible
	}
	if a.BackupState {
		flags |= flagBackupState
	}

	rpIDHash := sha256.Sum256([]byte(rpID))

	data := make([]byte, 0, 37)
	data = append(data, rpIDHash[:]...)
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, signCount)

	return data
}

func (a *Authenticator) transports() []string {
	if a.Transports == nil {
		return []string{}
	}

	return a.Transports
}

// nextSignCount advances and returns the credential's sign counter.
func (c *credential) nextSignCount(zero bool) uint32 {
	if zero {
		return 0
	}

	c.signCount++

	return c.signCount
}

// publicKeyCredential is the JSON form of a PublicKeyCredential (WebAuthn Level 3, section 5.1).
type publicKeyCredential struct {
	ID                      string         `json:"id"`
	RawID                   string         `json:"rawId"`
	Type                    string         `json:"type"`
	AuthenticatorAttachment string         `json:"authenticatorAttachment,omitempty"`
	Response                map[string]any `json:"response"`
	ClientExtensionResults  map[string]any `json:"clientExtensionResults"`
}

// clientDataJSON builds the CollectedClientData a browser would produce.
func clientDataJSON(ceremony, challenge, origin string) ([]byte, error) {
	data, err := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{
		Type:      ceremony,
		Challenge: challenge,
		Origin:    origin,
	})
	if err != nil {
		return nil, fmt.Errorf("testauthn: encode client data: %w", err)
	}

	return data, nil
}

// encodePublicKey returns the COSE_Key encoding of an ES256 public key.
func encodePublicKey(key *ecdsa.PrivateKey) ([]byte, error) {
	// Uncompressed SEC 1 point: 0x04 || X (32 bytes) || Y (32 bytes).
	point, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("testauthn: encode public key: %w", err)
	}
	if len(point) != 65 || point[0] != 4 {
		return nil, errors.New("testauthn: unexpected public key encoding")
	}

	encoded, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: point[1:33],
		YCoord: point[33:65],
	})
	if err != nil {
		return nil, fmt.Errorf("testauthn: encode public key: %w", err)
	}

	return encoded, nil
}

func contains(list [][]byte, id []byte) bool {
	for _, item := range list {
		if bytes.Equal(item, id) {
			return true
		}
	}

	return false
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
