package passkeys

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

// ErrInvalidConfig is wrapped by every error that [Register] returns for a
// configuration problem. The returned error lists all problems found, not
// only the first.
var ErrInvalidConfig = errors.New("passkeys: invalid configuration")

// UserVerification says whether the authenticator must verify the user
// (PIN, fingerprint, face) during a ceremony.
type UserVerification int

const (
	// UVRequired rejects responses without user verification. It is the default.
	UVRequired UserVerification = iota

	// UVPreferred asks for user verification but accepts responses without it.
	UVPreferred

	// UVDiscouraged asks the authenticator not to verify the user.
	UVDiscouraged
)

// SignCountPolicy says what happens when an authenticator's signature counter
// does not increase, which may mean that the authenticator was cloned.
type SignCountPolicy int

const (
	// SignCountWarn accepts the login and fires the sign count anomaly hook.
	// It is the default, because synced passkeys do not keep a counter.
	SignCountWarn SignCountPolicy = iota

	// SignCountReject rejects the login. Suitable when only hardware security keys are used.
	SignCountReject

	// SignCountIgnore accepts the login without firing the hook.
	SignCountIgnore
)

// COSE algorithm identifiers accepted in [Config.Algorithms].
const (
	AlgES256 = -7   // ECDSA with P-256 and SHA-256
	AlgEdDSA = -8   // EdDSA (Ed25519)
	AlgRS256 = -257 // RSASSA-PKCS1-v1_5 with SHA-256
)

// Defaults applied by [Register] to fields left at their zero value.
const (
	DefaultChallengeTTL          = 5 * time.Minute
	DefaultTimeout               = 2 * time.Minute
	DefaultMaxPendingChallenges  = 10000
	DefaultMaxCredentialsPerUser = 10
	DefaultRoutePrefix           = "/api/passkeys"
	DefaultCredentialsCollection = "passkey_credentials"
	DefaultChallengesCollection  = "passkey_challenges"
)

// maxChallengeTTL bounds how long a ceremony may stay open.
const maxChallengeTTL = time.Hour

// androidOriginPrefix marks the origin an Android app sends through Credential Manager.
const androidOriginPrefix = "android:apk-key-hash:"

var (
	collectionNameRegex = regexp.MustCompile(`^\w+$`)
	routePrefixRegex    = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)+$`)
)

// CollectionNames holds the names of the collections the module creates.
// Empty fields get the default name.
//
// The names are used when the module first creates its collections and are
// fixed from then on: the module never renames a collection.
type CollectionNames struct {
	// Credentials stores one record per registered passkey. Default "passkey_credentials".
	Credentials string

	// Challenges stores the server-side state of ceremonies in progress. Default "passkey_challenges".
	Challenges string
}

// Config configures the module. Only the relying party fields and
// AuthCollections are required; every other field has a safe default.
type Config struct {
	// RPID is the WebAuthn relying party ID: a domain without scheme, port or
	// path, for example "example.com". Passkeys are bound to it, so it cannot
	// be changed later without invalidating every registered passkey. Required.
	RPID string

	// RPDisplayName is the name shown to the user by the browser or the authenticator. Required.
	RPDisplayName string

	// RPOrigins lists the exact origins allowed to run ceremonies, for example
	// "https://example.com". Each host must be RPID or one of its subdomains.
	// Plain http is accepted only for localhost. Android apps that use
	// Credential Manager are listed as "android:apk-key-hash:<hash>". Required.
	RPOrigins []string

	// AuthCollections lists the auth collections (by name) whose records can
	// register and use passkeys. The superusers collection is not allowed. Required.
	AuthCollections []string

	// UserVerification is the user verification policy. Default [UVRequired].
	UserVerification UserVerification

	// Attestation is the attestation conveyance preference. Only "none" is
	// supported, which is also the default.
	Attestation string

	// Algorithms lists the accepted COSE algorithms in order of preference.
	// Default: ES256, EdDSA, RS256.
	Algorithms []int

	// ChallengeTTL is how long a ceremony may take from options to
	// verification. Default 5 minutes, at most 1 hour.
	ChallengeTTL time.Duration

	// Timeout is the hint sent to the browser for how long it may wait for the
	// user. Default 2 minutes. It cannot exceed ChallengeTTL.
	Timeout time.Duration

	// MaxPendingChallenges caps the number of unexpired challenges stored at
	// once. Above it, public ceremonies are refused until challenges expire.
	// Default 10000.
	MaxPendingChallenges int

	// MaxCredentialsPerUser caps the passkeys one account can hold. Default 10.
	MaxCredentialsPerUser int

	// AllowDeleteLastCredential lets a user delete their only passkey. The
	// default (false) prevents users from locking themselves out.
	AllowDeleteLastCredential bool

	// SignCountPolicy is the reaction to a signature counter that does not
	// increase. Default [SignCountWarn].
	SignCountPolicy SignCountPolicy

	// RoutePrefix is the path under which the module's routes are mounted, as
	// {RoutePrefix}/{collection}/... Default "/api/passkeys".
	RoutePrefix string

	// Collections names the module's own collections.
	Collections CollectionNames
}

// withDefaults returns a copy of c with defaults applied and values normalized.
func (c Config) withDefaults() Config {
	c.RPID = strings.TrimSpace(c.RPID)
	c.RPDisplayName = strings.TrimSpace(c.RPDisplayName)
	c.RPOrigins = slices.Clone(c.RPOrigins)
	c.AuthCollections = slices.Clone(c.AuthCollections)
	c.Algorithms = slices.Clone(c.Algorithms)

	if c.Attestation == "" {
		c.Attestation = "none"
	}
	if len(c.Algorithms) == 0 {
		c.Algorithms = []int{AlgES256, AlgEdDSA, AlgRS256}
	}
	if c.ChallengeTTL == 0 {
		c.ChallengeTTL = DefaultChallengeTTL
	}
	if c.Timeout == 0 {
		c.Timeout = min(DefaultTimeout, c.ChallengeTTL)
	}
	if c.MaxPendingChallenges == 0 {
		c.MaxPendingChallenges = DefaultMaxPendingChallenges
	}
	if c.MaxCredentialsPerUser == 0 {
		c.MaxCredentialsPerUser = DefaultMaxCredentialsPerUser
	}
	if c.RoutePrefix == "" {
		c.RoutePrefix = DefaultRoutePrefix
	}
	if c.Collections.Credentials == "" {
		c.Collections.Credentials = DefaultCredentialsCollection
	}
	if c.Collections.Challenges == "" {
		c.Collections.Challenges = DefaultChallengesCollection
	}

	return c
}

// validate checks everything that can be checked without a database. It
// expects defaults to be applied already.
func (c Config) validate() error {
	var errs []error

	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	rpIDValid := validateRPID(c.RPID) == nil
	if err := validateRPID(c.RPID); err != nil {
		fail("RPID: %w", err)
	}

	if c.RPDisplayName == "" {
		fail("RPDisplayName: required")
	}

	if len(c.RPOrigins) == 0 {
		fail("RPOrigins: at least one origin is required")
	}
	for _, origin := range c.RPOrigins {
		if err := validateOrigin(origin, c.RPID, rpIDValid); err != nil {
			fail("RPOrigins: %q: %w", origin, err)
		}
	}
	if d := firstDuplicate(c.RPOrigins); d != "" {
		fail("RPOrigins: %q is listed more than once", d)
	}

	if len(c.AuthCollections) == 0 {
		fail("AuthCollections: at least one collection is required")
	}
	for _, name := range c.AuthCollections {
		switch {
		case !collectionNameRegex.MatchString(name):
			fail("AuthCollections: %q is not a valid collection name", name)
		case strings.EqualFold(name, core.CollectionNameSuperusers):
			fail("AuthCollections: %q is not allowed, superuser authentication is out of scope", name)
		}
	}
	if d := firstDuplicate(lower(c.AuthCollections)); d != "" {
		fail("AuthCollections: %q is listed more than once", d)
	}

	if c.UserVerification < UVRequired || c.UserVerification > UVDiscouraged {
		fail("UserVerification: unknown value %d", c.UserVerification)
	}
	if c.SignCountPolicy < SignCountWarn || c.SignCountPolicy > SignCountIgnore {
		fail("SignCountPolicy: unknown value %d", c.SignCountPolicy)
	}

	if c.Attestation != "none" {
		fail("Attestation: %q is not supported, only \"none\"", c.Attestation)
	}

	for _, alg := range c.Algorithms {
		if alg != AlgES256 && alg != AlgEdDSA && alg != AlgRS256 {
			fail("Algorithms: %d is not supported (use AlgES256, AlgEdDSA, AlgRS256)", alg)
		}
	}
	if d := firstDuplicate(c.Algorithms); d != 0 {
		fail("Algorithms: %d is listed more than once", d)
	}

	if c.ChallengeTTL < 0 || c.ChallengeTTL > maxChallengeTTL {
		fail("ChallengeTTL: %s is out of range (0, %s]", c.ChallengeTTL, maxChallengeTTL)
	}
	if c.Timeout < 0 || c.Timeout > c.ChallengeTTL {
		fail("Timeout: %s must be positive and not longer than ChallengeTTL (%s)", c.Timeout, c.ChallengeTTL)
	}

	if c.MaxPendingChallenges < 0 {
		fail("MaxPendingChallenges: must be positive")
	}
	if c.MaxCredentialsPerUser < 0 {
		fail("MaxCredentialsPerUser: must be positive")
	}

	if !routePrefixRegex.MatchString(c.RoutePrefix) {
		fail("RoutePrefix: %q must start with \"/\", have no trailing \"/\" and use only letters, digits, \"-\" and \"_\"", c.RoutePrefix)
	}

	own := []string{c.Collections.Credentials, c.Collections.Challenges}
	for _, name := range own {
		switch {
		case !collectionNameRegex.MatchString(name):
			fail("Collections: %q is not a valid collection name", name)
		case strings.HasPrefix(name, "_"):
			fail("Collections: %q must not start with \"_\", that prefix is reserved for PocketBase system collections", name)
		case slices.Contains(lower(c.AuthCollections), strings.ToLower(name)):
			fail("Collections: %q is also listed in AuthCollections", name)
		}
	}
	if d := firstDuplicate(lower(own)); d != "" {
		fail("Collections: %q is used for more than one collection", d)
	}

	if len(errs) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %w", ErrInvalidConfig, errors.Join(errs...))
}

// validateRPID checks that id is a bare host name.
func validateRPID(id string) error {
	switch {
	case id == "":
		return errors.New("required")
	case strings.Contains(id, "://"):
		return errors.New("must not contain a scheme")
	case strings.ContainsAny(id, "/?#@: \t"):
		return errors.New("must be a domain only, without port, path or other URL parts")
	case id != strings.ToLower(id):
		return errors.New("must be lower case")
	case strings.HasPrefix(id, ".") || strings.HasSuffix(id, ".") || strings.Contains(id, ".."):
		return errors.New("is not a valid domain")
	case net.ParseIP(id) != nil:
		return errors.New("must be a domain, not an IP address")
	}

	return nil
}

// validateOrigin checks one entry of RPOrigins. The host is compared with
// rpID only when checkHost is true (that is, when rpID itself is valid).
func validateOrigin(origin, rpID string, checkHost bool) error {
	if hash, ok := strings.CutPrefix(origin, androidOriginPrefix); ok {
		if hash == "" {
			return errors.New("the key hash is missing")
		}

		return nil
	}

	u, err := url.Parse(origin)
	if err != nil {
		return errors.New("is not a valid URL")
	}

	host := u.Hostname()

	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("must start with https:// (or http:// for localhost)")
	case host == "":
		return errors.New("has no host")
	case u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(origin, "?") || strings.HasSuffix(origin, "#"):
		return errors.New("must be an origin only: scheme, host and optional port")
	case host != strings.ToLower(host):
		return errors.New("host must be lower case")
	case u.Scheme == "http" && !isLoopbackHost(host):
		return errors.New("plain http is allowed only for localhost")
	}

	if checkHost && host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("host is neither %q nor one of its subdomains", rpID)
	}

	return nil
}

// isLoopbackHost reports whether host is localhost or a loopback IP address.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// firstDuplicate returns the first value that occurs more than once, or the zero value.
func firstDuplicate[T comparable](values []T) T {
	seen := make(map[T]struct{}, len(values))

	for _, v := range values {
		if _, ok := seen[v]; ok {
			return v
		}

		seen[v] = struct{}{}
	}

	var zero T

	return zero
}

func lower(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ToLower(v)
	}

	return out
}
