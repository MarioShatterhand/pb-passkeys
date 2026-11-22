package passkeys

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// validConfig returns the smallest configuration that passes validation.
func validConfig() Config {
	return Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		RPOrigins:       []string{"https://example.com"},
		AuthCollections: []string{"users"},
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := validConfig().withDefaults()

	if err := cfg.validate(); err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}

	if cfg.UserVerification != UVRequired {
		t.Errorf("UserVerification = %d, want UVRequired", cfg.UserVerification)
	}
	if cfg.SignCountPolicy != SignCountWarn {
		t.Errorf("SignCountPolicy = %d, want SignCountWarn", cfg.SignCountPolicy)
	}
	if cfg.Attestation != "none" {
		t.Errorf("Attestation = %q, want none", cfg.Attestation)
	}
	if got, want := cfg.Algorithms, []int{AlgES256, AlgEdDSA, AlgRS256}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("Algorithms = %v, want %v", got, want)
	}
	if cfg.ChallengeTTL != 5*time.Minute || cfg.Timeout != 2*time.Minute {
		t.Errorf("ChallengeTTL = %s, Timeout = %s; want 5m and 2m", cfg.ChallengeTTL, cfg.Timeout)
	}
	if cfg.MaxPendingChallenges != 10000 || cfg.MaxCredentialsPerUser != 10 {
		t.Errorf("MaxPendingChallenges = %d, MaxCredentialsPerUser = %d; want 10000 and 10", cfg.MaxPendingChallenges, cfg.MaxCredentialsPerUser)
	}
	if cfg.AllowDeleteLastCredential {
		t.Error("AllowDeleteLastCredential defaults to true, want false")
	}
	if cfg.RoutePrefix != "/api/passkeys" {
		t.Errorf("RoutePrefix = %q, want /api/passkeys", cfg.RoutePrefix)
	}
	if cfg.Collections.Credentials != "passkey_credentials" || cfg.Collections.Challenges != "passkey_challenges" {
		t.Errorf("Collections = %+v, want the default names", cfg.Collections)
	}
}

func TestConfigTimeoutDefaultFollowsShortChallengeTTL(t *testing.T) {
	cfg := validConfig()
	cfg.ChallengeTTL = time.Minute
	cfg = cfg.withDefaults()

	if cfg.Timeout != time.Minute {
		t.Errorf("Timeout = %s, want it capped at ChallengeTTL (1m)", cfg.Timeout)
	}
	if err := cfg.validate(); err != nil {
		t.Errorf("config rejected: %v", err)
	}
}

func TestConfigDoesNotAliasCallerSlices(t *testing.T) {
	in := validConfig()
	out := in.withDefaults()

	out.RPOrigins[0] = "https://changed.example"
	out.AuthCollections[0] = "changed"

	if in.RPOrigins[0] != "https://example.com" || in.AuthCollections[0] != "users" {
		t.Error("withDefaults shares slices with the caller's Config")
	}
}

func TestConfigAccepted(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"subdomain origin", func(c *Config) { c.RPOrigins = []string{"https://app.example.com"} }},
		{"origin with port", func(c *Config) { c.RPOrigins = []string{"https://example.com:8443"} }},
		{"several origins", func(c *Config) { c.RPOrigins = []string{"https://example.com", "https://app.example.com"} }},
		{"localhost over http", func(c *Config) { c.RPID = "localhost"; c.RPOrigins = []string{"http://localhost:8090"} }},
		{"android origin", func(c *Config) {
			c.RPOrigins = []string{"https://example.com", "android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		}},
		{"several collections", func(c *Config) { c.AuthCollections = []string{"users", "members"} }},
		{"explicit none attestation", func(c *Config) { c.Attestation = "none" }},
		{"single algorithm", func(c *Config) { c.Algorithms = []int{AlgES256} }},
		{"preferred user verification", func(c *Config) { c.UserVerification = UVPreferred }},
		{"reject sign count policy", func(c *Config) { c.SignCountPolicy = SignCountReject }},
		{"custom route prefix", func(c *Config) { c.RoutePrefix = "/api/auth-keys/v1" }},
		{"custom collection names", func(c *Config) { c.Collections = CollectionNames{Credentials: "pk_creds", Challenges: "pk_chals"} }},
		{"timeout equal to challenge TTL", func(c *Config) { c.ChallengeTTL = time.Minute; c.Timeout = time.Minute }},
		{"surrounding spaces in RPID", func(c *Config) { c.RPID = " example.com " }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.edit(&cfg)

			if err := cfg.withDefaults().validate(); err != nil {
				t.Fatalf("config rejected: %v", err)
			}
		})
	}
}

func TestConfigRejected(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string // substring of the error message
	}{
		// Relying party ID.
		{"empty RPID", func(c *Config) { c.RPID = "" }, "RPID: required"},
		{"RPID with scheme", func(c *Config) { c.RPID = "https://example.com" }, "RPID: must not contain a scheme"},
		{"RPID with port", func(c *Config) { c.RPID = "example.com:443" }, "RPID: must be a domain only"},
		{"RPID with path", func(c *Config) { c.RPID = "example.com/app" }, "RPID: must be a domain only"},
		{"RPID in upper case", func(c *Config) { c.RPID = "Example.com" }, "RPID: must be lower case"},
		{"RPID with trailing dot", func(c *Config) { c.RPID = "example.com." }, "RPID: is not a valid domain"},
		{"RPID as IP address", func(c *Config) { c.RPID = "192.0.2.10"; c.RPOrigins = []string{"https://192.0.2.10"} }, "RPID: must be a domain, not an IP address"},
		{"empty display name", func(c *Config) { c.RPDisplayName = "  " }, "RPDisplayName: required"},

		// Origins.
		{"no origins", func(c *Config) { c.RPOrigins = nil }, "RPOrigins: at least one origin is required"},
		{"origin of another domain", func(c *Config) { c.RPOrigins = []string{"https://example.org"} }, "neither \"example.com\" nor one of its subdomains"},
		{"origin with RPID as suffix only", func(c *Config) { c.RPOrigins = []string{"https://notexample.com"} }, "neither \"example.com\" nor one of its subdomains"},
		{"origin with RPID as subdomain label", func(c *Config) { c.RPOrigins = []string{"https://example.com.evil.example"} }, "neither \"example.com\" nor one of its subdomains"},
		{"http origin", func(c *Config) { c.RPOrigins = []string{"http://example.com"} }, "plain http is allowed only for localhost"},
		{"origin without scheme", func(c *Config) { c.RPOrigins = []string{"example.com"} }, "must start with https://"},
		{"origin with other scheme", func(c *Config) { c.RPOrigins = []string{"ftp://example.com"} }, "must start with https://"},
		{"origin with path", func(c *Config) { c.RPOrigins = []string{"https://example.com/app"} }, "must be an origin only"},
		{"origin with trailing slash", func(c *Config) { c.RPOrigins = []string{"https://example.com/"} }, "must be an origin only"},
		{"origin with query", func(c *Config) { c.RPOrigins = []string{"https://example.com?x=1"} }, "must be an origin only"},
		{"origin with user info", func(c *Config) { c.RPOrigins = []string{"https://alice@example.com"} }, "must be an origin only"},
		{"origin in upper case", func(c *Config) { c.RPOrigins = []string{"https://Example.com"} }, "host must be lower case"},
		{"wildcard origin", func(c *Config) { c.RPOrigins = []string{"https://*.example.org"} }, "neither \"example.com\" nor one of its subdomains"},
		{"duplicate origin", func(c *Config) { c.RPOrigins = []string{"https://example.com", "https://example.com"} }, "listed more than once"},
		{"android origin without hash", func(c *Config) { c.RPOrigins = []string{"android:apk-key-hash:"} }, "the key hash is missing"},

		// Auth collections.
		{"no collections", func(c *Config) { c.AuthCollections = nil }, "AuthCollections: at least one collection is required"},
		{"superusers collection", func(c *Config) { c.AuthCollections = []string{"_superusers"} }, "superuser authentication is out of scope"},
		{"superusers collection in other case", func(c *Config) { c.AuthCollections = []string{"users", "_Superusers"} }, "superuser authentication is out of scope"},
		{"invalid collection name", func(c *Config) { c.AuthCollections = []string{"my users"} }, "is not a valid collection name"},
		{"duplicate collection", func(c *Config) { c.AuthCollections = []string{"users", "Users"} }, "listed more than once"},

		// Policy.
		{"unknown user verification", func(c *Config) { c.UserVerification = 7 }, "UserVerification: unknown value 7"},
		{"unknown sign count policy", func(c *Config) { c.SignCountPolicy = -1 }, "SignCountPolicy: unknown value -1"},
		{"direct attestation", func(c *Config) { c.Attestation = "direct" }, "Attestation: \"direct\" is not supported"},
		{"unsupported algorithm", func(c *Config) { c.Algorithms = []int{AlgES256, -65535} }, "Algorithms: -65535 is not supported"},
		{"duplicate algorithm", func(c *Config) { c.Algorithms = []int{AlgES256, AlgES256} }, "Algorithms: -7 is listed more than once"},

		// Limits.
		{"negative challenge TTL", func(c *Config) { c.ChallengeTTL = -time.Second }, "ChallengeTTL:"},
		{"challenge TTL above the maximum", func(c *Config) { c.ChallengeTTL = 2 * time.Hour }, "ChallengeTTL:"},
		{"timeout longer than challenge TTL", func(c *Config) { c.ChallengeTTL = time.Minute; c.Timeout = 2 * time.Minute }, "Timeout:"},
		{"negative timeout", func(c *Config) { c.Timeout = -time.Second }, "Timeout:"},
		{"negative pending challenges", func(c *Config) { c.MaxPendingChallenges = -1 }, "MaxPendingChallenges: must be positive"},
		{"negative credentials per user", func(c *Config) { c.MaxCredentialsPerUser = -1 }, "MaxCredentialsPerUser: must be positive"},

		// Routing and storage.
		{"route prefix without slash", func(c *Config) { c.RoutePrefix = "api/passkeys" }, "RoutePrefix:"},
		{"route prefix with trailing slash", func(c *Config) { c.RoutePrefix = "/api/passkeys/" }, "RoutePrefix:"},
		{"route prefix with parameter", func(c *Config) { c.RoutePrefix = "/api/{x}" }, "RoutePrefix:"},
		{"root route prefix", func(c *Config) { c.RoutePrefix = "/" }, "RoutePrefix:"},
		{"system collection name", func(c *Config) { c.Collections.Credentials = "_passkeys" }, "must not start with \"_\""},
		{"invalid own collection name", func(c *Config) { c.Collections.Challenges = "passkey-challenges" }, "is not a valid collection name"},
		{"same name for both collections", func(c *Config) { c.Collections = CollectionNames{Credentials: "pk", Challenges: "PK"} }, "used for more than one collection"},
		{"own collection equal to auth collection", func(c *Config) { c.Collections.Credentials = "users" }, "is also listed in AuthCollections"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.edit(&cfg)

			err := cfg.withDefaults().validate()
			if err == nil {
				t.Fatal("config accepted, want an error")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error does not wrap ErrInvalidConfig: %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestConfigReportsAllProblems(t *testing.T) {
	cfg := Config{RPID: "https://example.com", RPOrigins: []string{"http://example.org"}}

	err := cfg.withDefaults().validate()
	if err == nil {
		t.Fatal("config accepted, want an error")
	}

	for _, want := range []string{"RPID:", "RPDisplayName:", "RPOrigins:", "AuthCollections:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s\n%v", want, err)
		}
	}
}
