package passkeys

import (
	"errors"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// newTestApp starts an in-process PocketBase with a temporary data directory
// and adds two collections the tests rely on: the auth collection "members"
// and the base collection "notes".
func newTestApp(t *testing.T) *tests.TestApp {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("NewTestApp: %v", err)
	}
	t.Cleanup(app.Cleanup)

	if err := app.Save(core.NewAuthCollection("members")); err != nil {
		t.Fatalf("create auth collection: %v", err)
	}
	if err := app.Save(core.NewBaseCollection("notes")); err != nil {
		t.Fatalf("create base collection: %v", err)
	}

	return app
}

func testConfig(collections ...string) Config {
	return Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		RPOrigins:       []string{"https://example.com"},
		AuthCollections: collections,
	}
}

// serve triggers PocketBase's serve event the way apis.Serve does, without
// opening a listener, and returns the error that would abort startup.
func serve(app core.App) error {
	event := new(core.ServeEvent)
	event.App = app

	return app.OnServe().Trigger(event, func(e *core.ServeEvent) error { return e.Next() })
}

func TestRegister(t *testing.T) {
	app := newTestApp(t)

	m, err := Register(app, testConfig("members"))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	cfg := m.Config()
	if cfg.RoutePrefix != DefaultRoutePrefix || cfg.ChallengeTTL != DefaultChallengeTTL {
		t.Errorf("Config() does not carry defaults: %+v", cfg)
	}

	// The returned configuration is a copy.
	cfg.AuthCollections[0] = "changed"
	if m.Config().AuthCollections[0] != "members" {
		t.Error("Config() exposes the module's internal slices")
	}

	if err := serve(app); err != nil {
		t.Fatalf("startup failed with a valid configuration: %v", err)
	}
}

func TestRegisterRejectsInvalidConfig(t *testing.T) {
	app := newTestApp(t)

	cfg := testConfig("members")
	cfg.RPOrigins = []string{"http://example.com"}

	m, err := Register(app, cfg)
	if err == nil {
		t.Fatal("Register accepted an http origin")
	}
	if m != nil {
		t.Error("Register returned a module together with an error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error does not wrap ErrInvalidConfig: %v", err)
	}

	// A rejected configuration must not leave a startup hook behind.
	if err := serve(app); err != nil {
		t.Errorf("startup failed after a rejected Register: %v", err)
	}
}

func TestRegisterNilApp(t *testing.T) {
	if _, err := Register(nil, testConfig("members")); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Register(nil) error = %v, want ErrInvalidConfig", err)
	}
}

func TestMustRegisterPanics(t *testing.T) {
	app := newTestApp(t)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("MustRegister did not panic on an invalid configuration")
		}
		if err, ok := r.(error); !ok || !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("panic value = %v, want an error wrapping ErrInvalidConfig", r)
		}
	}()

	MustRegister(app, Config{})
}

func TestMustRegisterReturnsModule(t *testing.T) {
	app := newTestApp(t)

	if m := MustRegister(app, testConfig("members")); m == nil {
		t.Fatal("MustRegister returned nil")
	}
}

// Security invariant 19 (docs/security.md): the module refuses to serve
// passkey routes for the superusers collection.
func TestSuperusersCollectionRejected(t *testing.T) {
	app := newTestApp(t)

	t.Run("by name, at Register", func(t *testing.T) {
		_, err := Register(app, testConfig(core.CollectionNameSuperusers))
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Register error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("by ID, at startup", func(t *testing.T) {
		superusers, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
		if err != nil {
			t.Fatalf("find superusers collection: %v", err)
		}

		// The collection ID is a valid collection identifier, so the static check cannot catch it.
		m := &Module{app: app, cfg: testConfig(superusers.Id).withDefaults()}

		err = m.checkCollections(app)
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "superusers collection") {
			t.Fatalf("checkCollections error = %v, want the superusers error", err)
		}
	})
}

func TestStartupFailsForBadCollections(t *testing.T) {
	tests := []struct {
		name       string
		collection string
		want       string
	}{
		{"missing collection", "nobody", `collection "nobody" does not exist`},
		{"base collection", "notes", `"notes" is not an auth collection`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(t)

			if _, err := Register(app, testConfig("members", tt.collection)); err != nil {
				t.Fatalf("Register: %v", err)
			}

			err := serve(app)
			if err == nil {
				t.Fatal("startup succeeded, want an error")
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

func TestStartupWarnings(t *testing.T) {
	has := func(warnings []string, part string) bool {
		for _, w := range warnings {
			if strings.Contains(w, part) {
				return true
			}
		}

		return false
	}

	t.Run("rate limiting disabled", func(t *testing.T) {
		app := newTestApp(t)
		setRateLimits(t, app, false)
		m := &Module{app: app, cfg: testConfig("members").withDefaults()}

		if w := m.startupWarnings(app); !has(w, "rate limiting is disabled") {
			t.Errorf("no warning about disabled rate limiting: %q", w)
		}
	})

	t.Run("rate limiting enabled without a matching rule", func(t *testing.T) {
		app := newTestApp(t)
		setRateLimits(t, app, true, core.RateLimitRule{Label: "/api/collections/", MaxRequests: 10, Duration: 60})
		m := &Module{app: app, cfg: testConfig("members").withDefaults()}

		if w := m.startupWarnings(app); !has(w, "no PocketBase rate limit rule covers") {
			t.Errorf("no warning about the missing rule: %q", w)
		}
	})

	t.Run("rate limiting covers the prefix", func(t *testing.T) {
		app := newTestApp(t)
		setRateLimits(t, app, true, core.RateLimitRule{Label: "POST /api/passkeys/", MaxRequests: 10, Duration: 60})
		m := &Module{app: app, cfg: testConfig("members").withDefaults()}

		if w := m.startupWarnings(app); len(w) != 0 {
			t.Errorf("unexpected warnings: %q", w)
		}
	})

	t.Run("MFA enabled", func(t *testing.T) {
		app := newTestApp(t)
		setRateLimits(t, app, true, core.RateLimitRule{Label: "/api/", MaxRequests: 100, Duration: 60})

		members, err := app.FindCollectionByNameOrId("members")
		if err != nil {
			t.Fatalf("find collection: %v", err)
		}
		members.MFA.Enabled = true
		members.OTP.Enabled = true // PocketBase requires two auth methods for MFA
		if err := app.Save(members); err != nil {
			t.Fatalf("enable MFA: %v", err)
		}

		m := &Module{app: app, cfg: testConfig("members").withDefaults()}

		w := m.startupWarnings(app)
		if len(w) != 1 || !has(w, `collection "members" has MFA enabled`) {
			t.Errorf("warnings = %q, want exactly the MFA warning", w)
		}
	})
}

func TestRateLimitCovers(t *testing.T) {
	const prefix = "/api/passkeys"

	tests := []struct {
		label string
		want  bool
	}{
		{"/", true},
		{"/api/", true},
		{"/api/passkeys/", true},
		{"POST /api/passkeys/", true},
		{"/api/passkeys/members/login/", true},
		{"POST /api/passkeys/members/login/verify", true},
		{"/api/passkeys", false}, // exact path of the prefix itself, which has no route
		{"/api/collections/", false},
		{"/api/passkeys-other/", false},
		{"*:auth", false},
		{"members:create", false},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			rules := []core.RateLimitRule{{Label: tt.label, MaxRequests: 1, Duration: 1}}

			if got := rateLimitCovers(rules, prefix); got != tt.want {
				t.Errorf("rateLimitCovers(%q) = %v, want %v", tt.label, got, tt.want)
			}
		})
	}

	if rateLimitCovers(nil, prefix) {
		t.Error("rateLimitCovers(nil) = true, want false")
	}
}

func setRateLimits(t *testing.T, app core.App, enabled bool, rules ...core.RateLimitRule) {
	t.Helper()

	settings := app.Settings()
	settings.RateLimits.Enabled = enabled
	settings.RateLimits.Rules = rules

	if err := app.Save(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
}
