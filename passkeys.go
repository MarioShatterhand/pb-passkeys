package passkeys

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"

	"github.com/MarioShatterhand/pb-passkeys/internal/ceremony"
	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

// The cron job that removes expired challenges.
const (
	cleanupJobID    = "pbPasskeysCleanup"
	cleanupSchedule = "*/5 * * * *" // every 5 minutes
)

// Module is the handle returned by [Register]. It gives access to the
// effective configuration and, in later versions, to hooks and the Go API.
type Module struct {
	app        core.App
	cfg        Config
	names      store.Names
	ceremonies *ceremony.Service

	onRegistrationOptions  *hook.Hook[*RegistrationOptionsEvent]
	onCredentialRegistered *hook.Hook[*CredentialRegisteredEvent]
	onBeforeLogin          *hook.Hook[*BeforeLoginEvent]
	onLoginFailed          *hook.Hook[*LoginFailedEvent]
	onSignCountAnomaly     *hook.Hook[*SignCountAnomalyEvent]
}

// Register validates cfg and attaches the module to app. Call it once, before
// app.Start().
//
// Problems that can be found without a database (malformed relying party ID,
// insecure origins, unsupported options) are returned immediately, wrapped in
// [ErrInvalidConfig]. Problems that depend on the database (a collection in
// AuthCollections that does not exist or is not an auth collection, one of
// the module's own collections missing after the first start) are detected
// when the server starts, after migrations have run, and make startup fail
// with an error that also wraps [ErrInvalidConfig].
//
// On the first start the module creates its own collections, named in
// Config.Collections.
func Register(app core.App, cfg Config) (*Module, error) {
	if app == nil {
		return nil, fmt.Errorf("%w: app is nil", ErrInvalidConfig)
	}

	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	m, err := newModule(app, cfg)
	if err != nil {
		return nil, err
	}

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		// PocketBase has applied the application's migrations by now, so the
		// configured auth collections exist if they ever will.
		if err := m.checkCollections(e.App); err != nil {
			return err
		}

		names := m.names

		if err := store.Migrate(e.App, names); err != nil {
			return fmt.Errorf("passkeys: %w", err)
		}
		if err := store.Check(e.App, names); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}

		// Expired challenges are already unusable; the job only frees the space.
		cleanup := func() {
			if _, err := store.DeleteExpiredChallenges(app, names); err != nil {
				app.Logger().Error("passkeys: cleanup of expired challenges failed", "error", err.Error())
			}
		}
		if err := e.App.Cron().Add(cleanupJobID, cleanupSchedule, cleanup); err != nil {
			return fmt.Errorf("passkeys: schedule cleanup: %w", err)
		}

		for _, warning := range m.startupWarnings(e.App) {
			e.App.Logger().Warn("passkeys: " + warning)
		}

		m.bindRoutes(e)

		return e.Next()
	})

	return m, nil
}

// newModule builds a Module from a validated configuration with defaults applied.
func newModule(app core.App, cfg Config) (*Module, error) {
	userVerification := map[UserVerification]ceremony.UserVerification{
		UVRequired:    ceremony.UVRequired,
		UVPreferred:   ceremony.UVPreferred,
		UVDiscouraged: ceremony.UVDiscouraged,
	}[cfg.UserVerification]

	ceremonies, err := ceremony.New(ceremony.Config{
		RPID:             cfg.RPID,
		RPDisplayName:    cfg.RPDisplayName,
		RPOrigins:        cfg.RPOrigins,
		UserVerification: userVerification,
		Algorithms:       cfg.Algorithms,
		Timeout:          cfg.Timeout,
		ChallengeTTL:     cfg.ChallengeTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return &Module{
		app: app,
		cfg: cfg,
		names: store.Names{
			Credentials: cfg.Collections.Credentials,
			Challenges:  cfg.Collections.Challenges,
		},
		ceremonies:             ceremonies,
		onRegistrationOptions:  &hook.Hook[*RegistrationOptionsEvent]{},
		onCredentialRegistered: &hook.Hook[*CredentialRegisteredEvent]{},
		onBeforeLogin:          &hook.Hook[*BeforeLoginEvent]{},
		onLoginFailed:          &hook.Hook[*LoginFailedEvent]{},
		onSignCountAnomaly:     &hook.Hook[*SignCountAnomalyEvent]{},
	}, nil
}

// MustRegister is like [Register] but panics if the configuration is invalid.
// It is meant for use in main, where a wrong configuration should stop the
// program.
func MustRegister(app core.App, cfg Config) *Module {
	m, err := Register(app, cfg)
	if err != nil {
		panic(err)
	}

	return m
}

// Config returns the effective configuration: the one passed to [Register]
// with defaults applied.
func (m *Module) Config() Config {
	cfg := m.cfg
	cfg.RPOrigins = append([]string(nil), cfg.RPOrigins...)
	cfg.AuthCollections = append([]string(nil), cfg.AuthCollections...)
	cfg.Algorithms = append([]int(nil), cfg.Algorithms...)

	return cfg
}

// checkCollections verifies the parts of the configuration that depend on the database.
func (m *Module) checkCollections(app core.App) error {
	var errs []error

	for _, name := range m.cfg.AuthCollections {
		collection, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("AuthCollections: collection %q does not exist", name))
			continue
		}

		switch {
		case !collection.IsAuth():
			errs = append(errs, fmt.Errorf("AuthCollections: %q is not an auth collection", name))
		case collection.Name == core.CollectionNameSuperusers:
			// Reached when the collection was given by ID instead of by name.
			errs = append(errs, fmt.Errorf("AuthCollections: %q is the superusers collection, which is not allowed", name))
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %w", ErrInvalidConfig, errors.Join(errs...))
}

// startupWarnings returns human-readable notes about settings that are valid
// but probably not what the operator wants.
func (m *Module) startupWarnings(app core.App) []string {
	var warnings []string

	for _, name := range m.cfg.AuthCollections {
		collection, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			continue
		}

		if collection.MFA.Enabled {
			warnings = append(warnings, fmt.Sprintf(
				"collection %q has MFA enabled: PocketBase will ask for a second authentication method after a passkey login; "+
					"a passkey with user verification is already two factors, so consider turning MFA off for this collection",
				collection.Name,
			))
		}
	}

	limits := app.Settings().RateLimits

	switch {
	case !limits.Enabled:
		warnings = append(warnings, fmt.Sprintf(
			"PocketBase rate limiting is disabled: add rate limit rules for %q before exposing the server, the login routes are public",
			m.cfg.RoutePrefix+"/",
		))
	case !rateLimitCovers(limits.Rules, m.cfg.RoutePrefix):
		warnings = append(warnings, fmt.Sprintf(
			"no PocketBase rate limit rule covers %q: add one, the login routes are public",
			m.cfg.RoutePrefix+"/",
		))
	}

	return warnings
}

// rateLimitCovers reports whether at least one rule applies to routes under prefix.
//
// A PocketBase rule label is a tag, an exact path, or a path prefix ending in
// "/", optionally preceded by an HTTP method ("POST /api/passkeys/").
func rateLimitCovers(rules []core.RateLimitRule, prefix string) bool {
	base := prefix + "/"

	for _, rule := range rules {
		label := rule.Label
		if i := strings.IndexByte(label, ' '); i >= 0 {
			label = label[i+1:]
		}

		if !strings.HasPrefix(label, "/") {
			continue // a tag, not a path
		}

		// A broader prefix rule ("/", "/api/") covers all our routes; a rule
		// below our prefix covers at least some of them.
		if strings.HasSuffix(label, "/") && strings.HasPrefix(base, label) {
			return true
		}
		if strings.HasPrefix(label, base) {
			return true
		}
	}

	return false
}
