package passkeys

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pocketbase/pocketbase/core"
)

// Module is the handle returned by [Register]. It gives access to the
// effective configuration and, in later versions, to hooks and the Go API.
type Module struct {
	app core.App
	cfg Config
}

// Register validates cfg and attaches the module to app. Call it once, before
// app.Start().
//
// Problems that can be found without a database (malformed relying party ID,
// insecure origins, unsupported options) are returned immediately, wrapped in
// [ErrInvalidConfig]. Problems that depend on the database (a collection in
// AuthCollections that does not exist or is not an auth collection) are
// detected when the server starts, after migrations have run, and make
// startup fail with an error that also wraps [ErrInvalidConfig].
func Register(app core.App, cfg Config) (*Module, error) {
	if app == nil {
		return nil, fmt.Errorf("%w: app is nil", ErrInvalidConfig)
	}

	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	m := &Module{app: app, cfg: cfg}

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		if err := m.checkCollections(e.App); err != nil {
			return err
		}

		for _, warning := range m.startupWarnings(e.App) {
			e.App.Logger().Warn("passkeys: " + warning)
		}

		return e.Next()
	})

	return m, nil
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
