package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/pocketbase/pocketbase/core"
)

// migrationInit is the key under which the first migration is recorded in
// PocketBase's _migrations table. It must be unique among all migrations of
// the application and must never change.
const migrationInit = "pb_passkeys_0001_init"

// Migrate creates the module's collections if this installation has not
// created them yet. It is safe to call on every start.
//
// The migration runs through PocketBase's migrations runner and is recorded
// in the same _migrations table as the application's migrations, but it is
// kept in a list of its own instead of the global core.AppMigrations. There
// are two reasons. The migration depends on the configured collection names,
// and a process-wide list cannot hold a different configuration per app
// instance. And a migration in the global list can be reverted with
// "migrate down", which would delete every registered passkey.
//
// The record in _migrations is what tells a first start (create the
// collections) from a later one (a missing collection is an error, see
// [Check]). If that record is lost while the collections still exist, the
// migration finds them and leaves them as they are.
func Migrate(app core.App, names Names) error {
	var list core.MigrationsList

	list.Register(func(txApp core.App) error {
		return createCollections(txApp, names)
	}, nil, migrationInit)

	if _, err := core.NewMigrationsRunner(app, list).Up(); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}

	return nil
}

// createCollections creates each collection that does not exist yet.
func createCollections(app core.App, names Names) error {
	collections := []*core.Collection{
		newCredentialsCollection(names.Credentials),
		newChallengesCollection(names.Challenges),
	}

	for _, collection := range collections {
		_, err := app.FindCollectionByNameOrId(collection.Name)
		if err == nil {
			continue // already there; Check decides whether it is usable
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("look up collection %q: %w", collection.Name, err)
		}

		if err := app.Save(collection); err != nil {
			return fmt.Errorf("create collection %q: %w", collection.Name, err)
		}
	}

	return nil
}
