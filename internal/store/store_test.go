package store_test

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"

	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

var names = store.Names{Credentials: "passkey_credentials", Challenges: "passkey_challenges"}

// newApp starts an in-process PocketBase with a temporary data directory and
// an auth collection "members".
func newApp(t testing.TB) *tests.TestApp {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("NewTestApp: %v", err)
	}

	if err := app.Save(core.NewAuthCollection("members")); err != nil {
		t.Fatalf("create auth collection: %v", err)
	}

	return app
}

// newMigratedApp is newApp with the module's collections created.
func newMigratedApp(t testing.TB) *tests.TestApp {
	t.Helper()

	app := newApp(t)
	if err := store.Migrate(app, names); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	return app
}

func newMember(t testing.TB, app core.App, email string) *core.Record {
	t.Helper()

	members, err := app.FindCollectionByNameOrId("members")
	if err != nil {
		t.Fatalf("find members: %v", err)
	}

	record := core.NewRecord(members)
	record.SetEmail(email)
	record.SetRandomPassword()

	if err := app.Save(record); err != nil {
		t.Fatalf("create member %s: %v", email, err)
	}

	return record
}

// newCredential stores a credential record for owner, bypassing the API the
// way a verified registration ceremony will.
func newCredential(t testing.TB, app core.App, owner *core.Record, credentialID string) *core.Record {
	t.Helper()

	record, err := buildCredential(app, owner, credentialID)
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	if err := app.Save(record); err != nil {
		t.Fatalf("save credential %s: %v", credentialID, err)
	}

	return record
}

func buildCredential(app core.App, owner *core.Record, credentialID string) (*core.Record, error) {
	collection, err := app.FindCollectionByNameOrId(names.Credentials)
	if err != nil {
		return nil, err
	}

	record := core.NewRecord(collection)
	record.Set(store.FieldCollectionRef, owner.Collection().Id)
	record.Set(store.FieldRecordRef, owner.Id)
	record.Set(store.FieldCredentialID, credentialID)
	record.Set(store.FieldPublicKey, "cHVibGljLWtleS1ieXRlcw")
	record.Set(store.FieldName, "Phone")

	return record, nil
}

func authToken(t testing.TB, record *core.Record) string {
	t.Helper()

	token, err := record.NewAuthToken()
	if err != nil {
		t.Fatalf("NewAuthToken: %v", err)
	}

	return token
}

func TestMigrateCreatesCollections(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	if err := store.Check(app, names); err != nil {
		t.Fatalf("Check after Migrate: %v", err)
	}

	credentials, err := app.FindCollectionByNameOrId(names.Credentials)
	if err != nil {
		t.Fatalf("credentials collection: %v", err)
	}

	const owner = "recordRef = @request.auth.id && collectionRef = @request.auth.collectionId"

	for rule, got := range map[string]*string{
		"list": credentials.ListRule, "view": credentials.ViewRule,
		"update": credentials.UpdateRule, "delete": credentials.DeleteRule,
	} {
		if got == nil || *got != owner {
			t.Errorf("credentials %s rule = %v, want the owner rule", rule, deref(got))
		}
	}
	if credentials.CreateRule != nil {
		t.Errorf("credentials create rule = %q, want nil (superusers only)", *credentials.CreateRule)
	}

	if f, ok := credentials.Fields.GetByName(store.FieldPublicKey).(*core.TextField); !ok || !f.Hidden {
		t.Error("publicKey must be a hidden text field")
	}

	if !hasIndex(credentials, "UNIQUE", store.FieldCredentialID) {
		t.Errorf("no unique index on credentialId: %v", credentials.Indexes)
	}

	challenges, err := app.FindCollectionByNameOrId(names.Challenges)
	if err != nil {
		t.Fatalf("challenges collection: %v", err)
	}

	for rule, got := range map[string]*string{
		"list": challenges.ListRule, "view": challenges.ViewRule, "create": challenges.CreateRule,
		"update": challenges.UpdateRule, "delete": challenges.DeleteRule,
	} {
		if got != nil {
			t.Errorf("challenges %s rule = %q, want nil (superusers only)", rule, *got)
		}
	}

	if f, ok := challenges.Fields.GetByName(store.FieldSessionData).(*core.JSONField); !ok || !f.Hidden {
		t.Error("sessionData must be a hidden JSON field")
	}
}

// Security threat 15 (docs/security.md): the schema has no place for a
// secret in plaintext. The test pins the exact field list, so adding a field
// means coming here and thinking about what it stores.
func TestSchemaHasNoPlaintextSecretFields(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	want := map[string][]string{
		names.Credentials: {
			"id", "collectionRef", "recordRef", "credentialId", "publicKey", "signCount", "aaguid", "transports",
			"authenticatorAttachment", "backupEligible", "backupState", "attestationFormat", "name", "lastUsedAt",
			"created", "updated",
		},
		names.Challenges: {"id", "type", "collectionRef", "recordRef", "sessionData", "expiresAt", "created"},
	}

	for name, fields := range want {
		collection, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			t.Fatalf("collection %s: %v", name, err)
		}

		got := collection.Fields.FieldNames()
		slices.Sort(got)
		slices.Sort(fields)

		if !slices.Equal(got, fields) {
			t.Errorf("%s fields = %v\nwant %v", name, got, fields)
		}

		for _, field := range got {
			for _, word := range []string{"token", "secret", "password", "code", "private"} {
				if strings.Contains(strings.ToLower(field), word) {
					t.Errorf("%s has a field named %q; secrets must be stored only as hashes in fields named *Hash", name, field)
				}
			}
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	member := newMember(t, app, "alice@example.com")
	newCredential(t, app, member, "cred-1")

	for range 2 {
		if err := store.Migrate(app, names); err != nil {
			t.Fatalf("second Migrate: %v", err)
		}
	}

	if n := countRows(t, app, names.Credentials); n != 1 {
		t.Errorf("credentials after repeated Migrate = %d, want 1", n)
	}
	if n := countMigrationRows(t, app); n != 1 {
		t.Errorf("rows in _migrations for the module = %d, want 1", n)
	}
}

// The names are fixed after the first start (docs/open-questions.md): a
// changed name must be reported, not silently answered with new empty
// collections that would detach every registered passkey.
func TestRenamedCollectionsAreReported(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	renamed := store.Names{Credentials: "pk_credentials", Challenges: "pk_challenges"}

	if err := store.Migrate(app, renamed); err != nil {
		t.Fatalf("Migrate with new names: %v", err)
	}

	if _, err := app.FindCollectionByNameOrId(renamed.Credentials); err == nil {
		t.Fatal("Migrate created a collection under the new name after the first start")
	}

	err := store.Check(app, renamed)
	if !errors.Is(err, store.ErrCollection) {
		t.Fatalf("Check error = %v, want ErrCollection", err)
	}
	for _, want := range []string{`"pk_credentials" is missing`, `"pk_challenges" is missing`, "fixed after the first start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q:\n%v", want, err)
		}
	}
}

func TestMigrateAdoptsExistingCollectionsWhenRecordIsLost(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	member := newMember(t, app, "alice@example.com")
	newCredential(t, app, member, "cred-1")

	// What "migrate history-sync" does to migrations it does not know.
	if _, err := app.DB().Delete("_migrations", dbx.HashExp{"file": "pb_passkeys_0001_init"}).Execute(); err != nil {
		t.Fatalf("delete migration record: %v", err)
	}

	if err := store.Migrate(app, names); err != nil {
		t.Fatalf("Migrate after losing the record: %v", err)
	}
	if err := store.Check(app, names); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if n := countRows(t, app, names.Credentials); n != 1 {
		t.Errorf("credentials = %d, want the existing one to survive", n)
	}
}

func TestCheckRejectsForeignCollection(t *testing.T) {
	app := newApp(t)
	defer app.Cleanup()

	// The application already has an unrelated collection under the module's name.
	if err := app.Save(core.NewBaseCollection(names.Credentials)); err != nil {
		t.Fatalf("create foreign collection: %v", err)
	}

	if err := store.Migrate(app, names); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	err := store.Check(app, names)
	if !errors.Is(err, store.ErrCollection) || !strings.Contains(err.Error(), "was not created by this module") {
		t.Fatalf("Check error = %v, want the foreign collection error", err)
	}
}

// Security invariant 3 at the storage level: a credential ID cannot be stored
// twice, neither by another user nor by the same one.
func TestCredentialIDIsUnique(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	alice := newMember(t, app, "alice@example.com")
	bob := newMember(t, app, "bob@example.com")

	newCredential(t, app, alice, "cred-1")

	for _, owner := range []*core.Record{alice, bob} {
		record, err := buildCredential(app, owner, "cred-1")
		if err != nil {
			t.Fatalf("build credential: %v", err)
		}
		if err := app.Save(record); err == nil {
			t.Errorf("a second record with the same credentialId was saved for %s", owner.Email())
		}
	}

	if n := countRows(t, app, names.Credentials); n != 1 {
		t.Errorf("credentials = %d, want 1", n)
	}
}

func TestCredentialsAPIRules(t *testing.T) {
	const listURL = "/api/collections/passkey_credentials/records"

	// setup builds a fresh app with two members who own one credential each.
	type fixture struct {
		app                    *tests.TestApp
		alice, bob             *core.Record
		aliceCred, bobCred     *core.Record
		aliceToken, guestToken string
	}

	setup := func(t *testing.T) fixture {
		app := newMigratedApp(t)
		f := fixture{app: app}
		f.alice = newMember(t, app, "alice@example.com")
		f.bob = newMember(t, app, "bob@example.com")
		f.aliceCred = newCredential(t, app, f.alice, "cred-alice")
		f.bobCred = newCredential(t, app, f.bob, "cred-bob")
		f.aliceToken = authToken(t, f.alice)

		return f
	}

	t.Run("owner lists only their own credentials, without the public key", func(t *testing.T) {
		f := setup(t)
		(&tests.ApiScenario{
			Method:             http.MethodGet,
			URL:                listURL,
			Headers:            map[string]string{"Authorization": f.aliceToken},
			TestAppFactory:     func(testing.TB) *tests.TestApp { return f.app },
			ExpectedStatus:     http.StatusOK,
			ExpectedContent:    []string{`"totalItems":1`, `"credentialId":"cred-alice"`, `"name":"Phone"`},
			NotExpectedContent: []string{"cred-bob", "publicKey", "cHVibGljLWtleS1ieXRlcw"},
		}).Test(t)
	})

	t.Run("guest sees nothing", func(t *testing.T) {
		f := setup(t)
		(&tests.ApiScenario{
			Method:             http.MethodGet,
			URL:                listURL,
			TestAppFactory:     func(testing.TB) *tests.TestApp { return f.app },
			ExpectedStatus:     http.StatusOK,
			ExpectedContent:    []string{`"totalItems":0`},
			NotExpectedContent: []string{"cred-alice", "cred-bob"},
		}).Test(t)
	})

	t.Run("another user's credential cannot be viewed", func(t *testing.T) {
		f := setup(t)
		(&tests.ApiScenario{
			Method:             http.MethodGet,
			URL:                listURL + "/" + f.bobCred.Id,
			Headers:            map[string]string{"Authorization": f.aliceToken},
			TestAppFactory:     func(testing.TB) *tests.TestApp { return f.app },
			ExpectedStatus:     http.StatusNotFound,
			ExpectedContent:    []string{`"status":404`},
			NotExpectedContent: []string{"cred-bob"},
		}).Test(t)
	})

	t.Run("another user's credential cannot be deleted", func(t *testing.T) {
		f := setup(t)
		(&tests.ApiScenario{
			Method:          http.MethodDelete,
			URL:             listURL + "/" + f.bobCred.Id,
			Headers:         map[string]string{"Authorization": f.aliceToken},
			TestAppFactory:  func(testing.TB) *tests.TestApp { return f.app },
			ExpectedStatus:  http.StatusNotFound,
			ExpectedContent: []string{`"status":404`},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, _ *http.Response) {
				if n := countRows(t, app, names.Credentials); n != 2 {
					t.Errorf("credentials = %d, want both to remain", n)
				}
			},
		}).Test(t)
	})

	// Security invariant 12: nobody creates a credential through the API.
	t.Run("credential cannot be created through the API", func(t *testing.T) {
		f := setup(t)
		body := `{"collectionRef":"` + f.alice.Collection().Id + `","recordRef":"` + f.alice.Id +
			`","credentialId":"cred-forged","publicKey":"YXR0YWNrZXIta2V5"}`
		(&tests.ApiScenario{
			Method:          http.MethodPost,
			URL:             listURL,
			Body:            strings.NewReader(body),
			Headers:         map[string]string{"Authorization": f.aliceToken, "Content-Type": "application/json"},
			TestAppFactory:  func(testing.TB) *tests.TestApp { return f.app },
			ExpectedStatus:  http.StatusForbidden,
			ExpectedContent: []string{`"status":403`},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, _ *http.Response) {
				if n := countRows(t, app, names.Credentials); n != 2 {
					t.Errorf("credentials = %d, want no new record", n)
				}
			},
		}).Test(t)
	})
}

func TestChallengesHaveNoAPIAccess(t *testing.T) {
	const listURL = "/api/collections/passkey_challenges/records"

	tests_ := []struct {
		name   string
		method string
		body   string
	}{
		{"list", http.MethodGet, ""},
		{"create", http.MethodPost, `{"type":"login","collectionRef":"x","sessionData":{},"expiresAt":"2030-01-01 00:00:00.000Z"}`},
	}

	for _, tt := range tests_ {
		for _, signedIn := range []bool{false, true} {
			name := tt.name + " as guest"
			if signedIn {
				name = tt.name + " as signed-in user"
			}

			t.Run(name, func(t *testing.T) {
				app := newMigratedApp(t)

				headers := map[string]string{"Content-Type": "application/json"}
				if signedIn {
					headers["Authorization"] = authToken(t, newMember(t, app, "alice@example.com"))
				}

				(&tests.ApiScenario{
					Method:          tt.method,
					URL:             listURL,
					Body:            strings.NewReader(tt.body),
					Headers:         headers,
					TestAppFactory:  func(testing.TB) *tests.TestApp { return app },
					ExpectedStatus:  http.StatusForbidden,
					ExpectedContent: []string{`"status":403`},
					AfterTestFunc: func(t testing.TB, app *tests.TestApp, _ *http.Response) {
						if n := countRows(t, app, names.Challenges); n != 0 {
							t.Errorf("challenges = %d, want 0", n)
						}
					},
				}).Test(t)
			})
		}
	}
}

func hasIndex(c *core.Collection, kind, column string) bool {
	for _, idx := range c.Indexes {
		if strings.Contains(idx, kind) && strings.Contains(idx, column) {
			return true
		}
	}

	return false
}

func countRows(t testing.TB, app core.App, collection string) int {
	t.Helper()

	n, err := app.CountRecords(collection)
	if err != nil {
		t.Fatalf("count %s: %v", collection, err)
	}

	return int(n)
}

func countMigrationRows(t testing.TB, app core.App) int {
	t.Helper()

	var n int
	err := app.DB().Select("count(*)").From("_migrations").
		Where(dbx.NewExp("file LIKE 'pb_passkeys_%'")).Row(&n)
	if err != nil {
		t.Fatalf("count migration rows: %v", err)
	}

	return n
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}

	return *s
}
