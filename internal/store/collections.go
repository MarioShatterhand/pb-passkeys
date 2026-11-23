// Package store owns the module's collections: their schema, the migration
// that creates them, and (in later files) the queries on them.
package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

// Field names shared by both collections. Owners are referenced by collection
// ID and record ID in plain text fields, the same way PocketBase does it in
// its own _mfas and _externalAuths collections, so one pair of collections
// serves every configured auth collection.
const (
	FieldCollectionRef = "collectionRef"
	FieldRecordRef     = "recordRef"
	FieldCreated       = "created"
	FieldUpdated       = "updated"
)

// Fields of the credentials collection.
const (
	FieldCredentialID            = "credentialId"
	FieldPublicKey               = "publicKey"
	FieldSignCount               = "signCount"
	FieldAAGUID                  = "aaguid"
	FieldTransports              = "transports"
	FieldAuthenticatorAttachment = "authenticatorAttachment"
	FieldBackupEligible          = "backupEligible"
	FieldBackupState             = "backupState"
	FieldAttestationFormat       = "attestationFormat"
	FieldName                    = "name"
	FieldLastUsedAt              = "lastUsedAt"
)

// Fields of the challenges collection.
const (
	FieldChallenge   = "challenge"
	FieldType        = "type"
	FieldSessionData = "sessionData"
	FieldExpiresAt   = "expiresAt"
)

// MaxCredentialNameLength is the longest label a user can give a passkey.
const MaxCredentialNameLength = 64

// ownerRule limits access to the records of the authenticated user. Both
// parts are needed: record IDs are unique only within one collection.
const ownerRule = FieldRecordRef + " = @request.auth.id && " + FieldCollectionRef + " = @request.auth.collectionId"

// ErrCollection is wrapped by the errors of [Check].
var ErrCollection = errors.New("store: collection problem")

// Names holds the names of the module's collections.
type Names struct {
	Credentials string
	Challenges  string
}

// newCredentialsCollection builds the collection that holds one record per passkey.
//
// API rules: the owner can list, view, rename and delete their passkeys.
// Nobody can create one through the API; records are created only by a
// verified registration ceremony. The update rule alone does not restrict
// which fields change; that is enforced by a hook where the routes are bound.
func newCredentialsCollection(name string) *core.Collection {
	c := core.NewBaseCollection(name)

	c.ListRule = types.Pointer(ownerRule)
	c.ViewRule = types.Pointer(ownerRule)
	c.CreateRule = nil
	c.UpdateRule = types.Pointer(ownerRule)
	c.DeleteRule = types.Pointer(ownerRule)

	c.Fields.Add(
		&core.TextField{Name: FieldCollectionRef, Required: true},
		&core.TextField{Name: FieldRecordRef, Required: true},
		// A credential ID is at most 1023 bytes, which is 1364 base64url characters.
		&core.TextField{Name: FieldCredentialID, Required: true, Max: 1364},
		// The COSE public key. Not secret, but of no use to clients, so it is hidden from API responses.
		&core.TextField{Name: FieldPublicKey, Required: true, Hidden: true, Max: 8192},
		&core.NumberField{Name: FieldSignCount, OnlyInt: true, Min: types.Pointer(0.0)},
		&core.TextField{Name: FieldAAGUID, Max: 36},
		&core.JSONField{Name: FieldTransports, MaxSize: 1024},
		&core.TextField{Name: FieldAuthenticatorAttachment, Max: 32},
		&core.BoolField{Name: FieldBackupEligible},
		&core.BoolField{Name: FieldBackupState},
		&core.TextField{Name: FieldAttestationFormat, Max: 32},
		&core.TextField{Name: FieldName, Max: MaxCredentialNameLength},
		&core.DateField{Name: FieldLastUsedAt},
		&core.AutodateField{Name: FieldCreated, OnCreate: true},
		&core.AutodateField{Name: FieldUpdated, OnCreate: true, OnUpdate: true},
	)

	// A credential ID identifies one passkey globally: it must never be
	// registered twice, not even by the same user.
	c.AddIndex("idx_"+name+"_credentialId", true, FieldCredentialID, "")
	c.AddIndex("idx_"+name+"_owner", false, FieldCollectionRef+", "+FieldRecordRef, "")

	return c
}

// newChallengesCollection builds the collection that holds the server-side
// state of ceremonies in progress. It has no API access at all.
func newChallengesCollection(name string) *core.Collection {
	c := core.NewBaseCollection(name)

	c.ListRule = nil
	c.ViewRule = nil
	c.CreateRule = nil
	c.UpdateRule = nil
	c.DeleteRule = nil

	c.Fields.Add(
		// The challenge as sent to the client. It is the lookup key at
		// verification: the client proves which ceremony it answers by
		// returning the challenge inside the signed client data.
		&core.TextField{Name: FieldChallenge, Required: true, Hidden: true, Max: 255},
		&core.TextField{Name: FieldType, Required: true, Max: 32},
		&core.TextField{Name: FieldCollectionRef, Required: true},
		// Empty for a discoverable login, where the user is not known yet.
		&core.TextField{Name: FieldRecordRef},
		&core.JSONField{Name: FieldSessionData, Required: true, Hidden: true, MaxSize: 65536},
		&core.DateField{Name: FieldExpiresAt, Required: true},
		&core.AutodateField{Name: FieldCreated, OnCreate: true},
	)

	c.AddIndex("idx_"+name+"_challenge", true, FieldChallenge, "")
	c.AddIndex("idx_"+name+"_expiresAt", false, FieldExpiresAt, "")

	return c
}

// requiredFields lists, per collection, the fields that must exist for the
// module to work. [Check] uses it to tell the module's collections apart from
// an unrelated collection that happens to have the same name.
func requiredFields(names Names) map[string][]string {
	return map[string][]string{
		names.Credentials: {FieldCollectionRef, FieldRecordRef, FieldCredentialID, FieldPublicKey, FieldSignCount, FieldBackupEligible},
		names.Challenges:  {FieldChallenge, FieldType, FieldCollectionRef, FieldSessionData, FieldExpiresAt},
	}
}

// Check verifies that the module's collections exist and look like the
// module's own. Call it after [Migrate].
//
// A missing collection after a successful migration means that the configured
// names were changed after the first start, or that the collection was
// deleted. The module does not rename or recreate collections on its own,
// because that would silently detach every registered passkey.
func Check(app core.App, names Names) error {
	var errs []error

	for _, name := range []string{names.Credentials, names.Challenges} {
		collection, err := app.FindCollectionByNameOrId(name)
		if errors.Is(err, sql.ErrNoRows) {
			errs = append(errs, fmt.Errorf(
				"collection %q is missing: the module's collection names are fixed after the first start; "+
					"if the name in the configuration was changed, rename the existing collection to match", name))
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("collection %q: %w", name, err))
			continue
		}

		for _, field := range requiredFields(names)[name] {
			if collection.Fields.GetByName(field) == nil {
				errs = append(errs, fmt.Errorf(
					"collection %q has no field %q: a collection with this name exists but was not created by this module", name, field))
				break
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %w", ErrCollection, errors.Join(errs...))
}
