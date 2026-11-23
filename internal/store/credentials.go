package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// ErrCredentialNotFound means no credential matches the lookup.
var ErrCredentialNotFound = errors.New("store: credential not found")

// FindCredential returns the credential with the given ID (base64url) that
// belongs to a record of the given auth collection.
//
// The collection is part of the lookup on purpose: a credential registered
// for a record of one collection must never authenticate against another.
func FindCredential(app core.App, names Names, collectionRef, credentialID string) (*core.Record, error) {
	if collectionRef == "" || credentialID == "" {
		return nil, ErrCredentialNotFound
	}

	records, err := app.FindAllRecords(names.Credentials, dbx.HashExp{
		FieldCollectionRef: collectionRef,
		FieldCredentialID:  credentialID,
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: find credential: %w", err)
	}
	if len(records) == 0 {
		return nil, ErrCredentialNotFound
	}

	return records[0], nil
}

// CredentialIDExists reports whether a credential with the given ID is stored
// for any user of any collection. Registration uses it to refuse an ID that is
// already taken.
func CredentialIDExists(app core.App, names Names, credentialID string) (bool, error) {
	n, err := app.CountRecords(names.Credentials, dbx.HashExp{FieldCredentialID: credentialID})
	if err != nil {
		return false, fmt.Errorf("store: look up credential id: %w", err)
	}

	return n > 0, nil
}

// ListCredentials returns the credentials of one user, oldest first.
func ListCredentials(app core.App, names Names, collectionRef, recordRef string) ([]*core.Record, error) {
	records := []*core.Record{}

	err := app.RecordQuery(names.Credentials).
		AndWhere(ownerExp(collectionRef, recordRef)).
		OrderBy("[["+FieldCreated+"]] ASC", "[[id]] ASC").
		All(&records)
	if err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}

	return records, nil
}

// CountCredentials returns how many credentials one user has.
func CountCredentials(app core.App, names Names, collectionRef, recordRef string) (int, error) {
	n, err := app.CountRecords(names.Credentials, ownerExp(collectionRef, recordRef))
	if err != nil {
		return 0, fmt.Errorf("store: count credentials: %w", err)
	}

	return int(n), nil
}

func ownerExp(collectionRef, recordRef string) dbx.Expression {
	return dbx.HashExp{FieldCollectionRef: collectionRef, FieldRecordRef: recordRef}
}
