package passkeys

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"

	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

// Messages of the credential management rules.
const (
	msgOnlyNameEditable = "Only the name of a passkey can be changed."
	msgLastCredential   = "The last passkey of an account cannot be deleted."
)

// Kind is a coarse description of the authenticator a passkey lives on.
type Kind string

// Kinds returned by [CredentialKind].
const (
	// KindSynced is a passkey that a provider copies between the user's
	// devices (a password manager, a platform keychain).
	KindSynced Kind = "synced"

	// KindDevice is a passkey bound to one device, such as a phone or a
	// computer with a platform authenticator.
	KindDevice Kind = "device"

	// KindSecurityKey is a passkey on a roaming hardware key.
	KindSecurityKey Kind = "security_key"

	// KindUnknown is returned when the stored data does not tell.
	KindUnknown Kind = "unknown"
)

// CredentialKind tells what kind of authenticator a record of the credentials
// collection belongs to, so that an application can show users which of their
// passkeys is which.
//
// The answer is derived from what the browser and the authenticator reported
// at registration. With "none" attestation that data is not signed, so the
// result is a display hint only and must never be used for a security
// decision.
func CredentialKind(record *core.Record) Kind {
	if record == nil {
		return KindUnknown
	}

	var transports []string
	_ = record.UnmarshalJSONField(store.FieldTransports, &transports)

	attachment := record.GetString(store.FieldAuthenticatorAttachment)
	internal := slices.Contains(transports, "internal")
	roaming := slices.Contains(transports, "usb") || slices.Contains(transports, "nfc") || slices.Contains(transports, "ble")

	switch {
	case record.GetBool(store.FieldBackupEligible):
		return KindSynced
	case attachment == "cross-platform", roaming && !internal:
		return KindSecurityKey
	case attachment == "platform", internal:
		return KindDevice
	default:
		return KindUnknown
	}
}

// ListCredentials returns the passkeys of a user, oldest first, as records of
// the credentials collection.
func (m *Module) ListCredentials(user *core.Record) ([]*core.Record, error) {
	return store.ListCredentials(m.app, m.names, user.Collection().Id, user.Id)
}

// bindCredentialHooks installs the rules that the API rules of the
// credentials collection cannot express on their own.
func (m *Module) bindCredentialHooks() {
	m.app.OnRecordUpdateRequest(m.names.Credentials).BindFunc(m.guardCredentialUpdate)
	m.app.OnRecordDeleteRequest(m.names.Credentials).BindFunc(m.guardCredentialDelete)

	m.app.OnRecordDeleteExecute().Bind(&hook.Handler[*core.RecordEvent]{
		Func: m.deleteCredentialsWithOwner,
	})
}

// guardCredentialUpdate lets an API update change nothing but the name. The
// collection's update rule only says who may update a record, not which
// fields; without this check a user could overwrite their own public key or
// reassign a credential.
func (m *Module) guardCredentialUpdate(e *core.RecordRequestEvent) error {
	if e.HasSuperuserAuth() {
		return e.Next()
	}

	// Refuse the request by what it asks for, not only by what would change.
	// PocketBase silently drops hidden fields such as the public key from
	// what a non-superuser submitted, before this hook sees it; such a
	// request should fail loudly, so the body is read again as it was sent.
	submitted := map[string]any{}
	if err := e.BindBody(&submitted); err != nil {
		return e.BadRequestError("", err)
	}

	for key := range submitted {
		if key != store.FieldName {
			return e.ForbiddenError(msgOnlyNameEditable, nil)
		}
	}

	// Second line of defence: whatever reached the record must leave every
	// field but the name as it was.
	original := e.Record.Original()

	for _, field := range e.Record.Collection().Fields {
		name := field.GetName()
		if name == store.FieldName || name == store.FieldUpdated {
			continue
		}

		if !sameValue(e.Record.GetRaw(name), original.GetRaw(name)) {
			return e.ForbiddenError(msgOnlyNameEditable, nil)
		}
	}

	return e.Next()
}

// guardCredentialDelete refuses to delete a user's last passkey, unless the
// configuration allows it, and fires OnCredentialDeleted.
//
// The check and the delete run in one transaction. PocketBase serializes
// write transactions, so two requests that each delete one of the last two
// passkeys cannot both pass the check.
func (m *Module) guardCredentialDelete(e *core.RecordRequestEvent) error {
	collectionRef := e.Record.GetString(store.FieldCollectionRef)
	recordRef := e.Record.GetString(store.FieldRecordRef)
	protectLast := !m.cfg.AllowDeleteLastCredential && !e.HasSuperuserAuth()

	originalApp := e.App

	return e.App.RunInTransaction(func(txApp core.App) error {
		e.App = txApp
		defer func() { e.App = originalApp }()

		if protectLast {
			count, err := store.CountCredentials(txApp, m.names, collectionRef, recordRef)
			if err != nil {
				return err
			}
			if count <= 1 {
				return e.BadRequestError(msgLastCredential, nil)
			}
		}

		if err := e.Next(); err != nil {
			return err
		}

		// The owner may be gone already; the hook then gets a nil Record.
		owner, _ := txApp.FindRecordById(collectionRef, recordRef)

		return m.onCredentialDeleted.Trigger(&CredentialDeletedEvent{
			App:        txApp,
			Request:    e.RequestEvent,
			Record:     owner,
			Credential: e.Record,
		})
	})
}

// deleteCredentialsWithOwner removes a user's passkeys together with the
// user record, in the same transaction, the way PocketBase removes its own
// per-record auth data.
func (m *Module) deleteCredentialsWithOwner(e *core.RecordEvent) error {
	if !m.isPasskeyCollection(e.Record.Collection()) {
		return e.Next()
	}

	originalApp := e.App

	return e.App.RunInTransaction(func(txApp core.App) error {
		e.App = txApp
		defer func() { e.App = originalApp }()

		if err := e.Next(); err != nil {
			return err
		}

		_, err := store.DeleteCredentialsOf(txApp, m.names, e.Record.Collection().Id, e.Record.Id)

		return err
	})
}

// isPasskeyCollection reports whether collection is one of Config.AuthCollections.
func (m *Module) isPasskeyCollection(collection *core.Collection) bool {
	if collection == nil || !collection.IsAuth() || collection.Name == core.CollectionNameSuperusers {
		return false
	}

	for _, name := range m.cfg.AuthCollections {
		if strings.EqualFold(name, collection.Name) || name == collection.Id {
			return true
		}
	}

	return false
}

// sameValue compares two raw field values by their JSON form, which is how
// they are stored and returned.
func sameValue(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)

	return errA == nil && errB == nil && string(ja) == string(jb)
}
