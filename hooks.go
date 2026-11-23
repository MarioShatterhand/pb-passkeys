package passkeys

import (
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
)

// RegistrationOptionsEvent is passed to the [Module.OnRegistrationOptions] hook.
type RegistrationOptionsEvent struct {
	hook.Event
	*core.RequestEvent

	// Record is the signed-in user who is about to register a passkey.
	Record *core.Record

	// UserName and UserDisplayName are shown by the browser or the
	// authenticator next to the new passkey. They default to the record's
	// email (or its ID when there is none) and to its "name" field (or
	// UserName when empty). A handler may change them before calling Next.
	UserName        string
	UserDisplayName string
}

// CredentialRegisteredEvent is passed to the [Module.OnCredentialRegistered] hook.
type CredentialRegisteredEvent struct {
	hook.Event

	// App is the transaction the credential was saved in. Use it for any
	// database work that must succeed or fail together with the registration.
	App core.App

	// Request is the HTTP request that finished the registration.
	Request *core.RequestEvent

	// Record is the user who owns the new passkey.
	Record *core.Record

	// Credential is the saved record of the credentials collection.
	Credential *core.Record
}

// OnRegistrationOptions fires before the options for a new passkey are sent to
// a signed-in user. A handler may refuse the registration by returning an
// error instead of calling e.Next(), for example to apply its own limits.
func (m *Module) OnRegistrationOptions() *hook.Hook[*RegistrationOptionsEvent] {
	return m.onRegistrationOptions
}

// OnCredentialRegistered fires after a new passkey was verified and saved,
// inside the same database transaction. Returning an error instead of calling
// e.Next() rolls the registration back. Typical uses are notifying the user
// and writing an audit entry.
func (m *Module) OnCredentialRegistered() *hook.Hook[*CredentialRegisteredEvent] {
	return m.onCredentialRegistered
}
