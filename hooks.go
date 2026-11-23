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

// BeforeLoginEvent is passed to the [Module.OnBeforeLogin] hook.
type BeforeLoginEvent struct {
	hook.Event
	*core.RequestEvent

	// Record is the user whose passkey was just verified.
	Record *core.Record

	// Credential is the record of the passkey that signed.
	Credential *core.Record

	// UserVerified tells whether the authenticator verified the user (PIN,
	// fingerprint, face) for this login. It is always true when the
	// configured policy is UVRequired.
	UserVerified bool
}

// LoginFailedEvent is passed to the [Module.OnLoginFailed] hook.
type LoginFailedEvent struct {
	hook.Event
	*core.RequestEvent

	// Collection is the auth collection of the route.
	Collection *core.Collection

	// Record is the user the attempt was for, when the module got far enough
	// to know. It is nil for an unknown credential, a bad signature or an
	// expired ceremony.
	Record *core.Record

	// Reason says why the login failed. It is meant for logs and alerting and
	// must not be shown to the client.
	Reason string
}

// SignCountAnomalyEvent is passed to the [Module.OnSignCountAnomaly] hook.
type SignCountAnomalyEvent struct {
	hook.Event
	*core.RequestEvent

	// Record is the user who logged in.
	Record *core.Record

	// Credential is the passkey whose signature counter did not increase.
	// Its stored counter is left as it was.
	Credential *core.Record

	// Rejected tells whether the login is refused because of the anomaly
	// (SignCountReject) or goes on (SignCountWarn).
	Rejected bool
}

// OnBeforeLogin fires after a passkey assertion was verified and before
// PocketBase issues the auth token. A handler may refuse the login by
// returning an error instead of calling e.Next(), for example for a disabled
// account or a network rule.
func (m *Module) OnBeforeLogin() *hook.Hook[*BeforeLoginEvent] {
	return m.onBeforeLogin
}

// OnLoginFailed fires for every failed passkey login. The client always gets
// the same generic answer; this hook is where the reason is available, for
// alerting or for a log line that tools such as fail2ban can read.
func (m *Module) OnLoginFailed() *hook.Hook[*LoginFailedEvent] {
	return m.onLoginFailed
}

// OnSignCountAnomaly fires when a login was signed by an authenticator whose
// signature counter did not increase although it uses one, which may mean the
// authenticator was cloned. It fires under SignCountWarn and SignCountReject,
// not under SignCountIgnore.
func (m *Module) OnSignCountAnomaly() *hook.Hook[*SignCountAnomalyEvent] {
	return m.onSignCountAnomaly
}
