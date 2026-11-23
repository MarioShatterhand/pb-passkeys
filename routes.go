package passkeys

import (
	"errors"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/MarioShatterhand/pb-passkeys/internal/ceremony"
	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

// collectionParam is the name of the path parameter that holds the auth collection.
const collectionParam = "collection"

// modulePaths lists the module's routes, relative to
// {RoutePrefix}/{collection}. None of them has a path parameter of its own:
// secrets are sent in JSON bodies only, because URLs end up in request logs.
var modulePaths = []string{
	"/register/options",
	"/register/verify",
	"/login/options",
	"/login/verify",
}

// bindRoutes mounts the module's routes as {RoutePrefix}/{collection}/...
// All of them are POST.
func (m *Module) bindRoutes(e *core.ServeEvent) {
	group := e.Router.Group(m.cfg.RoutePrefix + "/{" + collectionParam + "}")

	handlers := map[string]func(*core.RequestEvent) error{
		"/register/options": m.handleRegisterOptions,
		"/register/verify":  m.handleRegisterVerify,
		"/login/options":    m.handleLoginOptions,
		"/login/verify":     m.handleLoginVerify,
	}

	for _, path := range modulePaths {
		group.POST(path, handlers[path])
	}
}

// routeCollection resolves the collection named in the path. Only the
// collections listed in Config.AuthCollections have passkey routes; every
// other name, existing or not, gets the same "not found".
func (m *Module) routeCollection(e *core.RequestEvent) (*core.Collection, error) {
	notFound := e.NotFoundError("", nil)

	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue(collectionParam))
	if err != nil || !m.isPasskeyCollection(collection) {
		return nil, notFound
	}

	return collection, nil
}

// routeUser returns the signed-in record, which must belong to the collection
// of the route.
func (m *Module) routeUser(e *core.RequestEvent, collection *core.Collection) (*core.Record, error) {
	if e.Auth == nil {
		return nil, e.UnauthorizedError("The request requires valid record authorization token.", nil)
	}

	if e.Auth.Collection().Id != collection.Id {
		return nil, e.ForbiddenError("The authorized record is not allowed to perform this action.", nil)
	}

	return e.Auth, nil
}

// ceremonyUser builds the ceremony view of a record with all of its passkeys.
func (m *Module) ceremonyUser(app core.App, record *core.Record) (*ceremony.User, error) {
	records, err := store.ListCredentials(app, m.names, record.Collection().Id, record.Id)
	if err != nil {
		return nil, err
	}

	credentials, err := credentialsFromRecords(records)
	if err != nil {
		return nil, err
	}

	name := record.Email()
	if name == "" {
		name = record.Id
	}

	displayName := record.GetString("name")
	if displayName == "" {
		displayName = name
	}

	return &ceremony.User{
		// The user handle is the record ID: random, stable, and free of personal data.
		Handle:      []byte(record.Id),
		Name:        name,
		DisplayName: displayName,
		Credentials: credentials,
	}, nil
}

// isClientFault reports whether err means the request could not succeed
// because of what the client sent, as opposed to a server-side failure.
func isClientFault(err error) bool {
	return errors.Is(err, ceremony.ErrVerification) ||
		errors.Is(err, ceremony.ErrMalformedResponse) ||
		errors.Is(err, store.ErrChallengeNotFound) ||
		errors.Is(err, store.ErrChallengeExpired) ||
		errors.Is(err, store.ErrChallengeMismatch) ||
		errors.Is(err, store.ErrCredentialNotFound)
}

// hookError marks an error that came out of an application hook.
type hookError struct{ err error }

func (h *hookError) Error() string { return h.err.Error() }
func (h *hookError) Unwrap() error { return h.err }

// asHookError wraps a non-nil error returned by a hook trigger.
func asHookError(err error) error {
	if err == nil {
		return nil
	}

	return &hookError{err: err}
}

// failure turns an error from a handler into the response for the client.
//
// An API error is passed through: it is what the module's own code, or a hook
// that wants a specific status, returned on purpose. Any other error from a
// hook means the application refused the operation; the client gets the
// generic message and the reason goes to the debug log. Everything else is a
// server-side failure.
func (m *Module) failure(e *core.RequestEvent, err error, generic string) error {
	var apiErr *router.ApiError
	if errors.As(err, &apiErr) {
		return apiErr
	}

	var fromHook *hookError
	if errors.As(err, &fromHook) {
		e.App.Logger().Debug("passkeys: refused by a hook", "reason", fromHook.Error())

		return e.BadRequestError(generic, nil)
	}

	return e.InternalServerError("", err)
}

// debugReason logs why a ceremony was refused. Only allow-listed, non-secret
// fields are logged: no challenge, session data or client data.
func (m *Module) debugReason(e *core.RequestEvent, what string, collection *core.Collection, recordID string, err error) {
	e.App.Logger().Debug("passkeys: "+what,
		"reason", ceremony.Reason(err),
		"collection", collection.Name,
		"record", recordID,
	)
}
