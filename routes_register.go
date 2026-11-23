package passkeys

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/pocketbase/pocketbase/core"

	"github.com/MarioShatterhand/pb-passkeys/internal/ceremony"
	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

// Messages returned by the registration routes. They are deliberately few:
// the reason for a refused response goes to the server log, not to the client.
const (
	msgRegisterFailed  = "Failed to register the passkey."
	msgCredentialLimit = "The passkey limit for this account is reached."
	msgTooManyPending  = "Too many passkey requests in progress. Try again later."
)

var (
	errCredentialExists = errors.New("credential id is already registered")
	errCredentialLimit  = errors.New("credential limit reached")
)

// verifyBody is the request body of the verify routes.
type verifyBody struct {
	// Credential is the PublicKeyCredential the browser returned, in its JSON form.
	Credential json.RawMessage `json:"credential"`

	// Name is an optional label for a new passkey.
	Name string `json:"name"`
}

// handleRegisterOptions starts a registration ceremony for the signed-in user.
func (m *Module) handleRegisterOptions(e *core.RequestEvent) error {
	collection, err := m.routeCollection(e)
	if err != nil {
		return err
	}

	record, err := m.routeUser(e, collection)
	if err != nil {
		return err
	}

	user, err := m.ceremonyUser(e.App, record)
	if err != nil {
		return e.InternalServerError("", err)
	}

	if len(user.Credentials) >= m.cfg.MaxCredentialsPerUser {
		return e.BadRequestError(msgCredentialLimit, nil)
	}

	event := &RegistrationOptionsEvent{
		RequestEvent:    e,
		Record:          record,
		UserName:        user.Name,
		UserDisplayName: user.DisplayName,
	}

	err = m.onRegistrationOptions.Trigger(event, func(event *RegistrationOptionsEvent) error {
		user.Name, user.DisplayName = event.UserName, event.UserDisplayName

		started, err := m.ceremonies.BeginRegistration(user)
		if err != nil {
			return e.InternalServerError("", err)
		}

		err = store.SaveChallenge(e.App, m.names, store.Challenge{
			Value:         started.Challenge,
			Type:          store.ChallengeRegistration,
			CollectionRef: collection.Id,
			RecordRef:     record.Id,
			SessionData:   started.Session,
			ExpiresAt:     started.ExpiresAt,
		}, m.cfg.MaxPendingChallenges)
		if errors.Is(err, store.ErrTooManyChallenges) {
			return e.TooManyRequestsError(msgTooManyPending, nil)
		}
		if err != nil {
			return e.InternalServerError("", err)
		}

		return e.JSON(http.StatusOK, started.Options)
	})
	if err != nil {
		return m.failure(e, asHookError(err), msgRegisterFailed)
	}

	return nil
}

// handleRegisterVerify finishes a registration ceremony and stores the new passkey.
func (m *Module) handleRegisterVerify(e *core.RequestEvent) error {
	collection, err := m.routeCollection(e)
	if err != nil {
		return err
	}

	record, err := m.routeUser(e, collection)
	if err != nil {
		return err
	}

	var body verifyBody
	if err := e.BindBody(&body); err != nil || len(body.Credential) == 0 {
		return e.BadRequestError(msgRegisterFailed, nil)
	}

	name := strings.TrimSpace(body.Name)
	if utf8.RuneCountInString(name) > store.MaxCredentialNameLength {
		return e.BadRequestError("The passkey name is too long.", nil)
	}

	credential, err := m.verifyRegistration(e, collection, record, body.Credential)
	if err != nil {
		if isClientFault(err) {
			m.debugReason(e, "registration refused", collection, record.Id, err)
			return e.BadRequestError(msgRegisterFailed, nil)
		}

		return e.InternalServerError("", err)
	}

	var saved *core.Record

	err = e.App.RunInTransaction(func(txApp core.App) error {
		// The unique index would refuse a duplicate as well; checking first
		// gives a clear reason for the log.
		exists, err := store.CredentialIDExists(txApp, m.names, encodeBytes(credential.ID))
		if err != nil {
			return err
		}
		if exists {
			return errCredentialExists
		}

		// Checked again here, inside the transaction: two registrations may
		// have been started while the user was one below the limit.
		count, err := store.CountCredentials(txApp, m.names, collection.Id, record.Id)
		if err != nil {
			return err
		}
		if count >= m.cfg.MaxCredentialsPerUser {
			return errCredentialLimit
		}

		credentials, err := txApp.FindCachedCollectionByNameOrId(m.names.Credentials)
		if err != nil {
			return err
		}

		saved = core.NewRecord(credentials)
		fillCredentialRecord(saved, record, credential, name)

		if err := txApp.Save(saved); err != nil {
			return err
		}

		return asHookError(m.onCredentialRegistered.Trigger(&CredentialRegisteredEvent{
			App:        txApp,
			Request:    e,
			Record:     record,
			Credential: saved,
		}))
	})

	switch {
	case errors.Is(err, errCredentialExists):
		m.debugReason(e, "registration refused", collection, record.Id, err)
		return e.BadRequestError(msgRegisterFailed, nil)
	case errors.Is(err, errCredentialLimit):
		return e.BadRequestError(msgCredentialLimit, nil)
	case err != nil:
		return m.failure(e, err, msgRegisterFailed)
	}

	return e.JSON(http.StatusOK, saved)
}

// verifyRegistration finds the ceremony the response belongs to, uses its
// challenge up, and verifies the response.
func (m *Module) verifyRegistration(e *core.RequestEvent, collection *core.Collection, record *core.Record, response []byte) (*ceremony.Credential, error) {
	challenge, err := ceremony.ChallengeOf(response)
	if err != nil {
		return nil, err
	}

	var session ceremony.Session

	stored, err := store.ConsumeChallenge(e.App, m.names, challenge, store.ChallengeRegistration, collection.Id, &session)
	if err != nil {
		return nil, err
	}

	// A registration challenge belongs to the user it was issued to.
	if stored.RecordRef != record.Id {
		return nil, store.ErrChallengeMismatch
	}

	user, err := m.ceremonyUser(e.App, record)
	if err != nil {
		return nil, err
	}

	return m.ceremonies.FinishRegistration(user, session, response)
}
