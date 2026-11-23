package passkeys

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/types"

	"github.com/MarioShatterhand/pb-passkeys/internal/ceremony"
	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

// AuthMethod is the method name the module passes to PocketBase when a
// passkey login succeeds. It shows up in OnRecordAuthRequest hooks and is the
// name PocketBase's MFA compares against other methods.
const AuthMethod = "passkey"

// msgLoginFailed is the one message for every failed login, whatever the
// reason: unknown credential, wrong signature, expired ceremony, or a refusal
// by policy or by a hook. It must not vary, or it would reveal which accounts
// and credentials exist.
const msgLoginFailed = "Failed to authenticate."

var (
	errSignCountRejected  = errors.New("signature counter did not increase and the policy is to reject")
	errUserHandleMismatch = errors.New("user handle does not match the owner of the credential")
)

// handleLoginOptions starts a discoverable login. It is public: the caller is
// not known yet, and the response is the same for everyone.
func (m *Module) handleLoginOptions(e *core.RequestEvent) error {
	collection, err := m.routeCollection(e)
	if err != nil {
		return err
	}

	started, err := m.ceremonies.BeginLogin()
	if err != nil {
		return e.InternalServerError("", err)
	}

	err = store.SaveChallenge(e.App, m.names, store.Challenge{
		Value:         started.Challenge,
		Type:          store.ChallengeLogin,
		CollectionRef: collection.Id,
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
}

// loginOutcome is what a verified assertion resolves to.
type loginOutcome struct {
	record     *core.Record // the user
	credential *core.Record // the passkey that signed
	result     *ceremony.LoginResult
}

// handleLoginVerify finishes a login and answers with PocketBase's standard
// auth response.
func (m *Module) handleLoginVerify(e *core.RequestEvent) error {
	collection, err := m.routeCollection(e)
	if err != nil {
		return err
	}

	var body verifyBody
	if err := e.BindBody(&body); err != nil || len(body.Credential) == 0 {
		return m.loginFailed(e, collection, nil, ceremony.ErrMalformedResponse)
	}

	outcome, err := m.verifyLogin(e, collection, body.Credential)
	if err != nil {
		if isClientFault(err) {
			return m.loginFailed(e, collection, nil, err)
		}

		return e.InternalServerError("", err)
	}

	if outcome.result.SignCountRegression && m.cfg.SignCountPolicy != SignCountIgnore {
		rejected := m.cfg.SignCountPolicy == SignCountReject

		hookErr := m.onSignCountAnomaly.Trigger(&SignCountAnomalyEvent{
			RequestEvent: e,
			Record:       outcome.record,
			Credential:   outcome.credential,
			Rejected:     rejected,
		})
		if hookErr != nil {
			e.App.Logger().Warn("passkeys: sign count anomaly hook failed", "error", hookErr.Error())
		}

		if rejected {
			return m.loginFailed(e, collection, outcome.record, errSignCountRejected)
		}
	}

	// The assertion was valid, so the credential's state moves forward even
	// if a hook refuses the login below.
	outcome.credential.Set(store.FieldSignCount, int64(outcome.result.Credential.SignCount))
	outcome.credential.Set(store.FieldBackupState, outcome.result.Credential.BackupState)
	outcome.credential.Set(store.FieldLastUsedAt, types.NowDateTime())

	if err := e.App.Save(outcome.credential); err != nil {
		return e.InternalServerError("", err)
	}

	event := &BeforeLoginEvent{
		RequestEvent: e,
		Record:       outcome.record,
		Credential:   outcome.credential,
		UserVerified: outcome.result.UserVerified,
	}

	err = m.onBeforeLogin.Trigger(event, func(event *BeforeLoginEvent) error {
		// PocketBase issues the token, applies the collection's auth rule
		// and MFA, records the origin and sends the new-device alert.
		return apis.RecordAuthResponse(e, event.Record, AuthMethod, nil)
	})
	if err == nil {
		return nil
	}

	// PocketBase has already written its "second factor required" answer.
	if errors.Is(err, apis.ErrMFA) {
		return err
	}

	// An API error is a deliberate answer: PocketBase's own (the collection's
	// auth rule) or one chosen by a hook. It is passed through.
	var apiErr *router.ApiError
	if errors.As(err, &apiErr) {
		return apiErr
	}

	// Anything else is a plain error from a hook: the application refused.
	return m.loginFailed(e, collection, outcome.record, err)
}

// verifyLogin finds the ceremony the response belongs to, uses its challenge
// up, and verifies the assertion against the credential it names.
func (m *Module) verifyLogin(e *core.RequestEvent, collection *core.Collection, response []byte) (*loginOutcome, error) {
	challenge, err := ceremony.ChallengeOf(response)
	if err != nil {
		return nil, err
	}

	var session ceremony.Session

	if _, err := store.ConsumeChallenge(e.App, m.names, challenge, store.ChallengeLogin, collection.Id, &session); err != nil {
		return nil, err
	}

	outcome := &loginOutcome{}

	lookup := func(credentialID, userHandle []byte) (*ceremony.User, error) {
		// The credential must belong to the collection of the route.
		credential, err := store.FindCredential(e.App, m.names, collection.Id, encodeBytes(credentialID))
		if err != nil {
			return nil, err
		}

		// The user handle is the record ID. It must name the owner of the
		// credential; go-webauthn already requires it to be present.
		if string(userHandle) != credential.GetString(store.FieldRecordRef) {
			return nil, errUserHandleMismatch
		}

		record, err := e.App.FindRecordById(collection, credential.GetString(store.FieldRecordRef))
		if err != nil {
			return nil, fmt.Errorf("owner of the credential: %w", err)
		}

		user, err := m.ceremonyUser(e.App, record)
		if err != nil {
			return nil, err
		}

		outcome.record, outcome.credential = record, credential

		return user, nil
	}

	result, err := m.ceremonies.FinishLogin(session, response, lookup)
	if err != nil {
		return nil, err
	}

	outcome.result = result

	return outcome, nil
}

// loginFailed fires OnLoginFailed, logs the reason, and returns the generic error.
func (m *Module) loginFailed(e *core.RequestEvent, collection *core.Collection, record *core.Record, reason error) error {
	recordID := ""
	if record != nil {
		recordID = record.Id
	}

	m.debugReason(e, "login refused", collection, recordID, reason)

	hookErr := m.onLoginFailed.Trigger(&LoginFailedEvent{
		RequestEvent: e,
		Collection:   collection,
		Record:       record,
		Reason:       ceremony.Reason(reason),
	})
	if hookErr != nil {
		e.App.Logger().Warn("passkeys: login failed hook returned an error", "error", hookErr.Error())
	}

	return e.BadRequestError(msgLoginFailed, nil)
}
