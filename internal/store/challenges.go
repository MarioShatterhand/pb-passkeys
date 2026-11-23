package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

// ChallengeType names the ceremony a challenge was issued for. A challenge
// can only complete a ceremony of its own type.
type ChallengeType string

const (
	// ChallengeRegistration is issued by register/options.
	ChallengeRegistration ChallengeType = "registration"

	// ChallengeLogin is issued by login/options.
	ChallengeLogin ChallengeType = "login"
)

// Errors returned by [SaveChallenge] and [ConsumeChallenge].
var (
	// ErrTooManyChallenges means the cap on unexpired challenges is reached.
	ErrTooManyChallenges = errors.New("store: too many pending challenges")

	// ErrChallengeNotFound means no challenge with that value exists. It was
	// never issued, was already used, or was removed after expiring.
	ErrChallengeNotFound = errors.New("store: challenge not found")

	// ErrChallengeExpired means the challenge existed but its lifetime is over.
	ErrChallengeExpired = errors.New("store: challenge expired")

	// ErrChallengeMismatch means the challenge was issued for another
	// ceremony type or another collection than the one it was presented to.
	ErrChallengeMismatch = errors.New("store: challenge does not belong to this ceremony")
)

// Challenge is the server-side state of one ceremony in progress.
type Challenge struct {
	// Value is the WebAuthn challenge exactly as sent to the client (base64url).
	Value string

	// Type is the ceremony the challenge was issued for.
	Type ChallengeType

	// CollectionRef is the ID of the auth collection named in the route.
	CollectionRef string

	// RecordRef is the ID of the user the ceremony is for. Empty for a
	// discoverable login, where the user is not known until verification.
	RecordRef string

	// SessionData is the ceremony state to keep until verification. It must
	// be JSON-serializable.
	SessionData any

	// ExpiresAt is the moment after which the challenge can no longer be used.
	ExpiresAt time.Time
}

// SaveChallenge stores a new challenge.
//
// maxPending caps the number of unexpired challenges in the whole collection:
// when it is reached, nothing is written and [ErrTooManyChallenges] is
// returned. The cap exists because challenges are created by public,
// unauthenticated requests. Counting and inserting happen in one transaction,
// so concurrent requests cannot exceed the cap.
func SaveChallenge(app core.App, names Names, c Challenge, maxPending int) error {
	expiresAt, err := types.ParseDateTime(c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: challenge expiry: %w", err)
	}

	return app.RunInTransaction(func(txApp core.App) error {
		pending, err := CountPendingChallenges(txApp, names)
		if err != nil {
			return err
		}
		if pending >= maxPending {
			return ErrTooManyChallenges
		}

		collection, err := txApp.FindCachedCollectionByNameOrId(names.Challenges)
		if err != nil {
			return fmt.Errorf("store: challenges collection: %w", err)
		}

		record := core.NewRecord(collection)
		record.Set(FieldChallenge, c.Value)
		record.Set(FieldType, string(c.Type))
		record.Set(FieldCollectionRef, c.CollectionRef)
		record.Set(FieldRecordRef, c.RecordRef)
		record.Set(FieldSessionData, c.SessionData)
		record.Set(FieldExpiresAt, expiresAt)

		if err := txApp.Save(record); err != nil {
			return fmt.Errorf("store: save challenge: %w", err)
		}

		return nil
	})
}

// ConsumeChallenge looks up the challenge with the given value, deletes it,
// and returns it with its session data decoded into sessionData (a pointer,
// or nil to skip decoding).
//
// A challenge is single-use: it is deleted as soon as it is presented,
// whether or not it turns out to be acceptable. Lookup and deletion run in
// one transaction, so of two concurrent requests with the same challenge at
// most one gets it; the other gets [ErrChallengeNotFound].
//
// After deletion the challenge is rejected with [ErrChallengeExpired] if its
// lifetime is over, or with [ErrChallengeMismatch] if it was issued for
// another ceremony type or another collection.
func ConsumeChallenge(app core.App, names Names, value string, want ChallengeType, collectionRef string, sessionData any) (*Challenge, error) {
	if value == "" {
		return nil, ErrChallengeNotFound
	}

	var record *core.Record

	err := app.RunInTransaction(func(txApp core.App) error {
		found, err := txApp.FindFirstRecordByData(names.Challenges, FieldChallenge, value)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrChallengeNotFound
		}
		if err != nil {
			return fmt.Errorf("store: find challenge: %w", err)
		}

		if err := txApp.Delete(found); err != nil {
			return fmt.Errorf("store: delete challenge: %w", err)
		}

		record = found

		return nil
	})
	if err != nil {
		return nil, err
	}

	c := &Challenge{
		Value:         record.GetString(FieldChallenge),
		Type:          ChallengeType(record.GetString(FieldType)),
		CollectionRef: record.GetString(FieldCollectionRef),
		RecordRef:     record.GetString(FieldRecordRef),
		ExpiresAt:     record.GetDateTime(FieldExpiresAt).Time(),
	}

	if !time.Now().Before(c.ExpiresAt) {
		return nil, ErrChallengeExpired
	}
	if c.Type != want || c.CollectionRef != collectionRef {
		return nil, ErrChallengeMismatch
	}

	if sessionData != nil {
		if err := record.UnmarshalJSONField(FieldSessionData, sessionData); err != nil {
			return nil, fmt.Errorf("store: decode session data: %w", err)
		}

		c.SessionData = sessionData
	}

	return c, nil
}

// CountPendingChallenges returns the number of challenges that have not expired yet.
func CountPendingChallenges(app core.App, names Names) (int, error) {
	n, err := app.CountRecords(names.Challenges, dbx.NewExp(
		"[["+FieldExpiresAt+"]] > {:now}", dbx.Params{"now": types.NowDateTime().String()},
	))
	if err != nil {
		return 0, fmt.Errorf("store: count challenges: %w", err)
	}

	return int(n), nil
}

// DeleteExpiredChallenges removes the challenges whose lifetime is over and
// returns how many were removed. Expired challenges are already unusable;
// this only frees the space.
func DeleteExpiredChallenges(app core.App, names Names) (int, error) {
	expired, err := app.FindAllRecords(names.Challenges, dbx.NewExp(
		"[["+FieldExpiresAt+"]] <= {:now}", dbx.Params{"now": types.NowDateTime().String()},
	))
	if err != nil {
		return 0, fmt.Errorf("store: find expired challenges: %w", err)
	}

	deleted := 0

	for _, record := range expired {
		if err := app.Delete(record); err != nil {
			return deleted, fmt.Errorf("store: delete expired challenge: %w", err)
		}

		deleted++
	}

	return deleted, nil
}
