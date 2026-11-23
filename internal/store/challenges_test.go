package store_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"

	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

const membersRef = "col-members"

// session stands in for the go-webauthn session data kept with a challenge.
type session struct {
	Challenge string `json:"challenge"`
	UserID    []byte `json:"userId"`
}

func loginChallenge(value string) store.Challenge {
	return store.Challenge{
		Value:         value,
		Type:          store.ChallengeLogin,
		CollectionRef: membersRef,
		SessionData:   session{Challenge: value},
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
}

func mustSave(t *testing.T, app core.App, c store.Challenge) {
	t.Helper()

	if err := store.SaveChallenge(app, names, c, 1000); err != nil {
		t.Fatalf("SaveChallenge(%s): %v", c.Value, err)
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	in := store.Challenge{
		Value:         "challenge-1",
		Type:          store.ChallengeRegistration,
		CollectionRef: membersRef,
		RecordRef:     "record-1",
		SessionData:   session{Challenge: "challenge-1", UserID: []byte("record-1")},
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	mustSave(t, app, in)

	var got session

	out, err := store.ConsumeChallenge(app, names, "challenge-1", store.ChallengeRegistration, membersRef, &got)
	if err != nil {
		t.Fatalf("ConsumeChallenge: %v", err)
	}

	if out.Value != in.Value || out.Type != in.Type || out.CollectionRef != in.CollectionRef || out.RecordRef != in.RecordRef {
		t.Errorf("challenge = %+v, want the stored values", out)
	}
	if got.Challenge != "challenge-1" || string(got.UserID) != "record-1" {
		t.Errorf("session data = %+v, want it decoded as stored", got)
	}
	if d := out.ExpiresAt.Sub(in.ExpiresAt); d < -time.Second || d > time.Second {
		t.Errorf("ExpiresAt = %s, want about %s", out.ExpiresAt, in.ExpiresAt)
	}
}

// Security invariant 2: a challenge is single-use.
func TestChallengeCannotBeUsedTwice(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	mustSave(t, app, loginChallenge("challenge-1"))

	if _, err := store.ConsumeChallenge(app, names, "challenge-1", store.ChallengeLogin, membersRef, nil); err != nil {
		t.Fatalf("first use: %v", err)
	}

	_, err := store.ConsumeChallenge(app, names, "challenge-1", store.ChallengeLogin, membersRef, nil)
	if !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("second use: err = %v, want ErrChallengeNotFound", err)
	}
}

// Security invariant 2, concurrent form: of many simultaneous uses of one
// challenge exactly one succeeds.
func TestChallengeConcurrentUse(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	mustSave(t, app, loginChallenge("challenge-1"))

	const attempts = 16

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
		other   []error
	)

	start := make(chan struct{})

	for range attempts {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			_, err := store.ConsumeChallenge(app, names, "challenge-1", store.ChallengeLogin, membersRef, nil)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err == nil:
				success++
			case !errors.Is(err, store.ErrChallengeNotFound):
				other = append(other, err)
			}
		}()
	}

	close(start)
	wg.Wait()

	if success != 1 {
		t.Errorf("successful uses = %d, want exactly 1", success)
	}
	if len(other) > 0 {
		t.Errorf("unexpected errors: %v", other)
	}
}

// Security invariant 2: a challenge cannot finish a ceremony of another type,
// and presenting it there still uses it up.
func TestChallengeRejectedAndConsumed(t *testing.T) {
	tests := []struct {
		name       string
		challenge  store.Challenge
		useType    store.ChallengeType
		useCollRef string
		want       error
	}{
		{
			name:       "login challenge at registration",
			challenge:  loginChallenge("challenge-1"),
			useType:    store.ChallengeRegistration,
			useCollRef: membersRef,
			want:       store.ErrChallengeMismatch,
		},
		{
			name:       "challenge of another collection",
			challenge:  loginChallenge("challenge-1"),
			useType:    store.ChallengeLogin,
			useCollRef: "col-other",
			want:       store.ErrChallengeMismatch,
		},
		{
			name: "expired challenge",
			challenge: func() store.Challenge {
				c := loginChallenge("challenge-1")
				c.ExpiresAt = time.Now().Add(-time.Second)
				return c
			}(),
			useType:    store.ChallengeLogin,
			useCollRef: membersRef,
			want:       store.ErrChallengeExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newMigratedApp(t)
			defer app.Cleanup()

			mustSave(t, app, tt.challenge)

			var got session

			_, err := store.ConsumeChallenge(app, names, "challenge-1", tt.useType, tt.useCollRef, &got)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if got.Challenge != "" {
				t.Error("session data was decoded for a rejected challenge")
			}

			// Even with the right parameters it is gone now.
			_, err = store.ConsumeChallenge(app, names, "challenge-1", tt.challenge.Type, tt.challenge.CollectionRef, nil)
			if !errors.Is(err, store.ErrChallengeNotFound) {
				t.Errorf("after rejection: err = %v, want ErrChallengeNotFound", err)
			}
			if n := countRows(t, app, names.Challenges); n != 0 {
				t.Errorf("challenges left = %d, want 0", n)
			}
		})
	}
}

func TestChallengeUnknown(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	mustSave(t, app, loginChallenge("challenge-1"))

	for _, value := range []string{"", "never-issued"} {
		_, err := store.ConsumeChallenge(app, names, value, store.ChallengeLogin, membersRef, nil)
		if !errors.Is(err, store.ErrChallengeNotFound) {
			t.Errorf("ConsumeChallenge(%q): err = %v, want ErrChallengeNotFound", value, err)
		}
	}

	if n := countRows(t, app, names.Challenges); n != 1 {
		t.Errorf("challenges = %d, want the stored one untouched", n)
	}
}

func TestChallengeValueIsUnique(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	mustSave(t, app, loginChallenge("challenge-1"))

	if err := store.SaveChallenge(app, names, loginChallenge("challenge-1"), 1000); err == nil {
		t.Fatal("a second challenge with the same value was saved")
	}
}

// Security invariant 21: above the cap nothing is written.
func TestPendingChallengesCap(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	const limit = 3

	// Expired challenges do not count towards the cap.
	expired := loginChallenge("expired-1")
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	mustSave(t, app, expired)

	for i := range limit {
		if err := store.SaveChallenge(app, names, loginChallenge(fmt.Sprintf("challenge-%d", i)), limit); err != nil {
			t.Fatalf("challenge %d below the cap: %v", i, err)
		}
	}

	err := store.SaveChallenge(app, names, loginChallenge("one-too-many"), limit)
	if !errors.Is(err, store.ErrTooManyChallenges) {
		t.Fatalf("at the cap: err = %v, want ErrTooManyChallenges", err)
	}

	if n := countRows(t, app, names.Challenges); n != limit+1 {
		t.Errorf("rows = %d, want %d (the cap plus the expired one)", n, limit+1)
	}

	// Using one up frees a slot.
	if _, err := store.ConsumeChallenge(app, names, "challenge-0", store.ChallengeLogin, membersRef, nil); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := store.SaveChallenge(app, names, loginChallenge("after-free"), limit); err != nil {
		t.Errorf("after freeing a slot: %v", err)
	}
}

func TestPendingChallengesCapUnderConcurrency(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	const (
		limit    = 5
		attempts = 20
	)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		saved    int
		refused  int
		failures []error
	)

	start := make(chan struct{})

	for i := range attempts {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			err := store.SaveChallenge(app, names, loginChallenge(fmt.Sprintf("challenge-%d", i)), limit)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err == nil:
				saved++
			case errors.Is(err, store.ErrTooManyChallenges):
				refused++
			default:
				failures = append(failures, err)
			}
		}()
	}

	close(start)
	wg.Wait()

	if len(failures) > 0 {
		t.Fatalf("unexpected errors: %v", failures)
	}
	if saved != limit || refused != attempts-limit {
		t.Errorf("saved = %d, refused = %d; want %d and %d", saved, refused, limit, attempts-limit)
	}
	if n := countRows(t, app, names.Challenges); n != limit {
		t.Errorf("rows = %d, want %d", n, limit)
	}
}

func TestDeleteExpiredChallenges(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	for i := range 3 {
		c := loginChallenge(fmt.Sprintf("expired-%d", i))
		c.ExpiresAt = time.Now().Add(-time.Duration(i+1) * time.Minute)
		mustSave(t, app, c)
	}
	mustSave(t, app, loginChallenge("still-valid"))

	deleted, err := store.DeleteExpiredChallenges(app, names)
	if err != nil {
		t.Fatalf("DeleteExpiredChallenges: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}

	if _, err := store.ConsumeChallenge(app, names, "still-valid", store.ChallengeLogin, membersRef, nil); err != nil {
		t.Errorf("the valid challenge was removed: %v", err)
	}

	if deleted, err := store.DeleteExpiredChallenges(app, names); err != nil || deleted != 0 {
		t.Errorf("second run: deleted = %d, err = %v; want 0 and nil", deleted, err)
	}
}

func TestCredentialQueries(t *testing.T) {
	app := newMigratedApp(t)
	defer app.Cleanup()

	if err := app.Save(core.NewAuthCollection("partners")); err != nil {
		t.Fatalf("create second auth collection: %v", err)
	}

	alice := newMember(t, app, "alice@example.com")
	bob := newMember(t, app, "bob@example.com")
	members := alice.Collection().Id

	partners, err := app.FindCollectionByNameOrId("partners")
	if err != nil {
		t.Fatalf("find partners: %v", err)
	}

	first := newCredential(t, app, alice, "cred-alice-1")
	time.Sleep(5 * time.Millisecond) // "created" has millisecond resolution
	second := newCredential(t, app, alice, "cred-alice-2")
	newCredential(t, app, bob, "cred-bob")

	t.Run("find within the collection", func(t *testing.T) {
		got, err := store.FindCredential(app, names, members, "cred-alice-1")
		if err != nil || got.Id != first.Id {
			t.Fatalf("FindCredential = %v, %v; want alice's first credential", got, err)
		}
	})

	// Part of security invariant 4: a credential of collection A is not
	// found when looked up through collection B.
	t.Run("not found through another collection", func(t *testing.T) {
		_, err := store.FindCredential(app, names, partners.Id, "cred-alice-1")
		if !errors.Is(err, store.ErrCredentialNotFound) {
			t.Fatalf("err = %v, want ErrCredentialNotFound", err)
		}
	})

	t.Run("not found for unknown or empty input", func(t *testing.T) {
		for _, tt := range [][2]string{{members, "nope"}, {members, ""}, {"", "cred-alice-1"}} {
			if _, err := store.FindCredential(app, names, tt[0], tt[1]); !errors.Is(err, store.ErrCredentialNotFound) {
				t.Errorf("FindCredential(%q, %q): err = %v, want ErrCredentialNotFound", tt[0], tt[1], err)
			}
		}
	})

	t.Run("credential id exists in any collection", func(t *testing.T) {
		for id, want := range map[string]bool{"cred-bob": true, "cred-alice-2": true, "nope": false} {
			got, err := store.CredentialIDExists(app, names, id)
			if err != nil || got != want {
				t.Errorf("CredentialIDExists(%q) = %v, %v; want %v", id, got, err, want)
			}
		}
	})

	t.Run("list and count are per owner, oldest first", func(t *testing.T) {
		list, err := store.ListCredentials(app, names, members, alice.Id)
		if err != nil {
			t.Fatalf("ListCredentials: %v", err)
		}
		if len(list) != 2 || list[0].Id != first.Id || list[1].Id != second.Id {
			t.Errorf("list = %v, want alice's two credentials in creation order", ids(list))
		}

		for owner, want := range map[*core.Record]int{alice: 2, bob: 1} {
			n, err := store.CountCredentials(app, names, members, owner.Id)
			if err != nil || n != want {
				t.Errorf("CountCredentials(%s) = %d, %v; want %d", owner.Email(), n, err, want)
			}
		}

		// The same record ID under another collection owns nothing.
		if n, err := store.CountCredentials(app, names, partners.Id, alice.Id); err != nil || n != 0 {
			t.Errorf("CountCredentials through another collection = %d, %v; want 0", n, err)
		}

		empty, err := store.ListCredentials(app, names, members, "nobody")
		if err != nil || len(empty) != 0 {
			t.Errorf("ListCredentials for an unknown user = %v, %v; want empty", ids(empty), err)
		}
	})
}

func ids(records []*core.Record) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Id
	}

	return out
}
