package passkeys

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pocketbase/pocketbase/core"

	"github.com/MarioShatterhand/pb-passkeys/internal/store"
	"github.com/MarioShatterhand/pb-passkeys/internal/testauthn"
)

const credentialsAPI = "/api/collections/passkey_credentials/records/"

// send issues a request with an optional JSON body.
func (s *testServer) send(method, path, token, body string) (int, []byte) {
	s.t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)

	return rec.Code, rec.Body.Bytes()
}

func (s *testServer) superuserToken() string {
	s.t.Helper()

	superuser, err := s.app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		s.t.Fatalf("find superuser: %v", err)
	}

	token, err := superuser.NewAuthToken()
	if err != nil {
		s.t.Fatalf("superuser token: %v", err)
	}

	return token
}

// credentialIDs returns the record IDs of a user's passkeys, oldest first.
func (s *testServer) credentialIDs(owner *core.Record) []string {
	s.t.Helper()

	records, err := s.module.ListCredentials(owner)
	if err != nil {
		s.t.Fatalf("ListCredentials: %v", err)
	}

	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Id
	}

	return out
}

// snapshot returns the stored fields of a credential as JSON, hidden ones included.
func (s *testServer) snapshot(id string) string {
	s.t.Helper()

	record, err := s.app.FindRecordById(DefaultCredentialsCollection, id)
	if err != nil {
		s.t.Fatalf("find credential %s: %v", id, err)
	}

	data := record.FieldsData()
	delete(data, store.FieldUpdated)

	raw, err := json.Marshal(data)
	if err != nil {
		s.t.Fatalf("encode credential: %v", err)
	}

	return string(raw)
}

func TestRenameCredential(t *testing.T) {
	s := newTestServer(t, nil)
	alice, aliceToken := s.newRecord("members", "alice@example.com")
	_, bobToken := s.newRecord("members", "bob@example.com")
	s.register(testauthn.New(), aliceToken, "Phone")
	id := s.credentialIDs(alice)[0]

	t.Run("owner renames", func(t *testing.T) {
		status, body := s.send(http.MethodPatch, credentialsAPI+id, aliceToken, `{"name":"Work phone"}`)
		if status != http.StatusOK || !strings.Contains(string(body), `"name":"Work phone"`) {
			t.Fatalf("status %d, body %s; want 200 with the new name", status, body)
		}
	})

	t.Run("name longer than 64 characters refused", func(t *testing.T) {
		status, body := s.send(http.MethodPatch, credentialsAPI+id, aliceToken, `{"name":"`+strings.Repeat("x", 65)+`"}`)
		if status != http.StatusBadRequest {
			t.Errorf("status %d, body %s; want 400", status, body)
		}
	})

	t.Run("another user cannot rename", func(t *testing.T) {
		status, body := s.send(http.MethodPatch, credentialsAPI+id, bobToken, `{"name":"Mine now"}`)
		if status != http.StatusNotFound {
			t.Errorf("status %d, body %s; want 404", status, body)
		}
	})

	t.Run("guest cannot rename", func(t *testing.T) {
		status, body := s.send(http.MethodPatch, credentialsAPI+id, "", `{"name":"Anyone"}`)
		if status != http.StatusNotFound {
			t.Errorf("status %d, body %s; want 404", status, body)
		}
	})

	record, err := s.app.FindRecordById(DefaultCredentialsCollection, id)
	if err != nil || record.GetString(store.FieldName) != "Work phone" {
		t.Errorf("stored name = %q, %v; want the owner's rename only", record.GetString(store.FieldName), err)
	}
}

// Security invariant 12: through the API a user can change only the name of
// a credential, never the key material or its owner.
func TestCredentialFieldsCannotBeChangedThroughAPI(t *testing.T) {
	s := newTestServer(t, nil)
	alice, aliceToken := s.newRecord("members", "alice@example.com")
	bob, _ := s.newRecord("members", "bob@example.com")
	s.register(testauthn.New(), aliceToken, "Phone")
	id := s.credentialIDs(alice)[0]

	before := s.snapshot(id)

	bodies := map[string]string{
		"publicKey":               `{"publicKey":"YXR0YWNrZXIta2V5"}`,
		"recordRef":               `{"recordRef":"` + bob.Id + `"}`,
		"collectionRef":           `{"collectionRef":"other"}`,
		"credentialId":            `{"credentialId":"Zm9yZ2Vk"}`,
		"signCount":               `{"signCount":0}`,
		"backupEligible":          `{"backupEligible":true}`,
		"backupState":             `{"backupState":true}`,
		"aaguid":                  `{"aaguid":"11111111-1111-1111-1111-111111111111"}`,
		"transports":              `{"transports":["usb"]}`,
		"authenticatorAttachment": `{"authenticatorAttachment":"cross-platform"}`,
		"attestationFormat":       `{"attestationFormat":"packed"}`,
		"lastUsedAt":              `{"lastUsedAt":"2030-01-01 00:00:00.000Z"}`,
		"name with publicKey":     `{"name":"Renamed","publicKey":"YXR0YWNrZXIta2V5"}`,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			status, response := s.send(http.MethodPatch, credentialsAPI+id, aliceToken, body)
			if status != http.StatusForbidden || !strings.Contains(string(response), msgOnlyNameEditable) {
				t.Errorf("status %d, body %s; want 403 %q", status, response, msgOnlyNameEditable)
			}

			if after := s.snapshot(id); after != before {
				t.Errorf("the stored credential changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// Security invariant 13: a user cannot delete their last passkey.
func TestDeleteCredential(t *testing.T) {
	t.Run("last passkey refused, one of two allowed", func(t *testing.T) {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")
		s.register(testauthn.New(), token, "Phone")
		s.register(testauthn.New(), token, "Laptop")
		ids := s.credentialIDs(alice)

		if status, body := s.send(http.MethodDelete, credentialsAPI+ids[0], token, ""); status != http.StatusNoContent {
			t.Fatalf("delete one of two: status %d, body %s; want 204", status, body)
		}

		status, body := s.send(http.MethodDelete, credentialsAPI+ids[1], token, "")
		if status != http.StatusBadRequest || !strings.Contains(string(body), msgLastCredential) {
			t.Errorf("delete the last: status %d, body %s; want 400 %q", status, body, msgLastCredential)
		}

		if left := s.credentialIDs(alice); len(left) != 1 || left[0] != ids[1] {
			t.Errorf("remaining credentials = %v, want only %s", left, ids[1])
		}
	})

	t.Run("last passkey allowed when configured", func(t *testing.T) {
		s := newTestServer(t, func(c *Config) { c.AllowDeleteLastCredential = true })
		alice, token := s.newRecord("members", "alice@example.com")
		s.register(testauthn.New(), token, "Phone")

		if status, body := s.send(http.MethodDelete, credentialsAPI+s.credentialIDs(alice)[0], token, ""); status != http.StatusNoContent {
			t.Errorf("status %d, body %s; want 204", status, body)
		}
		if left := s.credentialIDs(alice); len(left) != 0 {
			t.Errorf("remaining credentials = %v, want none", left)
		}
	})

	t.Run("superuser may delete the last passkey", func(t *testing.T) {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")
		s.register(testauthn.New(), token, "Phone")

		if status, body := s.send(http.MethodDelete, credentialsAPI+s.credentialIDs(alice)[0], s.superuserToken(), ""); status != http.StatusNoContent {
			t.Errorf("status %d, body %s; want 204", status, body)
		}
	})

	t.Run("another user's passkey does not count", func(t *testing.T) {
		s := newTestServer(t, nil)
		alice, aliceToken := s.newRecord("members", "alice@example.com")
		_, bobToken := s.newRecord("members", "bob@example.com")
		s.register(testauthn.New(), aliceToken, "Phone")
		s.register(testauthn.New(), bobToken, "Phone")

		// Two credentials exist in total, but alice has only one.
		status, body := s.send(http.MethodDelete, credentialsAPI+s.credentialIDs(alice)[0], aliceToken, "")
		if status != http.StatusBadRequest {
			t.Errorf("status %d, body %s; want 400", status, body)
		}
	})
}

// Security invariant 13, concurrent form: two requests that each delete one
// of the last two passkeys cannot both succeed.
func TestDeleteLastTwoCredentialsConcurrently(t *testing.T) {
	for round := range 5 {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")
		s.register(testauthn.New(), token, "Phone")
		s.register(testauthn.New(), token, "Laptop")
		ids := s.credentialIDs(alice)

		var (
			wg       sync.WaitGroup
			statuses [2]int
		)

		start := make(chan struct{})

		for i, id := range ids {
			wg.Add(1)

			go func() {
				defer wg.Done()
				<-start

				req := httptest.NewRequest(http.MethodDelete, credentialsAPI+id, bytes.NewReader(nil))
				req.Header.Set("Authorization", token)

				rec := httptest.NewRecorder()
				s.handler.ServeHTTP(rec, req)
				statuses[i] = rec.Code
			}()
		}

		close(start)
		wg.Wait()

		deleted, refused := 0, 0
		for _, status := range statuses {
			switch status {
			case http.StatusNoContent:
				deleted++
			case http.StatusBadRequest:
				refused++
			}
		}

		if deleted != 1 || refused != 1 {
			t.Fatalf("round %d: statuses = %v, want one 204 and one 400", round, statuses)
		}
		if left := s.credentialIDs(alice); len(left) != 1 {
			t.Fatalf("round %d: remaining credentials = %v, want exactly one", round, left)
		}
	}
}

func TestCredentialDeletedHook(t *testing.T) {
	t.Run("runs with the owner and the deleted credential", func(t *testing.T) {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")
		s.register(testauthn.New(), token, "Phone")
		s.register(testauthn.New(), token, "Laptop")
		id := s.credentialIDs(alice)[0]

		var got *CredentialDeletedEvent

		s.module.OnCredentialDeleted().BindFunc(func(e *CredentialDeletedEvent) error {
			got = e
			return e.Next()
		})

		if status, body := s.send(http.MethodDelete, credentialsAPI+id, token, ""); status != http.StatusNoContent {
			t.Fatalf("status %d, body %s", status, body)
		}
		if got == nil || got.Record == nil || got.Record.Id != alice.Id || got.Credential.Id != id || got.Request == nil || got.App == nil {
			t.Errorf("event = %+v, want alice, the deleted credential, the request and the transaction", got)
		}
	})

	t.Run("an error keeps the credential", func(t *testing.T) {
		s := newTestServer(t, nil)
		alice, token := s.newRecord("members", "alice@example.com")
		s.register(testauthn.New(), token, "Phone")
		s.register(testauthn.New(), token, "Laptop")
		id := s.credentialIDs(alice)[0]

		s.module.OnCredentialDeleted().BindFunc(func(*CredentialDeletedEvent) error {
			return errors.New("notification service unavailable")
		})

		status, body := s.send(http.MethodDelete, credentialsAPI+id, token, "")
		if status == http.StatusNoContent {
			t.Errorf("status %d, body %s; want an error", status, body)
		}
		if strings.Contains(string(body), "notification service") {
			t.Errorf("the response reveals the hook's error: %s", body)
		}
		if left := s.credentialIDs(alice); len(left) != 2 {
			t.Errorf("remaining credentials = %v, want both", left)
		}
	})
}

func TestCredentialsAreDeletedWithTheirOwner(t *testing.T) {
	s := newTestServer(t, nil)
	alice, aliceToken := s.newRecord("members", "alice@example.com")
	bob, bobToken := s.newRecord("members", "bob@example.com")
	s.register(testauthn.New(), aliceToken, "Phone")
	s.register(testauthn.New(), aliceToken, "Laptop")
	s.register(testauthn.New(), bobToken, "Phone")

	var hookRuns int

	s.module.OnCredentialDeleted().BindFunc(func(e *CredentialDeletedEvent) error {
		hookRuns++
		return e.Next()
	})

	if err := s.app.Delete(alice); err != nil {
		t.Fatalf("delete alice: %v", err)
	}

	if n := s.count(DefaultCredentialsCollection); n != 1 {
		t.Errorf("credentials = %d, want only bob's", n)
	}
	if left := s.credentialIDs(bob); len(left) != 1 {
		t.Errorf("bob's credentials = %v, want 1", left)
	}
	if hookRuns != 0 {
		t.Errorf("OnCredentialDeleted ran %d times for a cascade, want 0", hookRuns)
	}

	// Records of collections without passkeys are deleted as before.
	carol, _ := s.newRecord("partners", "carol@example.com")
	if err := s.app.Delete(carol); err != nil {
		t.Errorf("delete a record of a collection without passkeys: %v", err)
	}
}

func TestCredentialKind(t *testing.T) {
	s := newTestServer(t, nil)

	collection, err := s.app.FindCollectionByNameOrId(DefaultCredentialsCollection)
	if err != nil {
		t.Fatalf("find credentials collection: %v", err)
	}

	tests := []struct {
		name       string
		eligible   bool
		attachment string
		transports []string
		want       Kind
	}{
		{"synced passkey", true, "platform", []string{"internal", "hybrid"}, KindSynced},
		{"synced wins over cross-platform", true, "cross-platform", []string{"hybrid"}, KindSynced},
		{"platform authenticator", false, "platform", []string{"internal"}, KindDevice},
		{"internal transport without attachment", false, "", []string{"internal"}, KindDevice},
		{"security key by attachment", false, "cross-platform", []string{"usb"}, KindSecurityKey},
		{"security key by transport", false, "", []string{"nfc", "usb"}, KindSecurityKey},
		{"bluetooth key", false, "", []string{"ble"}, KindSecurityKey},
		{"usb and internal without attachment", false, "", []string{"usb", "internal"}, KindDevice},
		{"hybrid only", false, "", []string{"hybrid"}, KindUnknown},
		{"nothing reported", false, "", nil, KindUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := core.NewRecord(collection)
			record.Set(store.FieldBackupEligible, tt.eligible)
			record.Set(store.FieldAuthenticatorAttachment, tt.attachment)
			record.Set(store.FieldTransports, tt.transports)

			if got := CredentialKind(record); got != tt.want {
				t.Errorf("CredentialKind = %q, want %q", got, tt.want)
			}
		})
	}

	if got := CredentialKind(nil); got != KindUnknown {
		t.Errorf("CredentialKind(nil) = %q, want unknown", got)
	}

	// A credential registered through the routes is classified from what was stored.
	alice, token := s.newRecord("members", "alice@example.com")
	s.register(testauthn.New(), token, "Phone")

	records, err := s.module.ListCredentials(alice)
	if err != nil || len(records) != 1 {
		t.Fatalf("ListCredentials = %d, %v; want 1", len(records), err)
	}
	if got := CredentialKind(records[0]); got != KindDevice {
		t.Errorf("kind of a platform passkey = %q, want device", got)
	}
}
