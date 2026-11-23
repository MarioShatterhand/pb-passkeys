package passkeys

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/pocketbase/pocketbase/core"

	"github.com/MarioShatterhand/pb-passkeys/internal/ceremony"
	"github.com/MarioShatterhand/pb-passkeys/internal/store"
)

// fillCredentialRecord writes a verified credential into a record of the
// credentials collection.
func fillCredentialRecord(record *core.Record, owner *core.Record, c *ceremony.Credential, name string) {
	record.Set(store.FieldCollectionRef, owner.Collection().Id)
	record.Set(store.FieldRecordRef, owner.Id)
	record.Set(store.FieldCredentialID, encodeBytes(c.ID))
	record.Set(store.FieldPublicKey, encodeBytes(c.PublicKey))
	record.Set(store.FieldSignCount, int64(c.SignCount))
	record.Set(store.FieldAAGUID, formatAAGUID(c.AAGUID))
	record.Set(store.FieldTransports, c.Transports)
	record.Set(store.FieldAuthenticatorAttachment, c.Attachment)
	record.Set(store.FieldBackupEligible, c.BackupEligible)
	record.Set(store.FieldBackupState, c.BackupState)
	record.Set(store.FieldAttestationFormat, c.AttestationFormat)
	record.Set(store.FieldName, name)
}

// credentialFromRecord reads a record of the credentials collection back into
// the form the ceremonies need.
func credentialFromRecord(record *core.Record) (ceremony.Credential, error) {
	id, err := decodeBytes(record.GetString(store.FieldCredentialID))
	if err != nil {
		return ceremony.Credential{}, fmt.Errorf("credential %s: stored credential id: %w", record.Id, err)
	}

	publicKey, err := decodeBytes(record.GetString(store.FieldPublicKey))
	if err != nil {
		return ceremony.Credential{}, fmt.Errorf("credential %s: stored public key: %w", record.Id, err)
	}

	var transports []string
	if err := record.UnmarshalJSONField(store.FieldTransports, &transports); err != nil {
		transports = nil // hints only; a broken value must not block a login
	}

	return ceremony.Credential{
		ID:                id,
		PublicKey:         publicKey,
		SignCount:         signCountFromInt(record.GetInt64(store.FieldSignCount)),
		AAGUID:            parseAAGUID(record.GetString(store.FieldAAGUID)),
		Transports:        transports,
		Attachment:        record.GetString(store.FieldAuthenticatorAttachment),
		BackupEligible:    record.GetBool(store.FieldBackupEligible),
		BackupState:       record.GetBool(store.FieldBackupState),
		AttestationFormat: record.GetString(store.FieldAttestationFormat),
	}, nil
}

// credentialsFromRecords converts all records, failing on the first broken one.
func credentialsFromRecords(records []*core.Record) ([]ceremony.Credential, error) {
	out := make([]ceremony.Credential, 0, len(records))

	for _, record := range records {
		c, err := credentialFromRecord(record)
		if err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	return out, nil
}

// signCountFromInt converts a stored counter to the 32-bit value WebAuthn
// uses. The field only ever holds values written from a uint32; anything
// outside that range is clamped rather than wrapped.
func signCountFromInt(n int64) uint32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxUint32:
		return math.MaxUint32
	default:
		return uint32(n)
	}
}

func encodeBytes(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeBytes(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// formatAAGUID renders a 16-byte AAGUID in the usual 8-4-4-4-12 form. Any
// other length gives an empty string.
func formatAAGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}

	h := hex.EncodeToString(b)

	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// parseAAGUID is the inverse of formatAAGUID. It returns nil for anything
// that is not a well-formed AAGUID.
func parseAAGUID(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return nil
	}

	return b
}
