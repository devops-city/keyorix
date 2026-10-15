// secret_ownership_history.go — per-secret ownership-transfer chain, derived from
// existing audit_events rows (event_type = "secret.owner_transferred"). No new DB
// table: the data already lives in the audit log written by transferOwnership.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// OwnershipRecord is one link in a secret's ownership-transfer chain.
type OwnershipRecord struct {
	EventID   uint      `json:"event_id"`
	FromID    uint      `json:"from_id"`    // previous owner user ID
	ToID      uint      `json:"to_id"`      // new owner user ID
	ChangedBy uint      `json:"changed_by"` // actor who performed the transfer (UserID on the audit row)
	ChangedAt time.Time `json:"changed_at"`
	// Description is the full human-readable audit description, preserved as-is for
	// consumers that want more context than the parsed IDs alone.
	Description string `json:"description"`
}

// ownershipDescRe is a LEGACY fallback for secret.owner_transferred rows written
// before this file started reading the structured ownershipTransferDetail out of
// the event's Diff field (see secret_ownership.go). Those older rows have no Diff
// and only carry the human-readable description:
//
//	transferred ownership of secret "NAME" from user OLD_ID to user NEW_ID
//
// Do NOT rely on this for new events: the secret NAME is attacker-controllable
// (rename) and is interpolated into that same string ahead of the numeric IDs, so
// a maliciously-named secret can forge what a leftmost regex match reports as the
// from/to owner. transferOwnership now writes FromUserID/ToUserID as structured
// JSON in Diff specifically so parsing never has to trust free text again; this
// regex only exists to keep pre-fix historical rows from silently losing their
// parsed IDs.
var ownershipDescRe = regexp.MustCompile(`from user (\d+) to user (\d+)`)

// GetSecretOwnershipHistory returns the chain of ownership transfers for secretID
// in chronological order (oldest first), derived from AuditEvent rows where
// EventType == EventSecretOwnerTransferred. The actor must be able to read the
// secret. An empty slice (not an error) is returned when no transfers have
// occurred yet.
func (c *KeyorixCore) GetSecretOwnershipHistory(ctx context.Context, secretID, actorID uint) ([]OwnershipRecord, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}

	action := EventSecretOwnerTransferred
	// Ascending = true so results are ordered oldest-first (chronological chain).
	events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		SecretID:  &secretID,
		Action:    &action,
		Ascending: true,
		Count:     storage.AuditCountNone,
		PageSize:  500,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	records := make([]OwnershipRecord, 0, len(events))
	for _, e := range events {
		rec := OwnershipRecord{
			EventID:     e.ID,
			ChangedAt:   e.EventTime,
			Description: e.Description,
		}
		if e.UserID != nil {
			rec.ChangedBy = *e.UserID
		}
		// Prefer the structured from/to IDs written to Diff (see
		// ownershipTransferDetail) — never derived from attacker-controllable text.
		var d ownershipTransferDetail
		if e.Diff != "" && json.Unmarshal([]byte(e.Diff), &d) == nil {
			rec.FromID = d.FromUserID
			rec.ToID = d.ToUserID
		} else if m := ownershipDescRe.FindStringSubmatch(e.Description); len(m) == 3 {
			// LEGACY fallback for rows written before Diff carried structured IDs.
			fromID, err1 := strconv.ParseUint(m[1], 10, 32)
			toID, err2 := strconv.ParseUint(m[2], 10, 32)
			if err1 == nil && err2 == nil {
				rec.FromID = uint(fromID)
				rec.ToID = uint(toID)
			}
		}
		records = append(records, rec)
	}
	return records, nil
}
