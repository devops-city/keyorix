package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3363 (AUTH-2 item 5): a failed second factor is stored with Success=false,
// so success=false queries, SIEM rules and exports see it. The family-wide
// source guard is TestFailureNamedAuditEvents_AreWrittenWithSuccessFalse; these
// pin the stored value through the real write path.

func auditSuccessValues(t *testing.T, db *gorm.DB, eventType string) []bool {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", eventType).Find(&rows).Error)
	out := make([]bool, 0, len(rows))
	for _, r := range rows {
		require.NotNil(t, r.Success, "%s stored with a NULL success", eventType)
		out = append(out, *r.Success)
	}
	return out
}

func TestMFAFailed_IsStoredWithSuccessFalse(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	activateMFAForTest(t, c, fixed)
	require.Error(t, c.DisableMFA(context.Background(), 1, "000000", ""))
	assert.Equal(t, []bool{false}, auditSuccessValues(t, db, "mfa.failed"))
}

func TestMFAError_IsStoredWithSuccessFalse(t *testing.T) {
	t.Parallel()
	c, db, _ := newMFATestCore(t)
	// TOTP enrolled but no secret stored: the code cannot be evaluated (mfa.error).
	u := &models.User{ID: 1, Username: "alice", MFAEnabled: true}
	require.ErrorIs(t, c.requireReauth(context.Background(), u, "000000", "disable"), ErrMFAVerificationStorageFailure)
	assert.Equal(t, []bool{false}, auditSuccessValues(t, db, "mfa.error"))
}

func TestWebAuthnFailed_IsStoredWithSuccessFalse(t *testing.T) {
	t.Parallel()
	c, db, _ := newMFATestCore(t)
	c.auditWebAuthnFailed(context.Background(), 1, "login")
	assert.Equal(t, []bool{false}, auditSuccessValues(t, db, "webauthn.failed"))
}

// writeAuditEventFailedFull keeps every field writeAuditEventFull writes; only
// Success differs.
func TestWriteAuditEventFailedFull_KeepsTheFields(t *testing.T) {
	t.Parallel()
	c, db, _ := newMFATestCore(t)
	uid, sid, pid := uint(1), uint(7), uint(3)
	require.True(t, c.writeAuditEventFailedFull(context.Background(), "secret.rotate_failed", &uid, &sid, &pid, "198.51.100.4", "rotation failed"))
	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "secret.rotate_failed").First(&ev).Error)
	require.NotNil(t, ev.Success)
	assert.False(t, *ev.Success)
	assert.EqualValues(t, 1, *ev.UserID)
	assert.EqualValues(t, 7, *ev.SecretNodeID)
	assert.EqualValues(t, 3, *ev.ProjectID)
	assert.Equal(t, "198.51.100.4", ev.IPAddress)
}
