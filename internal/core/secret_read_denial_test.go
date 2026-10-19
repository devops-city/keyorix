package core

// secret_read_denial_test.go -- #3273: a refused native secret-value read is
// audited as secret.read with Success=false, at both insecure_audit_skip_reads
// settings, through an aggregator that bounds the rows a burst can write. The
// per-path, per-reason tests against the real router and gRPC server are in
// server/http/secret_value_read_denial_audit_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func refusedReadRows(t *testing.T, db *gorm.DB) []models.AuditEvent {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, db.Where("event_type = ? AND success = ?", "secret.read", false).Order("id").Find(&rows).Error)
	return rows
}

func refusedReadDiff(t *testing.T, row models.AuditEvent) secretReadDenialDiff {
	t.Helper()
	var d secretReadDenialDiff
	require.NoError(t, json.Unmarshal([]byte(row.Diff), &d), "diff: %s", row.Diff)
	return d
}

func testDenial(userID uint, reason SecretReadDenialReason, secretID uint) secretReadDenial {
	return secretReadDenial{
		path: SecretReadPathRESTGet, reason: reason,
		actor:  SecretReadDenialActor{UserID: userID, Username: fmt.Sprintf("user%d", userID), IP: "10.0.0.9"},
		target: SecretReadDenialTarget{SecretID: secretID},
	}
}

// A refused read is written at both settings: insecure_audit_skip_reads only
// drops SUCCESSFUL value reads.
func TestSecretReadDenial_WrittenAtBothSkipReadsSettings(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("insecure_audit_skip_reads=%v", skip), func(t *testing.T) {
			c, _, db := newAuditSkipReadsWorld(t, skip)
			c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedExpired, 7))
			rows := refusedReadRows(t, db)
			require.Len(t, rows, 1)
			assert.Contains(t, rows[0].Description, "reason=expired")
			assert.Contains(t, rows[0].Description, "outcome=denied")
			require.NotNil(t, rows[0].UserID)
			assert.EqualValues(t, 1, *rows[0].UserID)
			d := refusedReadDiff(t, rows[0])
			assert.Equal(t, "expired", d.Reason)
			assert.Equal(t, 1, d.Count)
			assert.False(t, d.Aggregated)
		})
	}
}

// N refusals of one key in a window: the first is written at once, the rest
// cost no write until the window closes, then exactly one summary row carries
// the count. Total rows for the window: 2, and the counts add up to N.
func TestSecretReadDenial_BurstIsAggregatedFirstImmediateCountCorrect(t *testing.T) {
	c, counting, db := newAuditSkipReadsWorld(t, false)
	c.secretReadDenialAgg = newDenialAggregator(time.Hour, secretReadDenialPrincipalKeys, secretReadDenialMaxKeys, nil)
	const n = 500

	c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedForbidden, 42))
	require.Len(t, refusedReadRows(t, db), 1, "the first refusal of a window must be written immediately")
	for range n - 1 {
		c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedForbidden, 42))
	}
	assert.Len(t, refusedReadRows(t, db), 1, "refusals 2..N of the window must not each write a row")
	assert.EqualValues(t, 1, counting.logAuditEvent.Load(), "one audit write for the whole burst so far")

	c.FlushSecretReadDenials()
	rows := refusedReadRows(t, db)
	require.Len(t, rows, 2, "one immediate row + one summary row per window")
	first, summary := refusedReadDiff(t, rows[0]), refusedReadDiff(t, rows[1])
	assert.Equal(t, 1, first.Count)
	assert.True(t, summary.Aggregated)
	assert.Equal(t, n-1, summary.Count)
	assert.Equal(t, n, first.Count+summary.Count, "the rows must account for every refusal")
	assert.NotEmpty(t, summary.WindowStart)
	assert.Contains(t, rows[1].Description, fmt.Sprintf("(%d further refusals aggregated", n-1))

	// The next refusal opens a new window: written immediately again.
	c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedForbidden, 42))
	assert.Len(t, refusedReadRows(t, db), 3)
}

// The window closes on its own (a timer), so a burst that simply stops still
// gets its summary row.
func TestSecretReadDenial_WindowTimerWritesSummary(t *testing.T) {
	c, _, db := newAuditSkipReadsWorld(t, false)
	c.secretReadDenialAgg = newDenialAggregator(50*time.Millisecond, secretReadDenialPrincipalKeys, secretReadDenialMaxKeys, nil)
	for range 10 {
		c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedNotFound, 9))
	}
	require.Eventually(t, func() bool { return len(refusedReadRows(t, db)) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 9, refusedReadDiff(t, refusedReadRows(t, db)[1]).Count)
}

// Different keys are separate: another principal, another reason or another
// target each get their own first row.
func TestSecretReadDenial_KeyIsPrincipalReasonTarget(t *testing.T) {
	c, _, db := newAuditSkipReadsWorld(t, false)
	c.secretReadDenialAgg = newDenialAggregator(time.Hour, secretReadDenialPrincipalKeys, secretReadDenialMaxKeys, nil)
	c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedForbidden, 1))
	c.recordSecretReadDenial(context.Background(), testDenial(2, SecretReadDeniedForbidden, 1))
	c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedNotFound, 1))
	c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedForbidden, 2))
	c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedForbidden, 1))
	assert.Len(t, refusedReadRows(t, db), 4)
}

// A flood that varies the target is bounded per principal: past
// secretReadDenialPrincipalKeys live keys, further targets fold into one
// overflow key. Rows stay bounded and the counts still add up.
func TestSecretReadDenial_DistinctTargetFloodIsBoundedPerPrincipal(t *testing.T) {
	c, _, db := newAuditSkipReadsWorld(t, false)
	const cap, n = 5, 300
	c.secretReadDenialAgg = newDenialAggregator(time.Hour, cap, secretReadDenialMaxKeys, nil)
	for i := range n {
		c.recordSecretReadDenial(context.Background(), testDenial(1, SecretReadDeniedForbidden, uint(1000+i)))
	}
	assert.Len(t, refusedReadRows(t, db), cap+1, "cap first rows + one overflow first row")
	c.FlushSecretReadDenials()
	rows := refusedReadRows(t, db)
	assert.Len(t, rows, cap+2, "plus one overflow summary")
	total := 0
	for _, r := range rows {
		total += refusedReadDiff(t, r).Count
	}
	assert.Equal(t, n, total)
	assert.Equal(t, secretReadDenialOverflowShard, refusedReadDiff(t, rows[cap]).Target)
	assert.Equal(t, secretReadDenialOverflowShard, refusedReadDiff(t, rows[cap+1]).Target, "the overflow summary names the overflow key")

	// Another principal is not affected by the first one's cap.
	c.recordSecretReadDenial(context.Background(), testDenial(2, SecretReadDeniedForbidden, 1000))
	assert.Len(t, refusedReadRows(t, db), cap+3)
}

// The aggregator as a whole is bounded too: past maxKeys, new keys fold into
// their principal's overflow key.
func TestSecretReadDenial_GlobalKeyCap(t *testing.T) {
	c, _, db := newAuditSkipReadsWorld(t, false)
	c.secretReadDenialAgg = newDenialAggregator(time.Hour, 100, 3, nil)
	for i := range 3 {
		c.recordSecretReadDenial(context.Background(), testDenial(uint(i+1), SecretReadDeniedForbidden, 1))
	}
	for range 20 {
		c.recordSecretReadDenial(context.Background(), testDenial(9, SecretReadDeniedForbidden, 1))
	}
	assert.Len(t, refusedReadRows(t, db), 4)
	assert.LessOrEqual(t, len(c.secretReadDenialAgg.buckets), 4)
}

// failingAuditStorage fails every audit write.
func failingAuditStorage(counting *auditCallCountingStorage) storage.Storage {
	return hooked(counting.store(), &storeHooks{
		LogAuditEvent: func(storage.Storage, context.Context, *models.AuditEvent) error {
			return errors.New("audit store unavailable")
		},
	})
}

// A refusal stays a refusal when its audit row cannot be written: the write is
// best-effort and logged, never a reason to answer differently, and never a
// panic. Exercised through CopySecret, which records in core.
func TestSecretReadDenial_AuditWriteFailureKeepsTheRefusal(t *testing.T) {
	_, counting, db := newAuditSkipReadsWorld(t, false)
	c := NewKeyorixCore(failingAuditStorage(counting))
	_, err := c.CopySecret(context.Background(), 4242, 1, "", "mallory", 3, "10.0.0.1", "ua")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found", "the refusal must be the same answer as without auditing")
	assert.Empty(t, refusedReadRows(t, db))
	assert.NotPanics(t, func() {
		c.recordSecretReadDenial(context.Background(), testDenial(3, SecretReadDeniedForbidden, 4242))
	})
}

// A forbidden and a not_found row look the same on every column a caller can
// see (their own dashboard activity reads UserID-filtered rows; a project view
// filters on ProjectID): no SecretNodeID, no ProjectID, the same activity type
// and label, no secret name. Only reason= and Diff (audit.read) tell them apart.
func TestSecretReadDenial_ForbiddenAndNotFoundRowsAreNotAnOracle(t *testing.T) {
	c, _, db := newAuditSkipReadsWorld(t, false)
	forbidden := testDenial(5, SecretReadDeniedForbidden, 77)
	forbidden.subjectID, forbidden.projectID = 77, 3 // the internal truth: it exists, in project 3
	c.recordSecretReadDenial(context.Background(), forbidden)
	c.recordSecretReadDenial(context.Background(), testDenial(5, SecretReadDeniedNotFound, 78))
	rows := refusedReadRows(t, db)
	require.Len(t, rows, 2)
	for _, r := range rows {
		assert.Nil(t, r.SecretNodeID, "a refusal before authorization must not name the secret on a column")
		assert.Nil(t, r.ProjectID, "a refusal before authorization must not name the project on a column")
	}
	a, b := mapAuditEventToActivity(&rows[0], "u"), mapAuditEventToActivity(&rows[1], "u")
	assert.Equal(t, a.Type, b.Type)
	assert.Equal(t, a.Label, b.Label)
	assert.Empty(t, a.SecretName)
	assert.Empty(t, b.SecretName)
	assert.Equal(t, activityTypeReadRefused, a.Type, "a refusal must not show as \"accessed\"")
	assert.Equal(t, uint(77), refusedReadDiff(t, rows[0]).SecretID, "audit.read holders still see the truth")
	assert.Contains(t, rows[0].Description, "reason=forbidden")
	assert.Contains(t, rows[1].Description, "reason=not_found")

	// A refusal past authorization (the caller was shown to have read access)
	// does name the secret.
	c.recordSecretReadDenial(context.Background(), testDenial(5, SecretReadDeniedSuspended, 77))
	rows = refusedReadRows(t, db)
	require.Len(t, rows, 3)
	require.NotNil(t, rows[2].SecretNodeID)
	assert.EqualValues(t, 77, *rows[2].SecretNodeID)
}

// Every error a value read can return maps onto a reason class.
func TestClassifySecretReadDenial(t *testing.T) {
	for sentinel, refusal := range SecretReadRefusalFamily() {
		got := ClassifySecretReadDenial(fmt.Errorf("wrapped: %w", sentinel))
		assert.NotEqual(t, SecretReadDeniedInternalError, got, "%s", refusal.Code)
		assert.False(t, got.IsBeforeAuthorization(), "%s is a refusal past authorization", refusal.Code)
	}
	cases := map[string]SecretReadDenialReason{
		"secret \"x\" is restricted: a recent MFA verification is required": SecretReadDeniedClassificationGate,
		"permission denied: insufficient permissions":                       SecretReadDeniedForbidden,
		"Secret not found: record not found":                                SecretReadDeniedNotFound,
		"decrypt: cipher: message authentication failed":                    SecretReadDeniedInternalError,
	}
	for msg, want := range cases {
		assert.Equal(t, want, ClassifySecretReadDenial(errors.New(msg)), msg)
	}
	assert.Equal(t, SecretReadDeniedNotFound, ClassifySecretReadDenial(ErrSecretRefNotFound))
	assert.Len(t, SecretReadDenialReasons(), 9)
}

// The value-read entry points note their refusal on the request's note, and do
// nothing at all without one or on success.
func TestSecretReadDenial_ValueReadEntryPointsNoteTheirRefusal(t *testing.T) {
	c, _, _ := newAuditSkipReadsWorld(t, false)
	ctx, note := WithSecretReadDenialNote(context.Background(), SecretReadPathRESTGet)
	_, err := c.GetSecretValue(ctx, 999)
	require.Error(t, err)
	assert.Equal(t, SecretReadDeniedNotFound, note.Reason())

	_, err = c.GetSecretValue(context.Background(), 999) // no note: must not panic
	require.Error(t, err)
}

// Render resolves references inside core, so it records its own refusals: a
// reference to a missing secret and one to a forbidden secret (the same text,
// #181) each leave a row with its reason and no column naming the secret; a
// refusal past authorization names it; the response is unchanged.
func TestSecretReadDenial_RenderRefusalsAudited(t *testing.T) {
	ctx := context.Background()
	c, db, projectID, secretID := newRenderFixture(t)
	const ref = "${secret:production/db-password}"

	_, forbiddenErr := c.RenderSecretTemplate(ctx, ref, projectID, 2, "viewer", "10.0.0.1", "ua")
	require.ErrorIs(t, forbiddenErr, ErrSecretRefNotFound)
	_, unknownEnvErr := c.RenderSecretTemplate(ctx, "${secret:staging/db-password}", projectID, 2, "viewer", "10.0.0.1", "ua")
	require.ErrorIs(t, unknownEnvErr, ErrSecretRefNotFound)

	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", secretID).Update("status", SecretStatusSuspended).Error)
	_, err := c.RenderSecretTemplate(ctx, ref, projectID, 1, "owner", "10.0.0.1", "ua")
	require.ErrorIs(t, err, ErrSecretSuspended)

	rows := refusedReadRows(t, db)
	require.Len(t, rows, 3)
	want := []SecretReadDenialReason{SecretReadDeniedForbidden, SecretReadDeniedNotFound, SecretReadDeniedSuspended}
	for i, r := range rows {
		d := refusedReadDiff(t, r)
		assert.Equal(t, string(want[i]), d.Reason, r.Description)
		assert.Equal(t, secretReadPathRender, d.Path)
	}
	assert.Nil(t, rows[0].SecretNodeID)
	assert.Nil(t, rows[0].ProjectID)
	assert.Equal(t, secretID, refusedReadDiff(t, rows[0]).SecretID, "the internal truth is kept in Diff")
	assert.Nil(t, rows[1].SecretNodeID)
	require.NotNil(t, rows[2].SecretNodeID)
	assert.Equal(t, secretID, *rows[2].SecretNodeID)
}

// A render whose max-reads budget runs out at commit records that refusal.
func TestSecretReadDenial_RenderMaxReadsAtCommitAudited(t *testing.T) {
	ctx := context.Background()
	c, db, projectID, secretID := newRenderFixture(t)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", secretID).Updates(map[string]any{"max_reads": 1, "read_count": 1}).Error)
	_, err := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
	require.ErrorIs(t, err, ErrSecretMaxReadsExhausted)
	rows := refusedReadRows(t, db)
	require.Len(t, rows, 1)
	assert.Equal(t, string(SecretReadDeniedMaxReadsExhausted), refusedReadDiff(t, rows[0]).Reason)
}
