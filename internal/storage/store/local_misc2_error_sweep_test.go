// local_misc2_error_sweep_test.go — DB-error and small-logic-branch sweep for
// local_alert_escalation.go, local_access_activity.go, local_webauthn.go, and
// local_version_comments.go.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAlertEscalationPolicy_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetAlertEscalationPolicy(context.Background(), 1)
	require.Error(t, err)
}

func TestListAlertEscalationPolicies_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListAlertEscalationPolicies(context.Background())
	require.Error(t, err)
}

func TestUpdateAlertEscalationPolicy_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.UpdateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{ID: 1})
	require.Error(t, err)
}

func TestDeleteAlertEscalationPolicy_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.DeleteAlertEscalationPolicy(context.Background(), 1)
	require.Error(t, err)
}

func TestListUnacknowledgedAnomalyAlertsBefore_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListUnacknowledgedAnomalyAlertsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestLastUserSecretActivity_SkipsRealZeroUserID(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})
	ctx := context.Background()
	pid := uint(7)
	uid := uint(3)
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", ProjectID: &pid, UserID: &uid, EventTime: time.Now(),
	}).Error)
	// A REAL stored user_id=0 (not NULL) still passes "user_id IS NOT NULL",
	// unlike a nil *uint field (which never reaches the query result at all).
	require.NoError(t, ls.db.Exec("UPDATE audit_events SET user_id = 0 WHERE user_id = ?", uid).Error)

	m, err := ls.LastUserSecretActivity(ctx, pid, time.Time{})
	require.NoError(t, err)
	assert.NotContains(t, m, uint(0))
	assert.Empty(t, m)
}

func TestAdvanceWebAuthnCredentialCounter_UnmarshalFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.WebAuthnCredential{})
	require.NoError(t, ls.db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: []byte("cred-1"), CredentialBlob: []byte("not-json"),
	}).Error)

	_, err := ls.AdvanceWebAuthnCredentialCounter(context.Background(), []byte("cred-1"), 1, []byte(`{"authenticator":{"signCount":5}}`), 5, time.Now())
	require.Error(t, err)
}

func TestAdvanceWebAuthnCredentialCounter_UpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.WebAuthnCredential{})
	require.NoError(t, ls.db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: []byte("cred-2"), CredentialBlob: []byte(`{"authenticator":{"signCount":1}}`),
	}).Error)

	dropTableAfterQueries(t, ls.db, 1, "web_authn_credentials")

	_, err := ls.AdvanceWebAuthnCredentialCounter(context.Background(), []byte("cred-2"), 1, []byte(`{"authenticator":{"signCount":5}}`), 5, time.Now())
	require.Error(t, err)
}

func TestConsumeWebAuthnSession_LoadFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.WebAuthnSession{})
	require.NoError(t, ls.db.Create(&models.WebAuthnSession{
		UserID: 1, TokenHash: "sess-tok", ExpiresAt: time.Now().Add(time.Hour),
	}).Error)

	dropTableAfterUpdates(t, ls.db, 1, "web_authn_sessions")

	_, err := ls.ConsumeWebAuthnSession(context.Background(), "sess-tok", time.Now())
	require.Error(t, err)
}

func TestDeleteSecretVersionComment_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.DeleteSecretVersionComment(context.Background(), 1, 2, 3)
	require.Error(t, err)
}
