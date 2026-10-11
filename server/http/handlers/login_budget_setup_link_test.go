// login_budget_setup_link_test.go — #2936 on the setup-link endpoint
// (POST /auth/setup/consume, ConsumeSetup). It shares the per-IP login budget
// and reserves a slot before the token lookup (G1), so it follows the same
// rule as /auth/login: a consume that DELIVERS a session hands its slot back,
// and one that fails keeps it (#2956 review, 2026-10-10 04:03, point 3).
package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func setupBudgetSlots(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", lockoutOracleTestIP).Count(&n).Error)
	return n
}

func TestLoginBudget_DeliveredSetupLinkLeavesNoSlot(t *testing.T) {
	h, _, db := newSetupConsumeCompletionEnv(t)
	plain := issueAccountSetupToken(t, h, "bob@example.com")

	w := postConsumeSetup(t, h, plain, "Kx#Vr9$Mn2!Zp4@Qw")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, setupBudgetSlots(t, db), "a setup-link consume that delivered a session must hand its slot back (#2936)")
}

func TestLoginBudget_FailedSetupLinkKeepsItsSlot(t *testing.T) {
	h, _, db := newSetupConsumeCompletionEnv(t)

	w := postConsumeSetup(t, h, "no-such-setup-token", "Kx#Vr9$Mn2!Zp4@Qw")
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.EqualValues(t, 1, setupBudgetSlots(t, db), "a dead token is a failed attempt and keeps its slot")
}
