package core

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// upgrading6vQuery returns the SQL block that docs/UPGRADING.md section 6v tells
// operators to run after #3493. The test runs the text the operator will copy, not a
// private copy of it, so the documented query cannot drift from what is tested.
func upgrading6vQuery(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/UPGRADING.md")
	require.NoError(t, err)
	_, after, found := strings.Cut(string(raw), "<!-- upgrading-6v-check-query -->")
	require.True(t, found, "marker comment missing from docs/UPGRADING.md section 6v")
	_, block, found := strings.Cut(after, "```sql\n")
	require.True(t, found, "no ```sql block after the marker")
	query, _, found := strings.Cut(block, "```")
	require.True(t, found, "unterminated ```sql block")
	return strings.TrimSpace(query)
}

type upgrading6vRow struct {
	ID         uint
	Username   string
	Email      string
	ExternalID string
}

func upgrading6vIDs(t *testing.T, db *gorm.DB, query string) []uint {
	t.Helper()
	var rows []upgrading6vRow
	require.NoError(t, db.Raw(query).Scan(&rows).Error)
	ids := make([]uint, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

// The UPGRADING 6v check query must return exactly the accounts SCIM created that carry
// an sso: external id (the rows #3493 stopped treating as SCIM-managed), and none of
// the accounts SSO itself claimed or created. SQLite always; Postgres when
// KEYORIX_TEST_PG_DSN is set (the statement is documented as identical on both).
func TestUpgrading6vCheckQuery_FindsOnlySCIMCreatedSSORows(t *testing.T) {
	backends := map[string]func(*testing.T) *ctaReview{
		"sqlite":   newCTAReviewSQLite,
		"postgres": newCTAReview,
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			f := open(t)
			ctx := context.Background()
			db := f.setupDB

			// SCIM-created, bare external id: SCIM still owns it. Not reported.
			bare, err := f.setup.ProvisionSCIMUser(ctx, 0, "bob@example.com", "", "", "okta|bob", true)
			require.NoError(t, err)

			// SCIM-created before the upgrade with an sso: id (the server accepted it then;
			// ProvisionSCIMUser refuses it now, so relabel the row to reproduce that state).
			// Reported.
			legacy, err := f.setup.ProvisionSCIMUser(ctx, 0, "carol@example.com", "", "", "okta|carol", true)
			require.NoError(t, err)
			require.NoError(t, db.Model(&models.User{}).Where("id = ?", legacy.ID).
				Update("external_id", ssoExternalID("corp", "carol-sub")).Error)

			// Same, but soft-deleted since. Not reported.
			gone, err := f.setup.ProvisionSCIMUser(ctx, 0, "dave@example.com", "", "", "okta|dave", true)
			require.NoError(t, err)
			require.NoError(t, db.Model(&models.User{}).Where("id = ?", gone.ID).
				Update("external_id", ssoExternalID("corp", "dave-sub")).Error)
			require.NoError(t, db.Delete(&models.User{}, gone.ID).Error)

			// SSO-claimed native account and a JIT account: sso: ids, no SCIM audit row.
			// Not reported.
			claimed := &models.User{Username: "erin", UsernameFolded: "erin", Email: "erin@example.com",
				IsActive: true, AccountState: AccountActive, ExternalID: ssoExternalID("corp", "erin-sub")}
			require.NoError(t, db.Create(claimed).Error)
			jit := &models.User{Username: "frank", UsernameFolded: "frank", Email: "frank@example.com",
				IsActive: true, AccountState: AccountActive, ExternalID: ssoExternalID("corp", "frank-sub")}
			require.NoError(t, db.Create(jit).Error)

			query := upgrading6vQuery(t)
			got := upgrading6vIDs(t, db, query)
			require.Equal(t, []uint{legacy.ID}, got,
				"the documented query must report only the SCIM-created sso: row (bare=%d claimed=%d jit=%d gone=%d)",
				bare.ID, claimed.ID, jit.ID, gone.ID)

			// Calibration: the bare prefix query the old note suggested also lists the
			// SSO-owned accounts, which is why the join exists.
			naive := upgrading6vIDs(t, db,
				"SELECT id, username, email, external_id FROM users WHERE external_id LIKE 'sso:%' AND deleted_at IS NULL ORDER BY id")
			require.ElementsMatch(t, []uint{legacy.ID, claimed.ID, jit.ID}, naive)
		})
	}
}
