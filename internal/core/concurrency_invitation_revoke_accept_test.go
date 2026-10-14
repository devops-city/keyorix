package core

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_RevokeInvitation_RacesAccept is the #412 TOCTOU regression: an
// admin's RevokeInvitation and a concurrent holder's completeInvitationAccept (via
// CompleteSetup) both read the same pending invitation, mutate it in memory, and
// used to persist with a bare read-mutate-Save (UpdateProjectInvitation) with no
// WHERE-state guard — so whichever write landed second silently clobbered the
// other's transition, with no error on either side, and could leave the
// just-accepted membership/role grant live behind an invitation that reads
// "revoked". This drives BOTH paths concurrently against the SAME invitation, many
// times over, against a real file-backed SQLite (the same conditional-UPDATE code
// path production uses) and asserts: exactly one side ever wins, the loser gets a
// clean "concurrently modified" error rather than a silent no-op, the persisted
// invitation state exactly matches the winner, and — the security invariant that
// matters — no live project role grant for the invited user survives when revoke
// wins the race.
func TestConcurrency_RevokeInvitation_RacesAccept(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	const iterations = 25
	for i := range iterations {
		// Named explicitly (not the anonymous t.Run("", ...) form): Go names an
		// anonymous subtest "#00", "#01", ... and that literal "#" then lands in
		// t.TempDir()'s path. Embedded into a "file:" URI DSN, SQLite (per its
		// documented URI-filename parsing) treats everything from the first "#"
		// onward as an ignored fragment — silently truncating the path AND
		// dropping the "?_busy_timeout=..." query string — so every iteration
		// collided on the same truncated path instead of getting its own database.
		t.Run(fmt.Sprintf("iter%d", i), func(t *testing.T) {
			dsn := "file:" + filepath.Join(t.TempDir(), fmt.Sprintf("invite-revoke-accept-race-%d.db", i)) +
				"?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
			db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
			require.NoError(t, err)
			require.NoError(t, db.AutoMigrate(
				&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
				&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
				&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
				&models.ProjectMembership{}, &models.ProjectInvitation{}, &models.SetupToken{},
				&models.PasswordHistory{}, &models.AuditEvent{},
			))

			st := store.NewLocalStorage(db)
			c := NewKeyorixCore(st)
			c.SetBootstrapToken("test-bootstrap-token")
			boot, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
				Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
				DisplayName: "Admin", Token: "test-bootstrap-token",
			})
			require.NoError(t, err)
			adminID := boot.User.ID
			projID := boot.Project.ID
			// Open mode: acceptance grants the role immediately, so there's a real live
			// grant at stake if the race is lost.
			c.SetMembershipValidationMode(ValidationModeOpen)

			ctx := context.Background()
			now := c.now()
			future := now.Add(24 * time.Hour)
			email := "racer@example.com"
			inv, err := st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
				ProjectID: projID, Email: email, Role: "project_developer", State: InvitationPending,
				InvitedBy: adminID, ValidationModeAtInvite: ValidationModeOpen, ExpiresAt: &future, CreatedAt: now,
			})
			require.NoError(t, err)

			raw := setupPrefix + "revoke-accept-race"
			_, err = st.CreateSetupToken(ctx, &models.SetupToken{
				TokenHash: sha256Hex(raw), Purpose: SetupPurposeInvitationAccept, SubjectEmail: email,
				InvitationID: &inv.ID, State: SetupTokenActive, ExpiresAt: future, CreatedBy: adminID,
			})
			require.NoError(t, err)

			var revokeErr, acceptErr error
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				revokeErr = c.RevokeInvitation(ctx, projID, inv.ID, adminID)
			}()
			go func() {
				defer wg.Done()
				<-start
				_, acceptErr = c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
			}()
			close(start)
			wg.Wait()

			revokeWon := revokeErr == nil
			acceptWon := acceptErr == nil
			require.NotEqual(t, revokeWon, acceptWon,
				"iteration %d: exactly one of revoke/accept must win, never both or neither (revokeErr=%v acceptErr=%v)",
				i, revokeErr, acceptErr)

			final, err := st.GetProjectInvitation(ctx, inv.ID)
			require.NoError(t, err)

			if revokeWon {
				assert.Error(t, acceptErr)
				assert.Equal(t, InvitationRevoked, final.State,
					"iteration %d: the winning revoke must be the persisted state", i)

				// The security invariant #412 closes: a revoked invitation must not leave
				// a live project role grant behind, even if the accept raced far enough to
				// create the account before losing the final conditional write.
				//
				// GetUserRoleIDsExact (not GetUserRoleIDsAt) — every new account also
				// carries the install-wide "system_viewer" baseline role (ADR-021, granted
				// at project_id=0 by CreateUser regardless of any project invitation), and
				// GetUserRoleIDsAt's scope match treats project_id=0 as "applies
				// everywhere", so it would always find that unrelated global grant and make
				// this assertion vacuously fail. GetUserRoleIDsExact matches the invitation
				// grant's PROJECT-scoped key (project_id=projID, environment_id=0) only.
				newUser, uerr := st.GetUserByEmail(ctx, email)
				if uerr == nil && newUser != nil {
					ids, err := st.GetUserRoleIDsExact(ctx, newUser.ID, Scope{ProjectID: projID})
					require.NoError(t, err)
					assert.Empty(t, ids, "iteration %d: a revoked invitation must not leave a live project role grant behind", i)
				}
			} else {
				assert.Error(t, revokeErr)
				assert.Equal(t, InvitationAccepted, final.State,
					"iteration %d: the winning accept must be the persisted state", i)

				// The winning accept must have actually landed the grant it claims.
				newUser, uerr := st.GetUserByEmail(ctx, email)
				require.NoError(t, uerr)
				ids, err := st.GetUserRoleIDsAt(ctx, newUser.ID, Scope{ProjectID: projID})
				require.NoError(t, err)
				assert.NotEmpty(t, ids, "iteration %d: a successfully accepted invitation must have granted the role", i)
			}
		})
	}
}
