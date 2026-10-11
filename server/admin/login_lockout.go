// login_lockout.go implements `keyorix-server admin clear-login-lockout`
// (#2936): clears the per-IP login budget for one address and/or the
// per-account login lockout for one user, from the server host.
//
// Why a host-side admin command and not an API call: the situation it exists
// for is "nobody can log in" -- every login from the office/booth IP gets a
// 429, or the only admin account is locked -- so there may be no session to
// authorise an API call with. The authority is host access, the same as every
// other `keyorix-server admin` command (ADR-108 §B). An admin who CAN log in
// already has the audited online equivalent for accounts (core.UnlockUser).
//
// Like recover-admin, this deliberately works below internal/core: core has no
// operation that clears an IP's budget (the budget is a security control, not a
// user-facing setting), and its account unlock needs an acting Keyorix admin,
// which a host operator is not.
package admin

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

var (
	clearLockoutIP   string
	clearLockoutUser string
)

var clearLoginLockoutCmd = &cobra.Command{
	Use:   "clear-login-lockout",
	Short: "Clear the login budget for an IP address and/or the login lockout of an account",
	Long: `clear-login-lockout lifts a login refusal without waiting for it to expire.

  --ip ADDR    forgets every counted login attempt from ADDR (the per-IP budget
               behind "Too many login attempts", 429). ADDR is normalised the
               same way the server normalises it (IPv6 forms, a :port suffix).
  --user ID    clears the per-account login lockout of one user (numeric ID or
               email): failed-attempt counter, lock expiry and lockout count.

At least one is required; both may be given. Nothing else changes: no password,
MFA enrolment, session or role is touched. Every run writes an audit-chain
event (admin.login_lockout_cleared) naming what was cleared.

Like every admin command this needs the database to itself: stop the server
first, or pass --force if you are certain it is safe.

Exit codes: 0 on success, 1 on any failure.`,
	RunE: runClearLoginLockout,
}

func init() {
	clearLoginLockoutCmd.Flags().StringVar(&clearLockoutIP, "ip", "", "IP address whose login budget to clear")
	clearLoginLockoutCmd.Flags().StringVar(&clearLockoutUser, "user", "", "Account whose login lockout to clear: numeric user ID or email address")
	rootCmd.AddCommand(clearLoginLockoutCmd)
}

func runClearLoginLockout(cmd *cobra.Command, args []string) error {
	if clearLockoutIP == "" && clearLockoutUser == "" {
		return fmt.Errorf("give --ip, --user, or both")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return err
	}
	defer closeGormDB(db)

	var summary string
	err = withUsableStorage(cfg, func(store corestorage.Storage) error {
		s, err := performClearLoginLockout(context.Background(), db, store, clearLockoutIP, clearLockoutUser)
		summary = s
		return err
	})
	if err != nil {
		return err
	}
	fmt.Println(summary)
	return nil
}

// performClearLoginLockout does the work and writes the audit event; split from
// the cobra wrapper so it can be tested against a real database. It validates
// both inputs before changing anything, so a typo in one never leaves the
// other half applied.
func performClearLoginLockout(ctx context.Context, db *gorm.DB, store corestorage.Storage, ip, userIdentifier string) (string, error) {
	var canonical string
	if ip != "" {
		canonical = core.CanonicalIP(strings.TrimSpace(ip))
		if net.ParseIP(canonical) == nil {
			return "", fmt.Errorf("--ip %q is not an IP address", ip)
		}
	}
	var target *models.User
	if userIdentifier != "" {
		u, err := resolveTargetUser(ctx, store, userIdentifier)
		if err != nil {
			return "", err
		}
		target = u
	}

	var parts []string
	if canonical != "" {
		// Exactly the key the login handlers count under (core.CanonicalIP),
		// never a namespaced one: the password-reset and SSO-begin budgets share
		// this table under their own prefixes and are not what a login 429 is.
		res := db.WithContext(ctx).Where("ip = ?", canonical).Delete(&models.LoginAttempt{})
		if res.Error != nil {
			return "", fmt.Errorf("clear login attempts for %s: %w", canonical, res.Error)
		}
		parts = append(parts, fmt.Sprintf("cleared %d counted login attempt(s) for IP %s", res.RowsAffected, canonical))
	}
	if target != nil {
		if err := store.UpdateLoginLockoutState(ctx, target.ID, 0, nil, nil, 0); err != nil {
			return "", fmt.Errorf("clear login lockout for user %d: %w", target.ID, err)
		}
		parts = append(parts, fmt.Sprintf("cleared the login lockout of user %q (id %d)", target.Username, target.ID))
	}
	description := "keyorix-server admin clear-login-lockout: " + strings.Join(parts, "; ")

	ok := true
	ev := &models.AuditEvent{
		EventType:   "admin.login_lockout_cleared",
		Description: description,
		Success:     &ok,
		ActorType:   adminActorType,
		EventTime:   time.Now(),
	}
	if target != nil {
		uid := target.ID
		ev.UserID = &uid
	}
	if err := store.LogAuditEvent(ctx, ev); err != nil {
		// The clear already happened; say so rather than pretend it did not.
		return description, fmt.Errorf("%s -- but the audit event could not be written: %w", description, err)
	}
	return description, nil
}
