// recover_admin.go implements `keyorix-server admin recover-admin`
// (docs/design-b2-recover-admin.md §3): restores a locked-out admin account
// after host access AND the offline recovery key (recovery_key.go) are both
// verified. The recovery act is identical regardless of WHY the account is
// inaccessible (deactivated, lost password, lost MFA, login-lockout) -- all
// four cases go through the same reset below (design §3/§9 addendum 4).
//
// Deliberately bypasses internal/core entirely, calling storage.Storage
// primitives directly (same ADR-049 CLI-storage-factory pattern every other
// admin command uses): core's own equivalents (ReactivateUser, DisableMFA,
// RevokeUserSessions, ...) all require either a working re-authentication
// factor (exactly what this command exists for a user who has LOST) or an
// acting adminID subject to the normal admin-rank ceiling (there is no
// Keyorix identity to attribute this action to -- the actor is the host OS
// user, per design §4). Calling the raw storage layer is not a shortcut
// around those checks; it is the correct layer for an operation whose only
// authority is host access + the recovery key, neither of which the RBAC
// ceiling model has any way to represent.
package admin

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	recoverAdminUser string
	recoverAdminKey  string
)

var recoverAdminCmd = &cobra.Command{
	Use:   "recover-admin",
	Short: "Restore a locked-out admin account using the local recovery key",
	Long: `recover-admin restores an existing admin account that is deactivated, has a
lost password, has lost MFA, or is login-locked -- all four cases go through
the identical reset. Requires BOTH host access (running this command) AND
the local recovery key (docs/design-b2-recover-admin.md §2) -- knowing the
key alone, or holding the host alone, is not enough.

--recovery-key must be exactly "-": the key is always read from stdin, never
a command-line argument, to keep it out of shell history and process listings.
Omit it entirely if security.recover_admin.keyless_mode is enabled in this
host's config (a labs/demo escape hatch -- see the config field's own doc
comment for why this is not recommended for a real deployment).

What this resets, on the target account ONLY: reactivates it if deactivated,
sets a one-time password (printed once, forcing a real reset on next login),
clears MFA enrollment and every WebAuthn credential (forcing re-enrollment),
clears any login-lockout state, and revokes every existing session. It never
touches any other account, role, project, secret, or the KEK. Every use
writes an audit-chain event and notifies every current admin, whether or not
the server is running.

Exit codes: 0 on success, 1 on any failure (see the printed error message).`,
	RunE: runRecoverAdmin,
}

func init() {
	recoverAdminCmd.Flags().StringVar(&recoverAdminUser, "user", "", "The account to recover: numeric user ID or email address (required)")
	recoverAdminCmd.Flags().StringVar(&recoverAdminKey, "recovery-key", "", `Must be "-" -- the key is read from stdin, never a CLI argument (required unless security.recover_admin.keyless_mode is enabled)`)
	rootCmd.AddCommand(recoverAdminCmd)
}

func runRecoverAdmin(cmd *cobra.Command, args []string) error {
	if recoverAdminUser == "" {
		return fmt.Errorf("--user is required (numeric user ID or email address)")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	keyless := cfg.Security.RecoverAdmin.KeylessMode

	var rawKey string
	if keyless {
		// design §1/§5: keyless mode collapses host access and admin access
		// into one trust boundary -- loud every time, never a silent
		// downgrade, matching the startup warning's own "every boot, not
		// just the first" posture.
		fmt.Fprintln(os.Stderr, "WARNING: keyless mode is enabled (security.recover_admin.keyless_mode) -- "+
			"proceeding on HOST ACCESS ALONE, no recovery key required or checked. This collapses host access "+
			"and admin access into one trust boundary; see docs/design-b2-recover-admin.md §1/§5.")
		if recoverAdminKey != "" && recoverAdminKey != "-" {
			return fmt.Errorf(`--recovery-key must be exactly "-", or omitted entirely in keyless mode`)
		}
	} else {
		if recoverAdminKey != "-" {
			return fmt.Errorf(`--recovery-key must be exactly "-" -- the key is read from stdin, never passed as a value here`)
		}
		rawKey, err = readRecoveryKeyFromStdin()
		if err != nil {
			return err
		}
	}

	// Held for the WHOLE run (same reasoning as recovery-key rotate): a
	// concurrent recover-admin/rotate-key invocation must not observe a
	// half-applied recovery.
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	var summary *recoverAdminSummary
	err = withUsableStorage(cfg, func(store corestorage.Storage) error {
		s, err := performRecoverAdmin(context.Background(), store, recoverAdminUser, rawKey, keyless)
		summary = s
		return err
	})
	if err != nil {
		return fmt.Errorf("recover-admin: %w", err)
	}

	fmt.Printf("Recovered admin account: %s (user id %d).\n", summary.username, summary.userID)
	fmt.Println("Reset: account state, password, MFA enrollment,")
	fmt.Printf("  %d WebAuthn credential(s), login-lockout state, %d active session(s).\n",
		summary.webAuthnCredentialsCleared, summary.sessionsRevoked)
	fmt.Println()
	fmt.Println("One-time password (shown once — copy it now, it cannot be retrieved again):")
	// Intentional one-time display to the operator, same as user create OTP
	// (cli/cmd/user.go) -- this stdout line is the only channel by which a
	// freshly generated recovery password can reach the person recovering
	// the account. The codeql[...] tag must be the single comment line
	// directly above the sink (AlertSuppression.qll requires the comment's
	// own end line == alert line - 1; see internal/connect/vault.go for the
	// same constraint documented at its own suppression site).
	// codeql[go/clear-text-logging]
	fmt.Printf("  %s\n", summary.oneTimePassword)
	if cfg.Security.RequireMFA {
		// #3024: the login this password allows is a setup-only session.
		fmt.Printf("Log in as %q with this password. That session lasts at most %d minutes and can only set a new\n",
			summary.username, int(core.SetupSessionTTL.Minutes()))
		fmt.Println("password (keyorix change-password) and enrol a second factor (keyorix mfa enroll + activate), in either")
		fmt.Println("order. When both are done it ends; log in again with the new password and a code.")
	} else {
		fmt.Printf("Log in as %q with this password; you will be required to set a new one immediately.\n", summary.username)
	}
	if summary.auditChainBroken {
		fmt.Fprintf(os.Stderr, "WARNING: the audit chain was already broken before this run (first broken row: %d). "+
			"This recovery was still performed and is recorded as a new chain segment -- see the audit log.\n",
			summary.auditChainFirstBrokenID)
	}

	notifyErr := withUsableStorage(cfg, func(store corestorage.Storage) error {
		keyDetail := fmt.Sprintf("generation %d of the recovery key", summary.recoveryKeyVersion)
		if summary.keyless {
			keyDetail = "KEYLESS MODE (host access alone, no recovery key checked)"
		}
		notifyAllAdmins(store, "Admin account recovered",
			fmt.Sprintf("keyorix-server admin recover-admin, run by host user %s, restored account %q (user id %d) on this host, "+
				"using %s. If you did not expect this, investigate immediately.",
				summary.operator, summary.username, summary.userID, keyDetail))
		return nil
	})
	if notifyErr != nil {
		fmt.Printf("note: could not notify admins (%v)\n", notifyErr)
	}

	return nil
}

// readRecoveryKeyFromStdin reads a single line from stdin and returns it
// trimmed. The key's own Normalize (internal/recoverykey) tolerates
// whitespace/case/dash variation beyond this, so only the trailing newline
// needs stripping here.
func readRecoveryKeyFromStdin() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read recovery key from stdin: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("no recovery key read from stdin")
	}
	return line, nil
}

// resolveTargetUser parses --user as either a numeric ID or an email
// address, per design §3's "--user <email-or-id>".
func resolveTargetUser(ctx context.Context, store corestorage.Storage, identifier string) (*models.User, error) {
	// bitSize 32: user IDs fit in 32 bits on every platform, and a parsed value can never
	// overflow the uint conversion below (CodeQL go/incorrect-integer-conversion). An
	// out-of-range number is not a valid ID and falls through to the email lookup.
	if id, err := strconv.ParseUint(identifier, 10, 32); err == nil {
		user, err := store.GetUser(ctx, uint(id))
		if err != nil {
			return nil, fmt.Errorf("no account with id %d: %w", id, err)
		}
		return user, nil
	}
	user, err := store.GetUserByEmail(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("no account with email %q: %w", identifier, err)
	}
	return user, nil
}
