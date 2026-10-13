package admin

// check_admin_password.go -- `keyorix-server admin check-admin-password`: tells
// an operator, BEFORE the first-boot bootstrap POST, whether the configured
// first-admin password would be refused by the server's own password policy
// (#3201). The container entrypoint cannot see the server's refusal itself
// (BusyBox wget drops the body of a 403), so it asks this command first and
// prints the real reason instead of retrying ten times with a hint that blames
// the bootstrap token.
//
// It applies exactly the check core.BootstrapSystem applies: the policy the
// server resolves from the config (ResolvePasswordPolicy, shared with the
// server's startup) against the admin's own username / email / display name.
// It touches neither the database nor the network, and never prints the
// password.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/rules"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

// adminPasswordRejectedExitCode is the exit status of a password the policy
// refuses. It is distinct from 1 (stdin read error, flag error, ...) so the
// container entrypoint can tell a verdict from a failure to produce one.
const adminPasswordRejectedExitCode = 2

// maxAdminPasswordBytes bounds the stdin read; the server's own secret-file
// ceiling is 1 MiB, anything near that is already not a password.
const maxAdminPasswordBytes = 1 << 20

var (
	checkAdminPasswordUsername    string
	checkAdminPasswordEmail       string
	checkAdminPasswordDisplayName string
)

var checkAdminPasswordCmd = &cobra.Command{
	Use:   "check-admin-password",
	Short: "Check a first-admin password (read from stdin) against the server's password policy",
	Long: `Reads the password from standard input (never from an argument, which any
process in the container could read) and checks it against the password policy
the server enforces on POST /system/init, for the given admin identity. Exits 0
when the password would be accepted; otherwise prints the policy's reason
("admin password rejected: password must not contain your username, ...") and
exits 2. Exit 1 is any other failure (unreadable or oversized stdin, bad flags):
it is no verdict on the password. It does not touch the database or the
network, and never prints the password.

Exit codes: 0 accepted, 2 refused by the password policy, 1 anything else.

The container entrypoint runs it before the first-boot bootstrap so a rejected
password is reported once, with its real cause.`,
	Args: cobra.NoArgs,
	RunE: runCheckAdminPassword,
}

func init() {
	checkAdminPasswordCmd.Flags().StringVar(&checkAdminPasswordUsername, "username", "admin", "The first admin's username")
	checkAdminPasswordCmd.Flags().StringVar(&checkAdminPasswordEmail, "email", "admin@keyorix.local", "The first admin's email")
	checkAdminPasswordCmd.Flags().StringVar(&checkAdminPasswordDisplayName, "display-name", "Administrator", "The first admin's display name")
	rootCmd.AddCommand(checkAdminPasswordCmd)
}

// ResolvePasswordPolicy merges the configured password_policy block onto the
// built-in defaults (ADR-025), so a rule the operator did not set keeps its safe
// default instead of collapsing to the Go zero value (#G37). The server's startup
// and `admin check-admin-password` both use it, so the pre-boot check cannot
// disagree with what the server enforces. internal/config cannot import
// internal/core (it would cycle through internal/encryption), so the conversion
// happens here.
func ResolvePasswordPolicy(pp config.PasswordPolicyConfig) rules.PasswordPolicy {
	d := rules.DefaultPasswordPolicy()
	r := pp.Resolve(config.PasswordPolicyValues{
		MinLength:             d.MinLength,
		RequireUppercase:      d.RequireUppercase,
		RequireLowercase:      d.RequireLowercase,
		RequireDigit:          d.RequireDigit,
		RequireSpecial:        d.RequireSpecial,
		RejectPersonalInfo:    d.RejectPersonalInfo,
		RejectCommonPasswords: d.RejectCommonPasswords,
		HistoryCount:          d.HistoryCount,
		MaxAgeDays:            d.MaxAgeDays,
	})
	return rules.PasswordPolicy{
		MinLength:             r.MinLength,
		RequireUppercase:      r.RequireUppercase,
		RequireLowercase:      r.RequireLowercase,
		RequireDigit:          r.RequireDigit,
		RequireSpecial:        r.RequireSpecial,
		RejectPersonalInfo:    r.RejectPersonalInfo,
		RejectCommonPasswords: r.RejectCommonPasswords,
		HistoryCount:          r.HistoryCount,
		MaxAgeDays:            r.MaxAgeDays,
	}
}

// adminPasswordRejection validates pw for the first admin and returns the
// operator-facing refusal, or nil. The identity mirrors core.BootstrapSystem
// (an empty display name falls back to the username).
func adminPasswordRejection(policy rules.PasswordPolicy, pw, username, email, displayName string) error {
	if displayName == "" {
		displayName = username
	}
	if err := policy.Validate(pw, &models.User{Username: username, Email: email, DisplayName: displayName}); err != nil {
		return newExitCodeError(adminPasswordRejectedExitCode, fmt.Errorf("admin password rejected: %w", err))
	}
	return nil
}

func runCheckAdminPassword(cmd *cobra.Command, _ []string) error {
	pw, err := readAdminPassword(cmd.InOrStdin())
	if err != nil {
		return err
	}
	// The same policy the server resolves from its config. If the config cannot be
	// loaded the server will not start either; fall back to the defaults, which
	// are never weaker than a configured policy the server could have applied.
	policy := rules.DefaultPasswordPolicy()
	if cfg, cfgErr := config.Load(configPathFlag); cfgErr == nil {
		policy = ResolvePasswordPolicy(cfg.PasswordPolicy)
	}
	if err := adminPasswordRejection(policy, pw, checkAdminPasswordUsername, checkAdminPasswordEmail, checkAdminPasswordDisplayName); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "admin password accepted by the password policy")
	return nil
}

// readAdminPassword reads the whole of r, then strips one trailing "\n" and one
// trailing "\r" (as the server's own secret readers do).
func readAdminPassword(r io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(bufio.NewReader(r), maxAdminPasswordBytes+1))
	if err != nil {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	if len(raw) > maxAdminPasswordBytes {
		return "", errors.New("password on stdin is too large")
	}
	pw := strings.TrimSuffix(string(raw), "\n")
	pw = strings.TrimSuffix(pw, "\r")
	if pw == "" {
		return "", newExitCodeError(adminPasswordRejectedExitCode, errors.New("admin password rejected: the password is empty"))
	}
	return pw, nil
}
