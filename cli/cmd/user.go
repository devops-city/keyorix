// user.go ports `keyorix user` (docs/cli-split-inventory.md §2.2, PR 6): user account
// lifecycle management. Same flags, output, and exit codes as the old CLI's
// internal/cli/user package's remote-mode branch -- this is a pure transport port (REST
// only), not a behavior change. `--by` is kept on the five account-lifecycle commands that
// required it in the old CLI (suspend/reactivate/force-password-reset/revoke-sessions/
// resend-setup-link/delete) for flag-compatibility even though, exactly as in the old CLI's
// own remote mode, it is not sent to the server: the acting admin in remote mode is always
// the session identity behind the configured bearer token, never --by (which only had
// meaning for the old CLI's now-removed local/embedded audit trail).
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// readPassword is the function used to read a password from the terminal. It is a
// variable so tests can inject a mock without requiring a real PTY (mirrors the old CLI's
// internal/cli/user/create.go).
var readPassword = func() ([]byte, error) {
	return term.ReadPassword(int(syscall.Stdin))
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
	Long:  "Create, read, update, delete, list, and manage the account lifecycle of users.",
}

func init() {
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userGetCmd)
	userCmd.AddCommand(userUpdateCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userSuspendCmd)
	userCmd.AddCommand(userReactivateCmd)
	userCmd.AddCommand(userForcePasswordResetCmd)
	userCmd.AddCommand(userRevokeSessionsCmd)
	userCmd.AddCommand(userResendSetupLinkCmd)
	userCmd.AddCommand(userSuspendInactiveCmd)
}

// remoteUser decodes the "data" payload of GET/POST/PUT /api/v1/users[...], matching the
// field names userToAPIResponse (server/http/handlers/users_handler.go) writes.
type remoteUser struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func printRemoteUser(u *remoteUser) {
	fmt.Printf("ID: %d\nUsername: %s\nEmail: %s\nDisplay: %s\nActive: %t\nCreated: %s\nUpdated: %s\n",
		u.ID, u.Username, u.Email, u.DisplayName, u.Active, u.CreatedAt, u.UpdatedAt)
}

// remoteUserLabel resolves "user <id> (<email>)" via GET /api/v1/users/{id}. A lookup
// failure falls back to the bare "user <id>" -- a display nicety, never a precondition for
// the mutating call that follows it (mirrors the old CLI's remote_helpers.go).
func remoteUserLabel(ctx context.Context, client *apiclient.ClientWithResponses, userID uint) string {
	resp, err := client.GetUserWithResponse(ctx, int(userID))
	if err != nil || resp.StatusCode() != 200 {
		return fmt.Sprintf("user %d", userID)
	}
	u, err := decodeData[remoteUser](resp.Body)
	if err != nil || u.Email == "" {
		return fmt.Sprintf("user %d", userID)
	}
	return fmt.Sprintf("user %d (%s)", userID, u.Email)
}

// ── user create ──────────────────────────────────────────────────────────────

var (
	userCreateUsername        string
	userCreateEmail           string
	userCreateDisplayName     string
	userCreateSetupLink       bool
	userCreateOneTimePassword bool
	userCreateBy              string
)

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Long: "Create a new user. Supply --password to set an initial password, or use\n" +
		"--setup-link to provision an ADR-028 setup link instead: the account is created\n" +
		"in pending_first_login state and the user sets their own password via the link.\n" +
		"In out-of-band mode the link is printed for you to relay.\n\n" +
		"Or use --one-time-password to have the server generate an initial password\n" +
		"(ADR-028 Part E): the account is created in password_reset_required state, the\n" +
		"password is printed once for you to relay, and the user must change it on first\n" +
		"login.",
	RunE: runUserCreate,
}

var userCreatePassword string

func init() {
	userCreateCmd.Flags().StringVar(&userCreateUsername, "username", "", "Username (required)")
	userCreateCmd.Flags().StringVar(&userCreateEmail, "email", "", "Email (required)")
	userCreateCmd.Flags().StringVar(&userCreatePassword, "password", "", "Initial password (INSECURE on the command line — prefer KEYORIX_INITIAL_PASSWORD or the interactive prompt; required in some form unless --setup-link or --one-time-password)")
	userCreateCmd.Flags().StringVar(&userCreateDisplayName, "display-name", "", "Display name (defaults to username)")
	userCreateCmd.Flags().BoolVar(&userCreateSetupLink, "setup-link", false, "Provision a setup link instead of an admin-set password (ADR-028)")
	userCreateCmd.Flags().BoolVar(&userCreateOneTimePassword, "one-time-password", false, "Generate a one-time password instead of an admin-set password (ADR-028 Part E); must be changed on first login")
	userCreateCmd.Flags().StringVar(&userCreateBy, "by", "", "Acting admin email (unused in this REST-only CLI -- kept for flag compatibility; the session behind your bearer token is always the acting admin)")
}

func runUserCreate(cmd *cobra.Command, _ []string) error {
	if userCreateUsername == "" {
		return errors.New("username is required (use --username)")
	}
	if userCreateEmail == "" {
		return errors.New("email is required (use --email)")
	}
	if userCreateSetupLink && userCreateOneTimePassword {
		return errors.New("use either --setup-link or --one-time-password, not both")
	}

	var password string
	if !userCreateSetupLink && !userCreateOneTimePassword {
		pw, err := resolveInitialPassword(cmd)
		if err != nil {
			return err
		}
		if pw == "" {
			return errors.New("password is required (use --password, KEYORIX_INITIAL_PASSWORD, or the interactive prompt), or use --setup-link or --one-time-password")
		}
		password = pw
	}

	display := userCreateDisplayName
	if display == "" {
		display = userCreateUsername
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	body := apiclient.CreateUserJSONRequestBody{
		Username:    userCreateUsername,
		Email:       openapitypes.Email(userCreateEmail),
		DisplayName: display,
	}
	switch {
	case userCreateSetupLink:
		t := true
		body.DeliverSetupLink = &t
	case userCreateOneTimePassword:
		t := true
		body.GenerateOneTimePassword = &t
	default:
		body.Password = &password
	}

	resp, err := client.CreateUserWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return apiError("create user", resp.StatusCode(), resp.Body)
	}

	// The response shape varies by mode: password mode sends the user object
	// directly as `data`; setup-link/OTP modes nest it under `data.user`.
	payload, err := decodeData[struct {
		remoteUser
		User      *remoteUser `json:"user"`
		SetupLink *struct {
			Email        string `json:"email"`
			Channel      string `json:"channel"`
			Delivered    bool   `json:"delivered"`
			LinkForAdmin string `json:"link_for_admin,omitempty"`
		} `json:"setup_link"`
		OneTimePassword *struct {
			Email     string    `json:"email"`
			OTPValue  string    `json:"one_time_password"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"one_time_password"`
	}](resp.Body)
	if err != nil {
		return err
	}

	u := payload.remoteUser
	if payload.User != nil {
		u = *payload.User
	}
	fmt.Printf("User created: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)

	if payload.SetupLink != nil {
		sl := payload.SetupLink
		if sl.Delivered {
			fmt.Printf("Setup link delivered to %s via %s.\n", sl.Email, sl.Channel)
		} else {
			fmt.Printf("Setup link (relay this to %s securely — it is single-use and expires):\n  %s\n", sl.Email, sl.LinkForAdmin)
		}
	}
	if payload.OneTimePassword != nil {
		otp := payload.OneTimePassword
		// Intentional one-time display to the admin who ran this command --
		// the only channel by which a freshly issued OTP can reach them. The
		// codeql[...] tag must be the single comment line directly above the
		// sink (AlertSuppression.qll requires the comment's own end line ==
		// alert line - 1; see internal/connect/vault.go for the same
		// constraint documented at its own suppression site).
		// codeql[go/clear-text-logging]
		fmt.Printf("One-time password for %s (relay securely — it must be changed on first login):\n  %s\n", otp.Email, otp.OTPValue)
		if !otp.ExpiresAt.IsZero() {
			fmt.Printf("Expires: %s (UTC). After that, login with it is refused like a wrong password; send a setup link (user resend-setup-link) or re-create the user.\n",
				otp.ExpiresAt.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// resolveInitialPassword returns the new user's initial password without ever requiring it
// on argv: the (insecure, warned) --password flag if set, else KEYORIX_INITIAL_PASSWORD,
// else an interactive no-echo prompt. Mirrors the old CLI's identical helper
// (internal/cli/user/create.go).
func resolveInitialPassword(_ *cobra.Command) (string, error) {
	if userCreatePassword != "" {
		fmt.Fprintln(os.Stderr, "⚠️  Passing --password on the command line is insecure (visible via ps/proc and saved in shell history); prefer the KEYORIX_INITIAL_PASSWORD environment variable, or omit it to be prompted.")
		return userCreatePassword, nil
	}
	if pw := os.Getenv("KEYORIX_INITIAL_PASSWORD"); pw != "" {
		return pw, nil
	}
	fmt.Fprint(os.Stderr, "Initial password: ")
	b, err := readPassword()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(b), nil
}

// ── user get ─────────────────────────────────────────────────────────────────

var (
	userGetID    uint
	userGetEmail string
)

var userGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a user by id or email",
	RunE:  runUserGet,
}

func init() {
	userGetCmd.Flags().UintVar(&userGetID, "id", 0, "User ID")
	userGetCmd.Flags().StringVar(&userGetEmail, "email", "", "User email")
}

func runUserGet(_ *cobra.Command, _ []string) error {
	if userGetID == 0 && userGetEmail == "" {
		return errors.New("specify --id or --email")
	}
	if userGetID != 0 && userGetEmail != "" {
		return errors.New("use only one of --id or --email")
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	var body []byte
	var status int
	if userGetID != 0 {
		resp, err := client.GetUserWithResponse(ctx, int(userGetID))
		if err != nil {
			return err
		}
		body, status = resp.Body, resp.StatusCode()
	} else {
		resp, err := client.GetUserByEmailWithResponse(ctx, &apiclient.GetUserByEmailParams{Email: userGetEmail})
		if err != nil {
			return err
		}
		body, status = resp.Body, resp.StatusCode()
	}
	if status != 200 {
		return apiError("get user", status, body)
	}
	u, err := decodeData[remoteUser](body)
	if err != nil {
		return err
	}
	printRemoteUser(&u)
	return nil
}

// ── user update ──────────────────────────────────────────────────────────────

var (
	userUpdateID          uint
	userUpdateUsername    string
	userUpdateEmail       string
	userUpdateDisplayName string
	userUpdateActiveStr   string
)

var userUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a user",
	RunE:  runUserUpdate,
}

func init() {
	userUpdateCmd.Flags().UintVar(&userUpdateID, "id", 0, "User ID (required)")
	userUpdateCmd.Flags().StringVar(&userUpdateUsername, "username", "", "New username")
	userUpdateCmd.Flags().StringVar(&userUpdateEmail, "email", "", "New email")
	userUpdateCmd.Flags().StringVar(&userUpdateDisplayName, "display-name", "", "New display name")
	userUpdateCmd.Flags().StringVar(&userUpdateActiveStr, "active", "", "Active status: true or false")
}

func runUserUpdate(_ *cobra.Command, _ []string) error {
	if userUpdateID == 0 {
		return errors.New("user id is required (use --id)")
	}
	if userUpdateUsername == "" && userUpdateEmail == "" && userUpdateDisplayName == "" && userUpdateActiveStr == "" {
		return errors.New("provide at least one of --username, --email, --display-name, --active")
	}
	var active *bool
	if userUpdateActiveStr != "" {
		v, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(userUpdateActiveStr)))
		if err != nil {
			return fmt.Errorf("invalid --active value (use true or false): %w", err)
		}
		active = &v
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	body := apiclient.UpdateUserJSONRequestBody{}
	if userUpdateUsername != "" {
		body.Username = &userUpdateUsername
	}
	if userUpdateEmail != "" {
		e := openapitypes.Email(userUpdateEmail)
		body.Email = &e
	}
	if userUpdateDisplayName != "" {
		body.DisplayName = &userUpdateDisplayName
	}
	if active != nil {
		body.Active = active
	}

	resp, err := client.UpdateUserWithResponse(ctx, int(userUpdateID), body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		// Surfaces the admin-rank-ceiling refusal (403) and the last-install-
		// administrator refusal (409, server/http/handlers/users_crud.go's
		// UpdateUser) readably -- both now map to a real error body, not a bare
		// generic 500 (see this PR's server-side fix).
		return apiError("update user", resp.StatusCode(), resp.Body)
	}
	u, err := decodeData[remoteUser](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("User updated: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
	return nil
}

// ── user delete ──────────────────────────────────────────────────────────────

var (
	userDeleteID    uint
	userDeleteForce bool
	userDeleteBy    string
)

var userDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	RunE:  runUserDelete,
}

func init() {
	userDeleteCmd.Flags().UintVar(&userDeleteID, "id", 0, "User ID (required)")
	userDeleteCmd.Flags().BoolVar(&userDeleteForce, "force", false, "Skip the confirmation prompt")
	userDeleteCmd.Flags().StringVar(&userDeleteBy, "by", "", "Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility)")
	_ = userDeleteCmd.MarkFlagRequired("id")
	_ = userDeleteCmd.MarkFlagRequired("by")
}

func runUserDelete(_ *cobra.Command, _ []string) error {
	if userDeleteID == 0 {
		return errors.New("user id is required (use --id)")
	}
	if userDeleteBy == "" {
		return errors.New("acting admin email is required (use --by)")
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	label := remoteUserLabel(ctx, client, userDeleteID)

	if !userDeleteForce {
		if !confirmYesNo(fmt.Sprintf("Delete %s? This cannot be undone.", label)) {
			fmt.Println("❌ Deletion cancelled")
			return nil
		}
	}

	fmt.Printf("Deleting %s...\n", label)
	resp, err := client.DeleteUserWithResponse(ctx, int(userDeleteID))
	if err != nil {
		return err
	}
	if resp.StatusCode() != 204 && resp.StatusCode() != 200 {
		return apiError(fmt.Sprintf("delete %s", label), resp.StatusCode(), resp.Body)
	}
	fmt.Printf("%s deleted.\n", label)
	return nil
}

// ── user list ────────────────────────────────────────────────────────────────

var (
	userListPage     int
	userListPageSize int
)

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	RunE:  runUserList,
}

func init() {
	userListCmd.Flags().IntVar(&userListPage, "page", 1, "Page number")
	userListCmd.Flags().IntVar(&userListPageSize, "page-size", 20, "Page size (max 100)")
}

func runUserList(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	page, pageSize := userListPage, userListPageSize
	resp, err := client.ListUsersWithResponse(ctx, &apiclient.ListUsersParams{Page: &page, PageSize: &pageSize})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("list users", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		Users []remoteUser `json:"users"`
		Total int64        `json:"total"`
	}](resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf("Total: %d\n", data.Total)
	fmt.Printf("%-6s %-20s %-30s %-10s\n", "ID", "USERNAME", "EMAIL", "ACTIVE")
	for _, u := range data.Users {
		fmt.Printf("%-6d %-20s %-30s %-10t\n", u.ID, u.Username, u.Email, u.Active)
	}
	return nil
}

// ── account-lifecycle commands: suspend / reactivate / force-password-reset ──

const (
	descActingAdminEmail = "Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility)"
	descTargetUserID     = "Target user ID (required)"
)

var (
	userSuspendID            uint
	userSuspendBy            string
	userReactivateID         uint
	userReactivateBy         string
	userForcePasswordResetID uint
	userForcePasswordResetBy string
)

var userSuspendCmd = &cobra.Command{
	Use:   "suspend",
	Short: "Suspend a user (blocks login)",
	Long:  "Suspend a user account. A suspended user is refused login entirely until reactivated.",
	RunE: func(_ *cobra.Command, _ []string) error {
		if userSuspendID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if userSuspendBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		return runAccountStateChange(userSuspendID, "suspend", "Suspending", "suspended")
	},
}

var userReactivateCmd = &cobra.Command{
	Use:   "reactivate",
	Short: "Reactivate a user (restores login)",
	Long:  "Return a suspended (or otherwise non-active) user to the active state.",
	RunE: func(_ *cobra.Command, _ []string) error {
		if userReactivateID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if userReactivateBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		return runAccountStateChange(userReactivateID, "reactivate", "Reactivating", "reactivated")
	},
}

var userForcePasswordResetCmd = &cobra.Command{
	Use:   "force-password-reset",
	Short: "Require a user to change their password at next login",
	Long: "Force a user into a restricted session until they change their password.\n" +
		"They can authenticate but every endpoint except change-password is blocked until then.",
	RunE: func(_ *cobra.Command, _ []string) error {
		if userForcePasswordResetID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if userForcePasswordResetBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		return runAccountStateChange(userForcePasswordResetID, "require-password-reset", "Requiring a password reset for", "required to reset their password")
	},
}

var (
	userRevokeSessionsID uint
	userRevokeSessionsBy string
)

var userRevokeSessionsCmd = &cobra.Command{
	Use:   "revoke-sessions",
	Short: "Force-logout a user (revoke all active sessions)",
	Long: "Terminate every active session of a user immediately, without changing their\n" +
		"account state — for suspected session/token theft. The user can log back in after\n" +
		"re-authenticating. To block login entirely, use 'suspend' instead.",
	RunE: func(_ *cobra.Command, _ []string) error {
		if userRevokeSessionsID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if userRevokeSessionsBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		label := remoteUserLabel(ctx, client, userRevokeSessionsID)
		fmt.Printf("Revoking active sessions for %s...\n", label)

		resp, err := client.RevokeUserSessionsWithResponse(ctx, int(userRevokeSessionsID))
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError(fmt.Sprintf("revoke sessions for %s", label), resp.StatusCode(), resp.Body)
		}
		result, err := decodeData[struct {
			Revoked int `json:"revoked"`
		}](resp.Body)
		if err != nil {
			return err
		}
		if result.Revoked == 0 {
			fmt.Printf("0 sessions revoked for %s -- none were active.\n", label)
			return nil
		}
		fmt.Printf("Revoked %d active session(s) for %s.\n", result.Revoked, label)
		return nil
	},
}

func init() {
	userSuspendCmd.Flags().UintVar(&userSuspendID, "id", 0, descTargetUserID)
	userSuspendCmd.Flags().StringVar(&userSuspendBy, "by", "", descActingAdminEmail)
	_ = userSuspendCmd.MarkFlagRequired("id")
	_ = userSuspendCmd.MarkFlagRequired("by")

	userReactivateCmd.Flags().UintVar(&userReactivateID, "id", 0, descTargetUserID)
	userReactivateCmd.Flags().StringVar(&userReactivateBy, "by", "", descActingAdminEmail)
	_ = userReactivateCmd.MarkFlagRequired("id")
	_ = userReactivateCmd.MarkFlagRequired("by")

	userForcePasswordResetCmd.Flags().UintVar(&userForcePasswordResetID, "id", 0, descTargetUserID)
	userForcePasswordResetCmd.Flags().StringVar(&userForcePasswordResetBy, "by", "", descActingAdminEmail)
	_ = userForcePasswordResetCmd.MarkFlagRequired("id")
	_ = userForcePasswordResetCmd.MarkFlagRequired("by")

	userRevokeSessionsCmd.Flags().UintVar(&userRevokeSessionsID, "id", 0, descTargetUserID)
	userRevokeSessionsCmd.Flags().StringVar(&userRevokeSessionsBy, "by", "", descActingAdminEmail)
	_ = userRevokeSessionsCmd.MarkFlagRequired("id")
	_ = userRevokeSessionsCmd.MarkFlagRequired("by")
}

// runAccountStateChange performs the suspend/reactivate/require-password-reset transition
// against the connected server (POST /api/v1/users/{id}/<action>). The acting admin is the
// session identity behind the configured bearer token (see this file's doc comment on --by).
func runAccountStateChange(userID uint, action, verbing, pastTense string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	label := remoteUserLabel(ctx, client, userID)
	fmt.Printf("%s %s...\n", verbing, label)

	var resp interface {
		StatusCode() int
	}
	var body []byte
	switch action {
	case "suspend":
		r, err := client.SuspendUserWithResponse(ctx, int(userID))
		if err != nil {
			return err
		}
		resp, body = r, r.Body
	case "reactivate":
		r, err := client.ReactivateUserWithResponse(ctx, int(userID))
		if err != nil {
			return err
		}
		resp, body = r, r.Body
	case "require-password-reset":
		r, err := client.RequirePasswordResetWithResponse(ctx, int(userID))
		if err != nil {
			return err
		}
		resp, body = r, r.Body
	default:
		return fmt.Errorf("unknown account-state action %q", action)
	}
	if resp.StatusCode() != 200 {
		return apiError(fmt.Sprintf("change account state for %s", label), resp.StatusCode(), body)
	}
	fmt.Printf("%s has been %s.\n", label, pastTense)
	return nil
}

// ── user resend-setup-link ──────────────────────────────────────────────────

var (
	userResendSetupLinkID uint
	userResendSetupLinkBy string
)

var userResendSetupLinkCmd = &cobra.Command{
	Use:   "resend-setup-link",
	Short: "Reissue and redeliver a user's setup link (ADR-028)",
	Long: "Reissue an account's setup link, invalidating any prior link, and deliver it\n" +
		"again. In out-of-band mode the link is printed for you to relay. Throttled per\n" +
		"the ADR-028 resend limits.",
	RunE: func(_ *cobra.Command, _ []string) error {
		if userResendSetupLinkID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if userResendSetupLinkBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		label := remoteUserLabel(ctx, client, userResendSetupLinkID)
		fmt.Printf("Reissuing setup link for %s...\n", label)

		resp, err := client.ResendSetupLinkWithResponse(ctx, int(userResendSetupLinkID))
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError(fmt.Sprintf("resend setup link for %s", label), resp.StatusCode(), resp.Body)
		}
		prov, err := decodeData[struct {
			Email        string `json:"email"`
			Channel      string `json:"channel"`
			Delivered    bool   `json:"delivered"`
			LinkForAdmin string `json:"link_for_admin,omitempty"`
		}](resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Setup link reissued for %s.\n", label)
		if prov.Delivered {
			fmt.Printf("Setup link delivered to %s via %s.\n", prov.Email, prov.Channel)
		} else {
			fmt.Printf("Setup link (relay this to %s securely — it is single-use and expires):\n  %s\n", prov.Email, prov.LinkForAdmin)
		}
		return nil
	},
}

func init() {
	userResendSetupLinkCmd.Flags().UintVar(&userResendSetupLinkID, "id", 0, "Target user ID (required)")
	userResendSetupLinkCmd.Flags().StringVar(&userResendSetupLinkBy, "by", "", "Acting admin email (required; unused in this REST-only CLI -- kept for flag compatibility)")
	_ = userResendSetupLinkCmd.MarkFlagRequired("id")
	_ = userResendSetupLinkCmd.MarkFlagRequired("by")
}

// ── user suspend-inactive ────────────────────────────────────────────────────

var (
	userSuspendInactiveDays   int
	userSuspendInactiveDryRun bool
)

var userSuspendInactiveCmd = &cobra.Command{
	Use:   "suspend-inactive",
	Short: "Suspend users who have been inactive beyond a threshold",
	Long: `Suspend all non-admin users whose last login (or account creation, if they
have never logged in) is older than --days days. Triggers the server-side job via
POST /api/v1/admin/jobs/suspend-inactive-users (requires system.write).

With --dry-run the command evaluates all users against the threshold but makes
no changes — it prints what would be suspended.`,
	SilenceUsage: true,
	RunE:         runUserSuspendInactive,
}

func init() {
	userSuspendInactiveCmd.Flags().IntVar(&userSuspendInactiveDays, "days", 0, "Inactivity threshold in days (required, must be > 0)")
	userSuspendInactiveCmd.Flags().BoolVar(&userSuspendInactiveDryRun, "dry-run", false, "Preview which users would be suspended without making changes")
	_ = userSuspendInactiveCmd.MarkFlagRequired("days")
}

func runUserSuspendInactive(_ *cobra.Command, _ []string) error {
	if userSuspendInactiveDays <= 0 {
		return fmt.Errorf("--days must be greater than 0")
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	body := apiclient.SuspendInactiveUsersJSONRequestBody{
		InactiveDays: userSuspendInactiveDays,
		DryRun:       &userSuspendInactiveDryRun,
	}
	resp, err := client.SuspendInactiveUsersWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("suspend inactive users", resp.StatusCode(), resp.Body)
	}
	result, err := decodeData[struct {
		Suspended []uint `json:"suspended"`
		Skipped   int    `json:"skipped"`
		Total     int    `json:"total"`
	}](resp.Body)
	if err != nil {
		return err
	}

	prefix := ""
	if userSuspendInactiveDryRun {
		prefix = "[dry-run] "
	}
	fmt.Printf("%sInactive users examined: %d\n", prefix, result.Total)
	fmt.Printf("%sSkipped (already suspended or admin): %d\n", prefix, result.Skipped)
	if userSuspendInactiveDryRun {
		fmt.Printf("%sWould suspend: %d\n", prefix, len(result.Suspended))
	} else {
		fmt.Printf("%sSuspended: %d\n", prefix, len(result.Suspended))
	}
	if len(result.Suspended) > 0 {
		ids := make([]string, len(result.Suspended))
		for i, id := range result.Suspended {
			ids[i] = fmt.Sprintf("%d", id)
		}
		action := "Suspended"
		if userSuspendInactiveDryRun {
			action = "Would suspend"
		}
		fmt.Printf("%s%s user IDs: %s\n", prefix, action, strings.Join(ids, ", "))
	}
	return nil
}
