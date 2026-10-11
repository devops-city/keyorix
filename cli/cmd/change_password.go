// change_password.go ports `keyorix change-password` (item 3b,
// RELEASE-BLOCKERS): a self-service wrapper for POST /api/v1/auth/change-password
// that did not exist anywhere in this CLI, so the one documented emergency
// admin-recovery flow (docs/operator/j5-lost-admin.md, recover-admin's printed
// one-time password) needed a raw curl call to finish. Mirrors login.go's
// prompt/insecure-flag pattern exactly, since this command carries the same
// two sensitive values (current + new password) login.go's --password does.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var (
	changePasswordCurrent string
	changePasswordNew     string
)

var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change your own password (drops your other sessions)",
	Long: `change-password calls POST /auth/change-password to set a new password for the
currently logged-in account. Every other active session belonging to this account is
revoked as a result -- the current one is not.

This is the command to run right after logging in with a one-time password
(e.g. the one keyorix-server admin recover-admin prints) -- the account stays
confined to this command (and a handful of others) until a real password is set.
With security.require_mfa on and no second factor yet, that login is a short
setup session that must also enrol MFA ("keyorix mfa enroll" + "keyorix mfa
activate", before or after this command); once both are done the session ends
and the next "keyorix login" asks for a code.`,
	RunE: runChangePassword,
}

func init() {
	changePasswordCmd.Flags().StringVar(&changePasswordCurrent, "current-password", "", "Current password (omit to be prompted)")
	changePasswordCmd.Flags().StringVar(&changePasswordNew, "new-password", "", "New password (omit to be prompted)")
	rootCmd.AddCommand(changePasswordCmd)
}

func runChangePassword(cmd *cobra.Command, args []string) error {
	current := changePasswordCurrent
	if current != "" {
		warnInsecureFlag(cmd, "current-password", "omit it to be prompted instead.")
	} else {
		p, err := promptPassword("Current password: ")
		if err != nil {
			return fmt.Errorf("read current password: %w", err)
		}
		current = p
	}

	newPassword := changePasswordNew
	if newPassword != "" {
		warnInsecureFlag(cmd, "new-password", "omit it to be prompted instead.")
	} else {
		p, err := promptPassword("New password: ")
		if err != nil {
			return fmt.Errorf("read new password: %w", err)
		}
		confirm, err := promptPassword("Confirm new password: ")
		if err != nil {
			return fmt.Errorf("read new password confirmation: %w", err)
		}
		if p != confirm {
			return fmt.Errorf("new password and confirmation do not match")
		}
		newPassword = p
	}

	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return err
	}
	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build client for %s: %w", serverURL, err)
	}

	resp, err := client.ChangePasswordWithResponse(context.Background(), apiclient.ChangePasswordJSONRequestBody{
		CurrentPassword: current,
		NewPassword:     newPassword,
	})
	if err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return apiError("change password", resp.StatusCode(), resp.Body)
	}

	if reauthenticationRequired(resp.Body) {
		fmt.Println("Password changed. Account setup is complete and this session has ended:")
		fmt.Println(`run "keyorix login" with the new password and a code from your authenticator app.`)
		return nil
	}
	fmt.Println("Password changed. Every other active session for this account has been revoked.")
	return nil
}

// reauthenticationRequired reports whether a change-password / MFA-activation
// response says the server ended this session because account setup is complete
// (#3024: a recovered admin's or one-time-password user's setup-only session).
func reauthenticationRequired(body []byte) bool {
	var env struct {
		Data struct {
			ReauthenticationRequired bool `json:"reauthentication_required"`
		} `json:"data"`
	}
	return json.Unmarshal(body, &env) == nil && env.Data.ReauthenticationRequired
}
