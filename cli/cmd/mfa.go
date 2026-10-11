package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var mfaCmd = &cobra.Command{
	Use:   "mfa",
	Short: "Manage MFA (multi-factor authentication)",
}

var mfaEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Begin TOTP MFA enrolment",
	Long: `enroll generates a fresh TOTP secret and prints the otpauth:// URI (for a QR code)
and the base32 secret (for manual entry into an authenticator app). This only begins
enrolment -- the account is not protected by MFA until you confirm with a code via
"keyorix mfa activate". With security.require_mfa on (the default, ADR-112), a
session without MFA can reach only enroll/activate until this is done.`,
	RunE: runMFAEnroll,
}

var (
	mfaActivateCode     string
	mfaActivatePassword string
)

var mfaActivateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Confirm TOTP enrolment with a code, enabling MFA",
	Long: `activate verifies a TOTP code (from the authenticator app you enrolled with
"keyorix mfa enroll") against the pending secret, together with your account
password, and enables MFA. On success it prints one-time-shown recovery codes --
save them now, they will not be shown again. Activation keeps the current session
signed in (you just proved the password and a code) and signs out every other
session for the account; your next "keyorix login" asks for a code. Exception: in
the setup session after a one-time password (recover-admin, forced reset) under
security.require_mfa, activating as the last setup step ends that session too.`,
	RunE: runMFAActivate,
}

var mfaStepUpCode string

var mfaStepUpCmd = &cobra.Command{
	Use:   "stepup",
	Short: "Re-verify your TOTP to unlock restricted secret reads",
	Long: `Re-verify your authenticator code (or a recovery code) without re-logging in.
On success, a 15-minute window is opened server-side that allows reading
"restricted" classified secrets.`,
	RunE: runMFAStepUp,
}

func init() {
	// --code/--password are INSECURE on the command line (visible via ps/proc and saved
	// in shell history) -- same reasoning as loginCmd's --api-key. Omit to be prompted.
	mfaActivateCmd.Flags().StringVar(&mfaActivateCode, "code", "", "TOTP code from the authenticator app (INSECURE on the command line -- omit to be prompted)")
	mfaActivateCmd.Flags().StringVar(&mfaActivatePassword, "password", "", "Account password (INSECURE on the command line -- omit to be prompted)")
	mfaStepUpCmd.Flags().StringVar(&mfaStepUpCode, "code", "", "TOTP or recovery code (INSECURE on the command line -- omit to be prompted)")
	mfaCmd.AddCommand(mfaEnrollCmd)
	mfaCmd.AddCommand(mfaActivateCmd)
	mfaCmd.AddCommand(mfaStepUpCmd)
}

func runMFAEnroll(cmd *cobra.Command, args []string) error {
	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("MFA enrolment requires an active session -- run \"keyorix login\" first")
	}

	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	resp, err := client.EnrollMFAWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("contact %s: %w", serverURL, err)
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Secret == "" {
		return httpStatusError("MFA enrolment failed", resp.StatusCode(), resp.Body)
	}
	data := resp.JSON200.Data

	fmt.Println("Scan this into your authenticator app:")
	fmt.Println()
	fmt.Println("  " + data.OtpauthUri)
	fmt.Println()
	fmt.Println("Or enter this secret manually:")
	fmt.Println()
	fmt.Println("  " + data.Secret)
	fmt.Println()
	fmt.Println(`Then run "keyorix mfa activate" with a code from the app to finish enabling MFA.`)
	return nil
}

func runMFAActivate(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("code") || cmd.Flags().Changed("password") {
		fmt.Fprintln(os.Stderr, "Warning: --code/--password are visible in your shell history and to other processes on this machine (ps/proc) -- prefer the interactive prompts.")
	}

	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("MFA activation requires an active session -- run \"keyorix login\" first")
	}

	code := mfaActivateCode
	if code == "" {
		code, err = promptLine("Enter TOTP code from your authenticator app: ")
		if err != nil || code == "" {
			return fmt.Errorf("code is required")
		}
	}
	password := mfaActivatePassword
	if password == "" {
		password, err = promptPassword("Account password: ")
		if err != nil || password == "" {
			return fmt.Errorf("password is required")
		}
	}

	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	resp, err := client.ActivateMFAWithResponse(context.Background(), apiclient.ActivateMFAJSONRequestBody{
		Code:     code,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("contact %s: %w", serverURL, err)
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("MFA activation failed", resp.StatusCode(), resp.Body)
	}

	if reauthenticationRequired(resp.Body) {
		fmt.Println("MFA enabled. Account setup is complete and this session has ended: run \"keyorix login\" with your password and a code.")
	} else {
		fmt.Println("MFA enabled. This session stays signed in; other sessions were signed out, and your next \"keyorix login\" asks for a code.")
	}
	if codes := resp.JSON200.Data.RecoveryCodes; len(codes) > 0 {
		fmt.Println()
		fmt.Println("Save these recovery codes now -- they will not be shown again:")
		fmt.Println()
		for _, c := range codes {
			fmt.Println("  " + c)
		}
	}
	return nil
}

func runMFAStepUp(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("code") {
		fmt.Fprintln(os.Stderr, "Warning: --code is visible in your shell history and to other processes on this machine (ps/proc) -- prefer the interactive prompt.")
	}

	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("MFA step-up requires an active session -- run \"keyorix login\" first")
	}

	code := mfaStepUpCode
	if code == "" {
		code, err = promptLine("Enter TOTP or recovery code: ")
		if err != nil || code == "" {
			return fmt.Errorf("code is required")
		}
	}

	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	resp, err := client.MfaStepUpWithResponse(context.Background(), apiclient.MfaStepUpJSONRequestBody{Code: code})
	if err != nil {
		return fmt.Errorf("contact %s: %w", serverURL, err)
	}
	if resp.StatusCode() != 200 {
		return httpStatusError("MFA step-up failed", resp.StatusCode(), resp.Body)
	}

	fmt.Println("MFA step-up verified. Restricted secrets are accessible for 15 minutes.")
	return nil
}
