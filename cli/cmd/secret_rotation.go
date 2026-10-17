// secret_rotation.go — keyorix secret rotate/rotation-simulate/auto-rotate.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── rotate ───────────────────────────────────────────────────────────────────

var (
	rotateID    int
	rotateValue string
)

var secretRotateCmd = &cobra.Command{
	Use:          "rotate",
	Short:        "Rotate a secret by providing a new value",
	SilenceUsage: true,
	RunE:         runSecretRotate,
}

func runSecretRotate(cmd *cobra.Command, _ []string) error {
	if rotateID == 0 {
		return usageErrorf("--id is required")
	}

	warnInsecureFlag(cmd, "value", "omit the flag to be prompted instead.")
	value := rotateValue
	if !cmd.Flags().Changed("value") {
		v, err := promptPassword("New secret value (hidden): ")
		if err != nil {
			return fmt.Errorf("read value: %w", err)
		}
		value = v
	}
	if value == "" {
		return usageErrorf("secret value is required (use --value or enter it at the prompt)")
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RotateSecretWithResponse(context.Background(), rotateID, apiclient.RotateSecretJSONRequestBody{
		NewValue: value,
	})
	if err != nil {
		return err
	}
	if resp.JSON200 == nil {
		return httpStatusError("rotate secret", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Secret %d rotated successfully.\n", rotateID)
	return nil
}

func init() {
	secretRotateCmd.Flags().IntVar(&rotateID, "id", 0, "Secret ID (required)")
	secretRotateCmd.Flags().StringVar(&rotateValue, "value", "", "New secret value (omit to be prompted interactively)")
	SecretCmd.AddCommand(secretRotateCmd)
}

// ── rotation-simulate ────────────────────────────────────────────────────────

var rotationSimulateID int

var secretRotationSimulateCmd = &cobra.Command{
	Use:   "rotation-simulate",
	Short: "Simulate a rotation dry-run for a secret",
	Long: `Validate a secret's rotation configuration without executing any live rotation.

Checks:
  policy_exists  — at least one active rotation policy covers the secret
  backend_known  — the configured rotation backend is registered
  ref_non_empty  — the rotation ref is non-empty
  ref_valid      — the rotation ref passes metacharacter validation

Requires secrets.read at the secret's scope.`,
	SilenceUsage: true,
	RunE:         runSecretRotationSimulate,
}

func runSecretRotationSimulate(_ *cobra.Command, _ []string) error {
	if rotationSimulateID == 0 {
		return usageErrorf("--id is required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.SimulateSecretRotationWithResponse(context.Background(), rotationSimulateID)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("simulate rotation", resp.StatusCode(), resp.Body)
	}
	printRotationDryRunResult(resp.JSON200.Data)
	return nil
}

func printRotationDryRunResult(r *apiclient.RotationDryRunResult) {
	fmt.Printf("Secret: %s (id %d)\n", derefStr(r.SecretName), derefInt(r.SecretId))
	fmt.Printf("Backend: %s   Ref: %s\n", derefStr(r.Backend), derefStr(r.Ref))
	fmt.Println()
	fmt.Printf("%-20s %-6s %s\n", "CHECK", "RESULT", "MESSAGE")
	fmt.Printf("%-20s %-6s %s\n", "--------------------", "------", "-------")
	if r.Checks != nil {
		for _, ch := range *r.Checks {
			result := "PASS"
			if !derefBool(ch.Passed) {
				result = "FAIL"
			}
			fmt.Printf("%-20s %-6s %s\n", derefStr(ch.Name), result, derefStr(ch.Message))
		}
	}
	fmt.Println()
	if derefBool(r.Valid) {
		fmt.Println("Overall: PASS — rotation configuration is valid.")
	} else {
		fmt.Println("Overall: FAIL — one or more checks failed.")
	}
}

func init() {
	secretRotationSimulateCmd.Flags().IntVar(&rotationSimulateID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(secretRotationSimulateCmd)
}

// ── auto-rotate ──────────────────────────────────────────────────────────────

var (
	autoRotateID      int
	autoRotateOff     bool
	autoRotateLength  int
	autoRotateCharset string
	autoRotateBackend string
	autoRotateRef     string
)

var secretAutoRotateCmd = &cobra.Command{
	Use:   "auto-rotate",
	Short: "Enable/disable automated rotation for a secret",
	Long: `Opt a secret into automated rotation: when it is overdue under an active rotation
policy, Keyorix regenerates its value on schedule. Optionally set the generated
value's shape with --length and --charset. Use --off to disable.

Enable only for secrets whose value Keyorix owns — auto-rotation changes the stored
value without touching any upstream system. Requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE:         runSecretAutoRotate,
}

func runSecretAutoRotate(_ *cobra.Command, _ []string) error {
	if autoRotateID == 0 {
		return usageErrorf("--id is required")
	}
	switch autoRotateCharset {
	case "", "alphanumeric", "lower_alphanumeric", "hex", "alphanumeric_symbols":
	default:
		return fmt.Errorf("--charset must be alphanumeric, lower_alphanumeric, hex, or alphanumeric_symbols")
	}
	if (autoRotateBackend == "") != (autoRotateRef == "") {
		return usageErrorf("--backend and --ref must be set together (or both omitted)")
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	enabled := !autoRotateOff
	body := apiclient.SetSecretAutoRotateJSONRequestBody{
		Enabled: &enabled,
		Length:  &autoRotateLength,
		Charset: &autoRotateCharset,
		Backend: &autoRotateBackend,
		Ref:     &autoRotateRef,
	}
	resp, err := client.SetSecretAutoRotateWithResponse(context.Background(), autoRotateID, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return httpStatusError("set auto-rotate", resp.StatusCode(), resp.Body)
	}
	if autoRotateOff {
		fmt.Printf("Auto-rotation disabled for secret %d.\n", autoRotateID)
	} else {
		fmt.Printf("Auto-rotation enabled for secret %d.\n", autoRotateID)
	}
	return nil
}

func init() {
	secretAutoRotateCmd.Flags().IntVar(&autoRotateID, "id", 0, "Secret ID (required)")
	secretAutoRotateCmd.Flags().BoolVar(&autoRotateOff, "off", false, "Disable auto-rotation (default enables)")
	secretAutoRotateCmd.Flags().IntVar(&autoRotateLength, "length", 0, "Generated value length (8-256, 0 = default 32)")
	secretAutoRotateCmd.Flags().StringVar(&autoRotateCharset, "charset", "", "alphanumeric|lower_alphanumeric|hex|alphanumeric_symbols (empty = default)")
	secretAutoRotateCmd.Flags().StringVar(&autoRotateBackend, "backend", "", "Rotation backend name — rotate the upstream credential too")
	secretAutoRotateCmd.Flags().StringVar(&autoRotateRef, "ref", "", "Upstream identifier the backend rotates (required with --backend)")
	SecretCmd.AddCommand(secretAutoRotateCmd)
}
