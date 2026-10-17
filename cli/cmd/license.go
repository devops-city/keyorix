// license.go ports `keyorix license install`/`status` (docs/cli-split-inventory.md §7 PR
// 10): offline license installation and entitlement inspection. `license issue` (minting a
// signed token with the offline license-signing key) is deliberately NOT ported -- it is
// maintainer-only, Keyorix-internal tooling and stays in the old CLI. Both subcommands call
// pkg/licenseverify directly, the same public leaf package the server's Gate uses, rather
// than reimplementing evaluation here.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
	"github.com/keyorixhq/keyorix/pkg/licenseverify"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Offline license: install and check status",
	Long: `Install and inspect a Keyorix offline license (ADR-062 Phase 2).

A license is a compact signed token validated locally against the license public key
embedded in this binary at build time -- no phone-home. Enforcement is fail-safe: a missing,
expired, or invalid license degrades to the community baseline with a warning; it never
denies access to existing secrets or stops the server. "license issue" (minting a new
license) is maintainer-only tooling and lives in the old CLI.`,
}

func init() {
	rootCmd.AddCommand(licenseCmd)
}

var (
	licenseInstallDest       string
	licenseInstallDeployment string
	licenseInstallGraceHours int

	licenseStatusFile       string
	licenseStatusDeployment string
	licenseStatusGraceHours int
)

var licenseInstallCmd = &cobra.Command{
	Use:          "install <token-file>",
	Short:        "Validate a license token and store it for the server to load",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runLicenseInstall,
}

var licenseStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show the locally-evaluated license entitlement",
	SilenceUsage: true,
	RunE:         runLicenseStatus,
}

func init() {
	licenseInstallCmd.Flags().StringVar(&licenseInstallDest, "dest", "", "path to store the validated license token (required)")
	licenseInstallCmd.Flags().StringVar(&licenseInstallDeployment, "deployment-id", "", "this deployment's id, to check a bound license")
	licenseInstallCmd.Flags().IntVar(&licenseInstallGraceHours, "grace-hours", 0, "post-expiry grace window in hours (default 336 = 14d)")
	_ = licenseInstallCmd.MarkFlagRequired("dest")

	licenseStatusCmd.Flags().StringVar(&licenseStatusFile, "license", "", "license token file to evaluate")
	licenseStatusCmd.Flags().StringVar(&licenseStatusDeployment, "deployment-id", "", "this deployment's id, to check a bound license")
	licenseStatusCmd.Flags().IntVar(&licenseStatusGraceHours, "grace-hours", 0, "post-expiry grace window in hours (default 336 = 14d)")

	licenseCmd.AddCommand(licenseInstallCmd)
	licenseCmd.AddCommand(licenseStatusCmd)
}

func runLicenseInstall(cmd *cobra.Command, args []string) error {
	if licenseInstallDest == "" {
		return usageErrorf("--dest is required")
	}
	token, err := readLicenseToken(args[0])
	if err != nil {
		return err
	}
	reg, err := trust.DefaultRegistry()
	if err != nil {
		return fmt.Errorf("load trusted keys: %w", err)
	}
	st := licenseverify.Evaluate(token, reg, licenseInstallDeployment, time.Now().UTC(), graceOf(licenseInstallGraceHours))
	// Fail-safe: a degraded license still installs (so a later renewal/clock-fix can
	// activate it), but never store an unparseable/forged token.
	if st.State == licenseverify.StateInvalid {
		return fmt.Errorf("refusing to install an invalid license: %s", st.Reason)
	}
	if err := writeLicenseFileNoFollow(licenseInstallDest, []byte(token+"\n")); err != nil {
		return fmt.Errorf("write license: %w", err)
	}
	fmt.Printf("Installed license for %q (plan %s) -> %s\n", st.Licensee, st.Plan, licenseInstallDest)
	printLicenseStatus(st)
	return nil
}

func runLicenseStatus(cmd *cobra.Command, args []string) error {
	var token string
	if licenseStatusFile != "" {
		t, err := readLicenseToken(licenseStatusFile)
		if err != nil {
			return err
		}
		token = t
	}
	reg, err := trust.DefaultRegistry()
	if err != nil {
		return fmt.Errorf("load trusted keys: %w", err)
	}
	st := licenseverify.Evaluate(token, reg, licenseStatusDeployment, time.Now().UTC(), graceOf(licenseStatusGraceHours))
	printLicenseStatus(st)
	return nil
}

func printLicenseStatus(st licenseverify.Status) {
	fmt.Printf("  state:    %s\n", st.State)
	if st.Licensee != "" {
		fmt.Printf("  licensee: %s\n", st.Licensee)
	}
	if st.Plan != "" {
		fmt.Printf("  plan:     %s\n", st.Plan)
	}
	if !st.NotAfter.IsZero() {
		fmt.Printf("  expires:  %s\n", st.NotAfter.UTC().Format(time.RFC3339))
	}
	if st.Grants() && len(st.Features) > 0 {
		fmt.Printf("  features: %s\n", strings.Join(st.Features, ", "))
	} else {
		fmt.Printf("  features: (community baseline -- no commercial features)\n")
	}
	if st.Reason != "" {
		fmt.Printf("  note:     %s\n", st.Reason)
	}
}

func readLicenseToken(path string) (string, error) {
	b, err := regularfile.ReadFile("license file", path)
	if err != nil {
		return "", fmt.Errorf("read license token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// graceOf converts a grace flag (hours) into a duration, defaulting to 14 days when unset.
func graceOf(hours int) time.Duration {
	if hours <= 0 {
		return 14 * 24 * time.Hour
	}
	return time.Duration(hours) * time.Hour
}

// writeLicenseFileNoFollow writes data to path, refusing to write through a pre-existing
// symlink at the final path component. This module cannot import internal/securefiles (see
// pkg/bundleverify's own doc comment on the same tradeoff); a license token is sensitive
// but not secret-value material, and this narrower guarantee (final component only, not a
// full per-intermediate-directory walk) is judged sufficient for a single explicit
// operator-supplied --dest path.
func writeLicenseFileNoFollow(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, 0o600) // #nosec G304 -- operator-supplied --dest path; O_NOFOLLOW guards the final component
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
