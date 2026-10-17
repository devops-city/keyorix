// bundle.go ports `keyorix bundle verify`/`import` (docs/cli-split-inventory.md §7 PR 10):
// air-gap update-bundle verification and staging, fully offline. `bundle build` (assembling
// and signing a release bundle with the offline signing key) is deliberately NOT ported here
// -- it is maintainer-only release tooling that must never ship in a customer-facing binary,
// so it stays in the old CLI (internal/cli/bundle) even after Phase 5. Both subcommands call
// pkg/bundleverify directly (a public leaf package with no internal/core, internal/storage,
// internal/config, or cloud-SDK imports -- FINISH-SPLIT step 2's whole point) rather than
// reimplementing verification here, per the explicit decision not to duplicate this logic.
//
// One real behavior difference from the old CLI's `import`: --deployment-id is now an
// explicit flag instead of being auto-read from a local server config file. The old CLI's
// configuredDeploymentID() read internal/config, which this module cannot import; an
// air-gapped operator staging a bundle onto a server they don't have local config access to
// is the common case anyway, so an explicit flag is no worse in practice and removes an
// implicit dependency on running this command from the same host as the server.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
	"github.com/keyorixhq/keyorix/pkg/bundleverify"
	"github.com/keyorixhq/keyorix/pkg/licenseverify"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Air-gap update bundles: verify and import offline",
	Long: `Verify and stage Keyorix air-gap update bundles (ADR-062 Phase 1).

A bundle is a single signed tarball carrying a release's artifacts, pinned by sha256 in a
manifest that is signed with an offline ed25519 key. An air-gapped operator carries the
file across the gap and verifies it offline against the public key embedded in this binary
at build time -- trust follows a pinned chain, never a key shipped inside the bundle.
"bundle build" (signing a new release) is maintainer-only tooling and lives in the old CLI.`,
}

func init() {
	rootCmd.AddCommand(bundleCmd)
}

var (
	bundleVerifyInstalled  string
	bundleVerifyForce      bool
	bundleImportDest       string
	bundleImportInstalled  string
	bundleImportForce      bool
	bundleImportLicense    string
	bundleImportDeployment string
	bundleImportResetState bool
)

var bundleVerifyCmd = &cobra.Command{
	Use:          "verify <bundle>",
	Short:        "Verify a bundle offline against the embedded pinned key and component digests",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runBundleVerify,
}

var bundleImportCmd = &cobra.Command{
	Use:          "import <bundle>",
	Short:        "Verify a bundle offline and stage its artifacts into a directory",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runBundleImport,
}

func init() {
	bundleVerifyCmd.Flags().StringVar(&bundleVerifyInstalled, "installed-version", "",
		"currently-installed version, to enforce no-downgrade / min-upgrade-from (required unless --force)")
	bundleVerifyCmd.Flags().BoolVar(&bundleVerifyForce, "force", false,
		"proceed without --installed-version (dangerous -- skips the no-downgrade / anti-skip check, verifies signature and digests only)")

	bundleImportCmd.Flags().StringVar(&bundleImportDest, "dest", "", "directory to stage verified artifacts into (required)")
	bundleImportCmd.Flags().StringVar(&bundleImportInstalled, "installed-version", "",
		"currently-installed version, to enforce no-downgrade / min-upgrade-from (required on a first import into --dest, unless --force)")
	bundleImportCmd.Flags().BoolVar(&bundleImportForce, "force", false,
		"proceed without --installed-version on a first import into --dest (dangerous -- skips the no-downgrade / anti-skip check)")
	bundleImportCmd.Flags().StringVar(&bundleImportLicense, "license", "", "path to the installed license token (bundle import is a commercial feature)")
	bundleImportCmd.Flags().StringVar(&bundleImportDeployment, "deployment-id", "", "this deployment's configured license.deployment_id, if the license is deployment-bound")
	bundleImportCmd.Flags().BoolVar(&bundleImportResetState, "reset-install-state", false,
		"acknowledge that --dest's install state was intentionally reset (e.g. --dest was deliberately "+
			"cleared or recreated): required when the external install-state record disagrees with --dest "+
			"itself, otherwise refused as a possible downgrade-reset attempt")
	_ = bundleImportCmd.MarkFlagRequired("dest")

	bundleCmd.AddCommand(bundleVerifyCmd)
	bundleCmd.AddCommand(bundleImportCmd)
}

func runBundleVerify(cmd *cobra.Command, args []string) error {
	reg, err := trust.DefaultRegistry()
	if err != nil {
		return fmt.Errorf("load trusted keys: %w", err)
	}

	f, _, err := regularfile.Open("bundle", args[0])
	if err != nil {
		return fmt.Errorf("open bundle: %w", err)
	}
	defer func() { _ = f.Close() }()

	m, err := bundleverify.Verify(f, reg)
	if err != nil {
		return fmt.Errorf("verification failed (fail-closed): %w", err)
	}
	if err := requireBundleVerifyInstalledVersion(); err != nil {
		return err
	}
	if err := m.CheckUpgrade(bundleVerifyInstalled); err != nil {
		return err
	}

	fmt.Printf("Bundle verified\n")
	fmt.Printf("  version:    %s\n", m.Version)
	fmt.Printf("  signed by:  key-id %s (trusted, embedded)\n", m.KeyID)
	fmt.Printf("  released:   %s\n", m.ReleasedAt.Format(time.RFC3339))
	if m.MinUpgradeFrom != "" {
		fmt.Printf("  min from:   %s\n", m.MinUpgradeFrom)
	}
	fmt.Printf("  components: %d (all digests match)\n", len(m.Components))
	for _, c := range m.Components {
		fmt.Printf("    - %s\n", c.Path)
	}
	return nil
}

func runBundleImport(cmd *cobra.Command, args []string) error {
	if bundleImportDest == "" {
		return usageErrorf("--dest is required")
	}
	reg, err := trust.DefaultRegistry()
	if err != nil {
		return fmt.Errorf("load trusted keys: %w", err)
	}

	// Commercial gate (ADR-065 Phase 2c): `bundle import` -- staging an update for an
	// air-gapped rollout -- is the first license-gated feature. `bundle verify` stays free.
	if err := requireAirgapUpdates(reg); err != nil {
		return err
	}
	if err := requireBundleImportInstalledVersion(); err != nil {
		return err
	}

	f, _, err := regularfile.Open("bundle", args[0])
	if err != nil {
		return fmt.Errorf("open bundle: %w", err)
	}
	defer func() { _ = f.Close() }()

	m, err := bundleverify.ExtractAllowingStateReset(f, reg, bundleImportDest, bundleImportInstalled, bundleImportResetState)
	if err != nil {
		return fmt.Errorf("import failed (fail-closed, nothing staged on a verify failure): %w", err)
	}

	fmt.Printf("Imported %s -- staged %d verified components under %s\n", m.Version, len(m.Components), bundleImportDest)
	fmt.Printf("  signed by: key-id %s (trusted, embedded)\n", m.KeyID)
	for _, c := range m.Components {
		fmt.Printf("    - %s\n", c.Path)
	}
	fmt.Printf("\nNext (operator-controlled rollout -- Keyorix never pushes to your registry):\n")
	fmt.Printf("  1. Load images into your internal registry, e.g.:\n")
	fmt.Printf("       for img in %s/images/*; do docker load -i \"$img\"; done\n", bundleImportDest)
	fmt.Printf("  2. Apply CRDs and run the Helm upgrade from the staged charts:\n")
	fmt.Printf("       kubectl apply -f %s/crds/   # if present\n", bundleImportDest)
	fmt.Printf("       helm upgrade keyorix %s/charts/keyorix-*.tgz\n", bundleImportDest)
	return nil
}

func requireAirgapUpdates(reg *trust.KeyRegistry) error {
	var token string
	if bundleImportLicense != "" {
		b, err := regularfile.ReadFile("license file", bundleImportLicense)
		if err != nil {
			return fmt.Errorf("read license: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	st := licenseverify.Evaluate(token, reg, bundleImportDeployment, time.Now(), 14*24*time.Hour)
	if st.HasFeature(licenseverify.FeatureAirgapUpdates) {
		return nil
	}
	return fmt.Errorf("`bundle import` is a commercial feature (%q) and requires a valid license "+
		"(current state: %s). Install one with `keyorix license install` and pass it via --license, "+
		"or check `keyorix license status`. `bundle verify` remains available without a license",
		licenseverify.FeatureAirgapUpdates, st.State)
}

func requireBundleVerifyInstalledVersion() error {
	bundleVerifyInstalled = strings.TrimSpace(bundleVerifyInstalled)
	if bundleVerifyInstalled != "" {
		return nil
	}
	if !bundleVerifyForce {
		return usageErrorf("--installed-version is required to check the no-downgrade / anti-skip " +
			"(min-upgrade-from) guarantees for this deployment: pass --installed-version " +
			"<currently-running-version>. Re-run with --force to verify only the signature and " +
			"component digests, with no downgrade check")
	}
	fmt.Fprintln(os.Stderr, "WARNING: --installed-version was not supplied -- proceeding with --force means "+
		"the no-downgrade and anti-skip (min-upgrade-from) checks are SKIPPED for this verification.")
	return nil
}

func requireBundleImportInstalledVersion() error {
	bundleImportInstalled = strings.TrimSpace(bundleImportInstalled)
	if bundleImportInstalled != "" {
		return nil
	}
	_, hasMarker, err := bundleverify.PersistedInstalledVersionAllowingReset(bundleImportDest, bundleImportResetState)
	if err != nil {
		if errors.Is(err, bundleverify.ErrInstallStateReset) {
			return fmt.Errorf("import failed (fail-closed): %w. If --dest's install state was "+
				"intentionally reset, re-run with --reset-install-state to proceed; otherwise treat "+
				"this as a possible downgrade attempt and investigate before proceeding", err)
		}
		return fmt.Errorf("import failed (fail-closed, nothing staged on a verify failure): %w", err)
	}
	if hasMarker {
		return nil
	}
	if !bundleImportForce {
		return usageErrorf("--installed-version is required: no prior import was recorded at %q, so there is "+
			"nothing to anchor the no-downgrade / anti-skip (min-upgrade-from) check against. Pass "+
			"--installed-version <currently-running-version>. If this really is a first install with "+
			"nothing yet to protect, re-run with --force to proceed without a downgrade check",
			bundleImportDest)
	}
	fmt.Fprintf(os.Stderr, "WARNING: --installed-version was not supplied and no prior import was found at %s "+
		"-- proceeding with --force means the no-downgrade and anti-skip (min-upgrade-from) checks are "+
		"SKIPPED for this import.\n", bundleImportDest)
	return nil
}
