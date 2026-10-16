// trust.go ports `keyorix trust keygen` (docs/cli-split-inventory.md §2.6, PR 8): local
// tooling for Keyorix's air-gap signing keys (ADR-062). This is the one command in the
// entire ported surface that talks to no server at all -- it mints an ed25519 keypair
// locally and writes it to disk. The private key is the signing secret (kept offline,
// used by Keyorix to sign update bundles / licenses); the public key is embedded into
// release builds so a deployment can verify offline.
//
// The old CLI's internal/cli/trust imports internal/trust (for GenerateKey/purpose
// constants) and internal/securefiles (for the symlink/overwrite-safe key writes);
// neither can be imported here (depguard). GenerateKey is one line of stdlib
// (crypto/ed25519.GenerateKey) reimplemented directly below; the secure-write guarantee
// is cli/internal/securefiles (CreateFileSync/WriteFile, a port of the main module's
// internal/securefiles).
package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/securefiles"
)

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Air-gap signing-key tooling (ed25519 keypairs for update bundles / licenses)",
	Long: `Generate and inspect the asymmetric keys Keyorix uses to sign air-gapped update
bundles and offline licenses (ADR-062). The private key never ships; its public key is
embedded into release builds so an air-gapped deployment can verify offline.`,
}

func init() {
	trustCmd.AddCommand(trustKeygenCmd)
	rootCmd.AddCommand(trustCmd)
}

const (
	trustPurposeUpdate  = "update"
	trustPurposeLicense = "license"
)

var (
	trustKeygenPurpose string
	trustKeygenKeyID   string
	trustKeygenDir     string
	trustKeygenForce   bool
)

var trustKeygenCmd = &cobra.Command{
	Use:          "keygen",
	Short:        "Generate an ed25519 signing keypair (update or license)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		purpose := strings.TrimSpace(trustKeygenPurpose)
		var ldVar string
		switch purpose {
		case trustPurposeUpdate:
			ldVar = "updateKeysB64"
		case trustPurposeLicense:
			ldVar = "licenseKeysB64"
		default:
			return fmt.Errorf("--purpose must be %q or %q", trustPurposeUpdate, trustPurposeLicense)
		}
		keyID := strings.TrimSpace(trustKeygenKeyID)
		if keyID == "" {
			return usageErrorf("--key-id is required (e.g. %s-2026)", purpose)
		}

		privPath := filepath.Join(trustKeygenDir, keyID+".private.pem")
		pubPath := filepath.Join(trustKeygenDir, keyID+".public.pem")

		// Refuse to clobber an existing keypair (in particular the offline private key)
		// unless --force is passed. Check BOTH paths before writing either one, so a
		// re-run without --force is a clean no-op rather than a partial overwrite.
		if !trustKeygenForce {
			for _, p := range []string{privPath, pubPath} {
				if _, statErr := os.Stat(p); statErr == nil {
					return fmt.Errorf("%s already exists — refusing to overwrite an existing signing key; use --force to overwrite", p)
				} else if !os.IsNotExist(statErr) {
					return fmt.Errorf("check %s: %w", p, statErr)
				}
			}
		}

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("marshal private key: %w", err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

		// Both at 0600 -- the private key is a signing secret; the public key need not
		// be world-readable here (it is published separately). Without --force, use the
		// O_EXCL create mode: it closes the TOCTOU window the os.Stat check above cannot
		// -- an attacker who drops in a replacement file in the gap between that check
		// and this write no longer gets it silently truncated/replaced, they get the
		// write refused (the check above remains for a fast, clear error message in the
		// non-race case; O_EXCL is the actual enforcement). --force intentionally allows
		// overwrite, so it uses the non-exclusive write instead. Sync'd since this is
		// unrecoverable key material.
		writeKey := securefiles.CreateFileSync
		if trustKeygenForce {
			writeKey = func(dir, name string, data []byte, perm os.FileMode) error {
				return securefiles.WriteFile(dir, name, data, perm)
			}
		}
		if err := writeKey(trustKeygenDir, keyID+".private.pem", privPEM, 0o600); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
		if err := writeKey(trustKeygenDir, keyID+".public.pem", pubPEM, 0o600); err != nil {
			return fmt.Errorf("write public key: %w", err)
		}

		// The embed snippet: base64 public key keyed by key-id, for the build-time -X var.
		spec := keyID + "=" + base64.StdEncoding.EncodeToString(pub)
		fmt.Printf("Generated %s signing keypair %q:\n", purpose, keyID)
		fmt.Printf("  private key: %s  (KEEP OFFLINE — never commit or ship)\n", privPath)
		fmt.Printf("  public key:  %s\n\n", pubPath)
		fmt.Printf("Embed the public key into release builds via:\n")
		fmt.Printf("  -ldflags \"-X github.com/keyorixhq/keyorix/internal/trust.%s=%s\"\n", ldVar, spec)
		return nil
	},
}

func init() {
	trustKeygenCmd.Flags().StringVar(&trustKeygenPurpose, "purpose", "", "key purpose: update | license (required)")
	trustKeygenCmd.Flags().StringVar(&trustKeygenKeyID, "key-id", "", "key identifier, e.g. update-2026 (required)")
	trustKeygenCmd.Flags().StringVar(&trustKeygenDir, "dir", ".", "directory to write the keypair into")
	trustKeygenCmd.Flags().BoolVar(&trustKeygenForce, "force", false, "overwrite an existing keypair at the target paths (dangerous)")
}
