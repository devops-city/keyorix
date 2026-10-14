package core

import (
	"os/exec"
	"strings"
	"testing"
)

// coreIntegrationDeps is the exact set of integration packages
// internal/core's production files may still import, one entry per ADR-109
// decoupling step (docs/adr-109-core-depends-on-interfaces.md, "Order of
// work": notary, saml, rotation, dynamic, connect, encryption/KMS) plus the
// "last decoupling" (B5): internal/delivery and internal/license. A step
// that moves its integration behind internal/core/ports and wires the real
// implementation from server/main.go deletes its own entry here.
//
// notary and saml were removed at step 1, rotation at step 2, dynamic at step
// 3, connect at step 4, encryption at step 5: internal/core now depends only on
// ports.TimestampNotary/ports.VerifyReceiptFunc, ports.SAMLServiceProvider,
// ports.RotationExecutorResolver/ports.RotationPartialError,
// ports.DynamicBackendFactory/ports.DynamicBackendEngine,
// ports.ConnectorResolver/ports.RefHasDotSegment/ports.RefWithinPrefix, and
// ports.EncryptionProvider/ports.SecretAAD/ports.MFASecretAAD/
// ports.DynamicSecretConfigAAD/ports.DynamicSecretLeaseAAD, wired from
// server/main.go's DefaultIntegrations (encryption's own wiring call site,
// SetSecretValueEncryptor/SetAuthEncryptor, predates DefaultIntegrations and
// was not moved — see docs/adr-109-core-depends-on-interfaces.md's step 5
// section for why). delivery and license were removed at the "last
// decoupling" (B5): internal/core now depends only on
// ports.CredentialDelivery/ports.SetupLinkRequest/ports.DeliveryResult/
// ports.ChannelOutOfBand and ports.LicenseGate/ports.LicenseStatus/
// ports.LicenseState*/ports.FeatureBilling, wired from SetCredentialDelivery/
// SetLicenseGate exactly as before (both predate DefaultIntegrations and stay
// their own call sites in server/main.go, same as encryption's). Unlike the
// original six, license's own wiring doesn't reach through internal/license
// at all — internal/core/ports aliases straight to pkg/licenseverify, the
// public leaf package internal/license itself was already just a thin
// re-export of (see ports_license.go's own doc comment); delivery still goes
// through internal/delivery as its own package, unlike license, since
// internal/delivery has real implementations (SMTP, out-of-band, log) with
// no leaf-package equivalent to alias to directly. coreIntegrationDeps is
// EMPTY as of B5 — every one of these eight is now behind ports —
// machine-checked by TestCoreIntegrationDepsAllowlistIsEmpty below, not just
// implied by the map literal having no entries. All eight prefixes stay in
// the scan below (see present's HasPrefix checks) so a regression back to
// any of them is still caught by the "not on the allowlist" branch, not
// silently dropped from the scan.
//
// The comparison below is an EXACT match, not a ceiling: it also fails if an
// entry is deleted from this list without the corresponding import actually
// being removed from internal/core, or vice versa — so a step that forgets
// to touch this file when it's done (or claims done before it actually is)
// is caught, not just growth beyond what's listed.
//
// internal/connect/connecttypes is deliberately NOT on this list — it is a
// types-only sibling package with no SDK dependency (see the identical
// carve-out in internal/i18n/deps_guard_test.go), and ADR-109 has no reason
// to ever remove it from internal/core. It still appears in go list -deps
// after step 4/5 (reached via internal/encryption -> internal/config, not via
// internal/connect itself, which no longer appears at all) — the exclusion
// is keyed on the exact connecttypes import path, not on whether connect is
// still present, so it stays correct either way.
var coreIntegrationDeps = map[string]bool{}

// TestCoreIntegrationDepsAllowlistIsEmpty asserts the ADR-109 "Definition of
// done" claim directly (docs/adr-109-core-depends-on-interfaces.md: "go list
// -deps ./internal/core (production) contains no cloud SDK and no integration
// package") rather than leaving it as something a reader has to infer from
// coreIntegrationDeps having no entries. A future edit that re-adds an entry
// to coreIntegrationDeps (to make room for a regression, or a new integration
// ADR-109 didn't anticipate) fails this test immediately, forcing that choice
// to be deliberate and visible in review rather than a silent widening.
func TestCoreIntegrationDepsAllowlistIsEmpty(t *testing.T) {
	if len(coreIntegrationDeps) != 0 {
		t.Errorf("coreIntegrationDeps should be empty as of B5 (every integration, including delivery/license, behind ports) — got %d entries: %v", len(coreIntegrationDeps), coreIntegrationDeps)
	}
}

// TestCoreIntegrationDepsMatchADR109Allowlist fails if internal/core's
// production dependency graph drifts from coreIntegrationDeps in either
// direction. It runs `go list -deps` (production deps only, test files
// excluded) and skips when the go tool isn't available.
func TestCoreIntegrationDepsMatchADR109Allowlist(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	out, err := exec.Command("go", "list", "-deps", "github.com/keyorixhq/keyorix/internal/core").Output()
	if err != nil {
		t.Fatalf("go list -deps internal/core: %v", err)
	}
	present := map[string]bool{}
	for dep := range strings.FieldsSeq(string(out)) {
		if dep == "github.com/keyorixhq/keyorix/internal/connect/connecttypes" {
			continue
		}
		if strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/connect") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/rotation") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/dynamic") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/encryption") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/notary") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/saml") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/delivery") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/license") {
			present[dep] = true
		}
	}
	for dep := range coreIntegrationDeps {
		if !present[dep] {
			t.Errorf("internal/core no longer imports %s: an ADR-109 step finished it — shrink coreIntegrationDeps to match", dep)
		}
	}
	for dep := range present {
		if !coreIntegrationDeps[dep] {
			t.Errorf("internal/core imports %s, which is not on the ADR-109 allowlist (coreIntegrationDeps)", dep)
		}
	}
}
