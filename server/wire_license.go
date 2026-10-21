package main

import (
	"log"
	"strings"

	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

// loadLicenseToken reads the operator-configured license file. An unset path, or a
// file that cannot be read (missing, unreadable, or not a regular file -- a FIFO
// must not hang the boot), yields "" and a warning: the server runs the community
// baseline.
func loadLicenseToken(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	b, err := secretenv.ReadRegularFile("license file", p) // operator-configured license path; a FIFO is refused, not waited on
	if err != nil {
		log.Printf("WARNING: license file %q unreadable: %v (running community baseline)", p, err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

// wireLicenseGate is a core wiring step (coreWiringSteps in main.go).
func wireLicenseGate(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire the offline-license feature gate (ADR-065). Fail-safe throughout: a missing,
	// unreadable, or invalid license never blocks startup — the gate degrades to the
	// community baseline. A non-release build embeds no license key, so any token evaluates
	// to the baseline anyway. The gate evaluates the token freshly on every call.
	reg, terr := trust.DefaultRegistry()
	if terr != nil {
		// A malformed embedded key spec is a build/release misconfiguration; surface it,
		// but still run (no trusted keys → baseline).
		log.Printf("WARNING: trusted-key registry: %v (running community baseline)", terr)
		reg = nil
	}
	token := loadLicenseToken(cfg.License.Path)
	gate := license.NewGate(token, reg, cfg.License.DeploymentID, cfg.LicenseGrace())
	coreService.SetLicenseGate(gate)
	st := gate.Status()
	if st.Grants() {
		log.Printf("License: %s (%s) — state %s", st.Licensee, st.Plan, st.State)
	} else {
		log.Printf("License: community baseline (state %s)", st.State)
	}
	return nil
}
