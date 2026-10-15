// insecure_audit_skip_reads.go -- ADR-112 Amendment 4:
// storage.database.insecure_audit_skip_reads. When true, a SUCCESSFUL
// secret-value read writes no audit row; everything else stays audited. The
// read-skipping itself lives in internal/core (skipsSuccessfulReadAudit); this
// file holds the setting's name, its operator-facing wording and the
// compliance-profile refusal hook.
package config

import "fmt"

// InsecureAuditSkipReadsSettingName is the setting's canonical dotted path:
// its registry Name, its settings-diff key and the name every report uses.
const InsecureAuditSkipReadsSettingName = "storage.database.insecure_audit_skip_reads"

// InsecureAuditSkipReadsDescribe is the registry's one-line "what being in
// effect weakens", printed in the start-up WARNING and the posture deviation.
const InsecureAuditSkipReadsDescribe = "secret reads are NOT audited: a successful secret-value read writes no " +
	"audit row and no access-log row, so read history, read counts, usage reports and anomaly detection do not " +
	"see reads; writes, permission changes, authentication, denied reads and admin actions are still audited"

// ComplianceProfileGate is one compliance profile setting that, when active,
// refuses insecure_audit_skip_reads at start-up (ADR-112 Amendment 4 §3).
type ComplianceProfileGate struct {
	// Name is the profile setting's dotted config path, named in the refusal.
	Name string
	// Active reports whether the profile is in effect for cfg.
	Active func(*Config) bool
}

// complianceProfileGates lists every compliance profile setting. EMPTY today:
// Keyorix has no compliance profile setting yet. A PR that adds one registers
// it here, and then that profile refuses insecure_audit_skip_reads with no
// further wiring. TestInsecureAuditSkipReads_ComplianceProfileKeyIsGated fails
// if a compliance-profile-looking key appears in Config without an entry here,
// so the hook cannot be forgotten.
var complianceProfileGates []ComplianceProfileGate

// validateInsecureAuditSkipReads is Validate's check: insecure_audit_skip_reads
// is refused while any compliance profile is active.
func validateInsecureAuditSkipReads(c *Config) error {
	return refuseSkipReadsUnderProfiles(c, complianceProfileGates)
}

func refuseSkipReadsUnderProfiles(c *Config, gates []ComplianceProfileGate) error {
	if !c.Storage.Database.InsecureAuditSkipReads {
		return nil
	}
	for _, g := range gates {
		if g.Active(c) {
			return fmt.Errorf("%s: true is refused while the compliance profile %s is active: a compliance "+
				"profile requires every secret read to be audited; remove %s", InsecureAuditSkipReadsSettingName,
				g.Name, InsecureAuditSkipReadsSettingName)
		}
	}
	return nil
}
