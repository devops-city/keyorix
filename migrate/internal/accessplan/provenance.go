package accessplan

import "strings"

// provenanceLinePrefix is the fixed, grep-able marker ADR-114's "Provenance and idempotency"
// section puts in a migrated Role/MachineIdentity's own free-text Description field — neither
// model has a metadata map the way Secret does, so this is the by-name-lookup idempotency key's
// stand-in. apply-access (ADR-114's write-executing command) appends exactly this line, and
// Reconcile reads it back the same way plan.BuildPlan reads Secret.Metadata's
// "migrate.source-id" key — a name match plus a provenance match means "I created this, a
// repeat run is a no-op"; a name match with no (or a different) provenance match means a
// conflict with something this tool did not create.
const provenanceLinePrefix = "migrate.source-id: "

// FormatProvenanceLine renders key as the Description line apply-access must append to every
// object it creates.
func FormatProvenanceLine(key string) string {
	return provenanceLinePrefix + key
}

// ParseProvenanceKey extracts a migrate.source-id key from a Role/MachineIdentity's stored
// Description, if present. The line may appear anywhere in the description (apply-access always
// appends it after any human-readable summary) — found=false means this object either has no
// provenance line at all, or the migration tool never wrote one, both of which Reconcile treats
// identically: "something this tool did not create."
func ParseProvenanceKey(description string) (key string, found bool) {
	for line := range strings.SplitSeq(description, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, provenanceLinePrefix); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}
