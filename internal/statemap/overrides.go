// overrides.go — human-reviewed class decisions that survive regeneration.
//
// Classify's own output is a MACHINE verdict (a 1-hop write-count scan);
// once a human reads a "REVIEW" row's reason and decides the real class
// (e.g. "B, consume-first, verified: TestFoo_MintFailureAfterConsume"), that
// decision must never be silently overwritten the next time someone runs
// `go run ./cmd/statemapgen` after an unrelated code change. Mirrors
// docs/atomicity-exempt.tsv's own function\tclass\treason shape and its
// same guiding rule: a hand-authored classification is authoritative once
// given, and the generator's job is to APPLY it, not recompute over it.
package statemap

import (
	"os"
	"strings"
)

// Override is one human-reviewed (kind,id) -> class decision.
type Override struct {
	Class  string
	Reason string
}

// LoadOverrides reads docs/state-map/class-overrides.tsv (kind\tid\tclass\treason,
// '#'-prefixed and blank lines ignored). A missing file is not an error --
// it means no entry has been triaged yet, not that the mechanism is broken.
func LoadOverrides(path string) (map[string]Override, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Override{}, nil
		}
		return nil, err
	}
	out := map[string]Override{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) < 4 {
			continue
		}
		out[fields[0]+"\t"+fields[1]] = Override{Class: fields[2], Reason: fields[3]}
	}
	return out, nil
}

// ApplyOverrides returns a copy of entries with every (kind,id) match in
// overrides taking its class+reason from the override instead of whatever
// Classify computed. Entries with no matching override are returned
// unchanged.
func ApplyOverrides(entries []Entry, overrides map[string]Override) []Entry {
	out := make([]Entry, len(entries))
	copy(out, entries)
	for i := range out {
		if ov, ok := overrides[out[i].Kind+"\t"+out[i].ID]; ok {
			out[i].Class = ov.Class
			out[i].Reason = ov.Reason
		}
	}
	return out
}
