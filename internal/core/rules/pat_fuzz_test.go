package rules

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzDecodePATScopes fuzzes DecodePATScopes, which parses a PAT's stored scopes
// column back into a permission allowlist on the request-authentication path
// (patRestrictionFrom -> CurrentPATRestriction, run for every PAT-authenticated
// request). The column originates from EncodePATScopes, but a PAT row can also be
// migrated, restored from backup, or hand-edited, so the decoder treats the column
// as untrusted input.
//
// The security-critical contract is FAIL-CLOSED (#r124 PAT scope fail-open): an
// empty column means "unrestricted" (nil), but a NON-EMPTY column that cannot be
// parsed must never silently become unrestricted — it must return the non-empty
// PATScopeCorrupted sentinel so the token is denied everywhere rather than widened
// to full owner access on a corrupted/garbled row.
//
// This harness re-derives the expected branch independently from raw JSON and
// asserts: (a) Verify never panics/hangs (Guard); (b) an empty column decodes to
// nil; (c) a non-empty column that fails json.Unmarshal decodes to a NON-EMPTY
// result (fail closed), never nil/[]; (d) a cleanly-parsing column that names
// nothing ("null", "[]", a blank entry -- EncodePATScopes never emits any of
// them) decodes to the PATScopeCorrupted sentinel too (REVIEW-COVERAGE-1: before,
// it decoded to an empty list, which reads as unrestricted); (e) any other
// cleanly-parsing column mirrors what json.Unmarshal yields.
func FuzzDecodePATScopes(f *testing.F) {
	seeds := []string{
		"",                                 // empty column -> unrestricted (nil)
		"   ",                              // whitespace only -> unrestricted
		"\t\n",                             // other whitespace
		`["secrets.read"]`,                 // single scope
		`["secrets.read","secrets.write"]`, // multiple scopes
		`["secrets.read","audit.read"]`,    // realistic reporting PAT
		`[]`,                               // names nothing -> corrupted sentinel (encoder never writes it)
		"null",                             // names nothing -> corrupted sentinel
		`["a","a"]`,                        // duplicate entries
		`[""]`,                             // empty-string scope
		`["secrets.read"`,                  // truncated JSON -> corrupted sentinel
		`secrets.read`,                     // bare string, not JSON -> corrupted
		`{"scope":"x"}`,                    // JSON object, not array -> corrupted
		`[1,2,3]`,                          // array of non-strings -> corrupted
		`["a",`,                            // trailing comma / truncation
		`  ["padded"]  `,                   // valid array with surrounding whitespace
		"__corrupted__",                    // the sentinel value itself, as input
		strings.Repeat(`["x"],`, 100),      // repeated/large malformed
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		var got []string
		fuzzutil.Guard(t.Fatalf, "DecodePATScopes", func() {
			got = DecodePATScopes(raw)
		})

		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			if got != nil {
				t.Fatalf("DecodePATScopes(%q): empty column must decode to nil (unrestricted), got %#v", raw, got)
			}
			return
		}

		var parsed []string
		if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
			// FAIL-CLOSED invariant (#r124): unparseable non-empty column must NOT
			// widen the token to unrestricted; it must return a non-empty sentinel.
			if len(got) == 0 {
				t.Fatalf("SCOPE FAIL-OPEN: unparseable scopes column %q decoded to unrestricted (%#v); must fail closed to a non-empty sentinel", raw, got)
			}
			return
		}
		// A clean parse that names nothing (null, [], a blank entry) is a column
		// the encoder never writes: also the sentinel, never an empty list.
		if blankOrEmpty(parsed) {
			if !slices.Equal(got, PATScopeCorrupted) {
				t.Fatalf("SCOPE FAIL-OPEN: scopes column %q names nothing and decoded to %#v; must be the PATScopeCorrupted sentinel", raw, got)
			}
			return
		}
		if !slices.Equal(got, parsed) {
			t.Fatalf("DecodePATScopes(%q) = %#v, want %#v (must mirror json.Unmarshal on a cleanly-parsing column)", raw, got, parsed)
		}
	})
}

// FuzzDecodePATCIDRs fuzzes DecodePATCIDRs, the network-allowlist counterpart to
// DecodePATScopes. The stored AllowedCIDRs column is decoded on every
// PAT-authenticated request (CurrentPATRestriction, added by #146/#G18 to
// re-check the source-IP allowlist fresh rather than off a possibly-stale cache
// snapshot), so a decode that fails open is a network-boundary bypass.
//
// Same FAIL-CLOSED contract (#r125 PAT CIDR fail-open): empty column -> nil (no
// network restriction), but a NON-EMPTY column that fails to parse must return the
// non-empty PATCIDRCorrupted sentinel so IPInCIDRs blocks every source IP, rather
// than nil which would silently grant global network access on a corrupted row.
// DecodePATCIDRs unmarshals the raw (untrimmed) column, so this harness does too.
func FuzzDecodePATCIDRs(f *testing.F) {
	seeds := []string{
		"",                                // empty -> no restriction (nil)
		"   ",                             // whitespace only -> nil
		`["10.0.0.0/8"]`,                  // single CIDR
		`["10.0.0.0/8","192.168.0.0/16"]`, // multiple CIDRs
		`["192.168.1.1/32"]`,              // host route (v4)
		`["2001:db8::/32"]`,               // IPv6 CIDR
		`["::1/128"]`,                     // IPv6 host route
		`[]`,                              // names nothing -> corrupted sentinel
		"null",                            // names nothing -> corrupted sentinel
		`["10.0.0.0/8"`,                   // truncated -> corrupted sentinel
		`10.0.0.0/8`,                      // bare string, not JSON -> corrupted
		`["not-a-cidr"]`,                  // parses as JSON strings (decoder does not re-validate CIDRs)
		`{"cidr":"10.0.0.0/8"}`,           // object, not array -> corrupted
		`[123]`,                           // non-string array -> corrupted
		"<corrupted>",                     // the sentinel value itself, as input
		`  ["10.0.0.0/8"]  `,              // surrounding whitespace
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		var got []string
		fuzzutil.Guard(t.Fatalf, "DecodePATCIDRs", func() {
			got = DecodePATCIDRs(raw)
		})

		if strings.TrimSpace(raw) == "" {
			if got != nil {
				t.Fatalf("DecodePATCIDRs(%q): empty column must decode to nil (no restriction), got %#v", raw, got)
			}
			return
		}

		var parsed []string
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			// FAIL-CLOSED invariant (#r125): unparseable non-empty column must block
			// all networks, never decode to nil (which IPInCIDRs treats as "allow all").
			if len(got) == 0 {
				t.Fatalf("CIDR FAIL-OPEN: unparseable AllowedCIDRs column %q decoded to no restriction (%#v); must fail closed to a non-empty sentinel", raw, got)
			}
			return
		}
		if blankOrEmpty(parsed) {
			if !slices.Equal(got, PATCIDRCorrupted) {
				t.Fatalf("CIDR FAIL-OPEN: AllowedCIDRs column %q names nothing and decoded to %#v; must be the PATCIDRCorrupted sentinel", raw, got)
			}
			return
		}
		if !slices.Equal(got, parsed) {
			t.Fatalf("DecodePATCIDRs(%q) = %#v, want %#v (must mirror json.Unmarshal on a cleanly-parsing column)", raw, got, parsed)
		}
	})
}

// blankOrEmpty is the fuzz oracle's own statement of "names nothing" (kept
// separate from the decoder's namesSomething on purpose).
func blankOrEmpty(list []string) bool {
	if len(list) == 0 {
		return true
	}
	return slices.ContainsFunc(list, func(s string) bool { return strings.TrimSpace(s) == "" })
}
