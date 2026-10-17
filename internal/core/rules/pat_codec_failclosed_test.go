package rules

import (
	"slices"
	"testing"
)

// TestDecodePAT_NonEmptyColumnThatNamesNothingFailsClosed closes the gap the
// #r124/#r125 fail-closed rule left open (REVIEW-COVERAGE-1). The rule is "an
// empty column means unrestricted; a NON-EMPTY column the token was created with
// must never widen it". EncodePATScopes/EncodePATCIDRs encode "no restriction"
// as "" and never emit `null` or `[]`, so a stored `null` or `[]` is the same
// corrupted/hand-edited/foreign-restored row as unparseable JSON -- but it
// parsed cleanly to an empty list, and patRestrictionFrom /
// server/middleware's `len(AllowedCIDRs) > 0` read an empty list as "no
// restriction": a scoped, IP-pinned PAT became an owner-equivalent token from
// any address.
func TestDecodePAT_NonEmptyColumnThatNamesNothingFailsClosed(t *testing.T) {
	for _, raw := range []string{"null", "[]", " null ", "[ ]", "\t[]\n", `[null]`, `[""]`, `["  "]`} {
		t.Run(raw, func(t *testing.T) {
			if got := DecodePATScopes(raw); !slices.Equal(got, PATScopeCorrupted) {
				t.Errorf("DecodePATScopes(%q) = %#v, want the PATScopeCorrupted sentinel (deny everything)", raw, got)
			}
			if got := DecodePATCIDRs(raw); !slices.Equal(got, PATCIDRCorrupted) {
				t.Errorf("DecodePATCIDRs(%q) = %#v, want the PATCIDRCorrupted sentinel (block every source IP)", raw, got)
			}
		})
	}
}

// The encoder never produces a column the decoder now treats as corrupted:
// every real allowlist round-trips, and "no restriction" stays "".
func TestPATCodec_RoundTripUnchanged(t *testing.T) {
	for _, scopes := range [][]string{nil, {}, {" ", ""}, {"secrets.read"}, {"secrets.read", "audit.read", "secrets.read"}} {
		enc, err := EncodePATScopes(scopes)
		if err != nil {
			t.Fatal(err)
		}
		dec := DecodePATScopes(enc)
		if enc == "" {
			if dec != nil {
				t.Errorf("scopes %q: empty encoding decoded to %#v, want nil", scopes, dec)
			}
			continue
		}
		if slices.Equal(dec, PATScopeCorrupted) {
			t.Errorf("scopes %q: encoder output %q decodes as corrupted", scopes, enc)
		}
	}
	for _, cidrs := range [][]string{nil, {""}, {"10.0.0.1"}, {"10.0.0.0/8", "2001:db8::/32"}} {
		enc, err := EncodePATCIDRs(cidrs)
		if err != nil {
			t.Fatal(err)
		}
		dec := DecodePATCIDRs(enc)
		if enc == "" {
			if dec != nil {
				t.Errorf("cidrs %q: empty encoding decoded to %#v, want nil", cidrs, dec)
			}
			continue
		}
		if slices.Equal(dec, PATCIDRCorrupted) {
			t.Errorf("cidrs %q: encoder output %q decodes as corrupted", cidrs, enc)
		}
	}
}
