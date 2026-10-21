package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// docs/security/security.txt is the source of the RFC 9116 file published at
// https://keyorix.com/.well-known/security.txt. RFC 9116 requires Contact and
// Expires, allows at most one Expires, Canonical and Preferred-Languages, and
// says Expires SHOULD be less than a year ahead. This checks those rules against
// the file in the tree.
//
// It does NOT check that the file is actually served: the marketing site is not
// in this repository (docs/security/security-txt.md).
//
// The expiry check fails on a lapsed date on purpose: an expired security.txt
// must be ignored by clients, so renewal is a release task, not a nice-to-have.
func TestSecurityTxtIsValidRFC9116(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "security", "security.txt"))
	if err != nil {
		t.Fatalf("read security.txt: %v", err)
	}
	fields := parseSecurityTxt(string(raw))

	for _, required := range []string{"Contact", "Expires", "Canonical", "Policy", "Preferred-Languages"} {
		if len(fields[required]) == 0 {
			t.Errorf("security.txt: missing %s field", required)
		}
	}
	for _, single := range []string{"Expires", "Canonical", "Preferred-Languages"} {
		if n := len(fields[single]); n > 1 {
			t.Errorf("security.txt: %s must appear at most once, found %d", single, n)
		}
	}
	for _, c := range fields["Contact"] {
		if !strings.HasPrefix(c, "mailto:") && !strings.HasPrefix(c, "https://") {
			t.Errorf("security.txt: Contact %q must be a mailto: or https: URI", c)
		}
	}
	for _, name := range []string{"Canonical", "Policy"} {
		for _, v := range fields[name] {
			if !strings.HasPrefix(v, "https://") {
				t.Errorf("security.txt: %s %q must be an https URI", name, v)
			}
		}
	}
	if got := fields["Canonical"]; len(got) == 1 && got[0] != "https://keyorix.com/.well-known/security.txt" {
		t.Errorf("security.txt: Canonical %q is not the published location", got[0])
	}

	if len(fields["Expires"]) != 1 {
		return
	}
	expires, err := time.Parse(time.RFC3339, fields["Expires"][0])
	if err != nil {
		t.Fatalf("security.txt: Expires %q is not RFC 3339: %v", fields["Expires"][0], err)
	}
	now := time.Now()
	switch {
	case !expires.After(now):
		t.Errorf("security.txt: Expires %s has passed; renew it (docs/security/security-txt.md)", expires.Format(time.RFC3339))
	case expires.After(now.AddDate(0, 0, 366)):
		t.Errorf("security.txt: Expires %s is more than a year ahead; RFC 9116 says less than one year", expires.Format(time.RFC3339))
	case expires.Before(now.AddDate(0, 0, 60)):
		t.Logf("security.txt: Expires %s is under 60 days away; renew it (docs/security/security-txt.md)", expires.Format(time.RFC3339))
	}
}

// parseSecurityTxt returns field name -> values, skipping comments and blanks.
func parseSecurityTxt(s string) map[string][]string {
	out := map[string][]string{}
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(name)] = append(out[strings.TrimSpace(name)], strings.TrimSpace(value))
	}
	return out
}
