package dsn

import (
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseDSNHosts fuzzes the union entry point the register-time SSRF check
// calls (core.validateAdminDSNHost). Invariants:
//
//  1. never panics or hangs on any string;
//  2. returns nil or a list of non-empty, distinct candidates;
//  3. the union never loses a reading: everything ParseDSNHostsFromKeyValue,
//     ParseDSNHostsFromURL (for a "://" string), either MySQL wrapper scan and
//     the Kubernetes JSON reading return is in it. A refactor that drops a
//     reading, or goes back to first-match, fails here before it reaches the
//     validator.
//
// Whether the union matches what the drivers dial is checked against the
// drivers themselves by internal/dynamic's FuzzDSNHostsCoverDriverHosts; this
// target stays stdlib-only so it runs at leaf-package speed.
func FuzzParseDSNHosts(f *testing.F) {
	for _, s := range []string{
		"",
		"not-a-dsn",
		"host=203.0.113.5 host=169.254.169.254 user=a",
		"host='169.254.169.254' user=a",
		"host = 169.254.169.254",
		`host=169.254.169.25\4`,
		"host='unterminated",
		"host=169.254.169.254 password=a://203.0.113.5",
		"postgres://203.0.113.5/db?host=169.254.169.254",
		"postgres://%31%36%39.254.169.254/db",
		"postgres://u@169.254.169.254,x@203.0.113.5/db",
		"postgres://203.0.113.5?a=b@169.254.169.254/db",
		"postgres://u@[64:ff9b::a9fe:a9fe]:5432,10.0.0.1:5432/db",
		"postgres://[fe80::1%25eth0]:5432/db",
		"postgres://[unterminated",
		"u:x@tcp(203.0.113.5:1)y@tcp(169.254.169.254:3306)/db",
		"user:pass@unix(/tmp/mysql.sock)/db",
		"mongodb://%31%36%39.254.169.254+:27017/",
		`{"api_server":"https://203.0.113.5,169.254.169.254"}`,
		`{"api_server":""}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var got []string
		fuzzutil.Guard(t.Fatalf, "dsn.ParseDSNHosts", func() { got = ParseDSNHosts(s) })

		if got != nil && len(got) == 0 {
			t.Fatalf("ParseDSNHosts(%q) returned an empty non-nil list", s)
		}
		seen := map[string]bool{}
		for _, h := range got {
			if h == "" {
				t.Fatalf("ParseDSNHosts(%q) returned an empty candidate: %q", s, got)
			}
			if seen[h] {
				t.Fatalf("ParseDSNHosts(%q) returned %q twice: %q", s, h, got)
			}
			seen[h] = true
		}

		var readings []string
		readings = append(readings, ParseDSNHostsFromKeyValue(s)...)
		if strings.Contains(s, "://") {
			if hs, ok := ParseDSNHostsFromURL(s); ok {
				readings = append(readings, hs...)
			}
		}
		for _, marker := range []string{"@tcp(", "@("} {
			if h, ok := ParseDSNHostFromWrapper(s, marker); ok {
				readings = append(readings, h)
			}
		}
		if h, ok := ParseDSNHostFromKubernetesConfig(s); ok {
			readings = append(readings, h)
		}
		for _, h := range readings {
			if h != "" && !slices.Contains(got, h) {
				t.Fatalf("ParseDSNHosts(%q) = %q dropped %q, which a single reading returns", s, got, h)
			}
		}
	})
}
