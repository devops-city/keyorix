package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #3141 guard: no handler may read r.RemoteAddr directly. Audit and access-log rows
// were written with the raw "ip:port" because a dozen secret handlers did; the only
// reader is clientIP (admin_impersonation.go), which canonicalizes to the bare IP.
// Scans the non-test sources of this package, so a new handler that copies the old
// `ip, ua := r.RemoteAddr, ...` line fails here.
func TestStructural_HandlersNeverReadRemoteAddrDirectly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no handler sources found (err=%v)", err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for i, line := range strings.Split(string(b), "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "//") || !strings.Contains(line, "r.RemoteAddr") {
				continue
			}
			if f == "admin_impersonation.go" && strings.Contains(line, "core.CanonicalIP(r.RemoteAddr)") {
				continue // clientIP itself
			}
			t.Errorf("%s:%d reads r.RemoteAddr directly; use clientIP(r) (bare IP, #3141): %s", f, i+1, trim)
		}
	}
	if checked < 50 {
		t.Fatalf("only %d handler sources checked; the glob is wrong", checked)
	}
}
