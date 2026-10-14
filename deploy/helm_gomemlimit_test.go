package deploy

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// The server container's GOMEMLIMIT is derived from resources.limits.memory
// (server.goMemLimitPercent), overridable verbatim by server.goMemLimit, and
// absent when there is no limit to derive it from or the percent is 0.
//
// Not covered: that the Go runtime honours the value (that is the runtime's
// contract), or that a given percent is the right headroom for a workload.
func TestHelmServerGoMemLimit(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart render check")
	}
	re := regexp.MustCompile(`(?m)^\s+- name: GOMEMLIMIT\n\s+value: "([^"]*)"`)
	cases := []struct {
		name string
		sets []string
		want string // "" = GOMEMLIMIT absent
	}{
		{"default 85% of 512Mi", nil, "445644KiB"},
		{"2Gi limit", []string{"server.resources.limits.memory=2Gi"}, "1782579KiB"},
		{"decimal M limit", []string{"server.resources.limits.memory=500M"}, "415039KiB"},
		{"explicit override wins", []string{"server.goMemLimit=400MiB"}, "400MiB"},
		{"custom percent", []string{"server.goMemLimitPercent=50"}, "262144KiB"},
		{"percent 0 turns it off", []string{"server.goMemLimitPercent=0"}, ""},
		{"unknown unit is skipped, not guessed", []string{"server.resources.limits.memory=1e9"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"template", "kx", filepath.Join("..", "deploy", "helm", "keyorix"), "-s", "templates/server-deployment.yaml",
				"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
			for _, s := range tc.sets {
				args = append(args, "--set", s)
			}
			out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, chart path and flags
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			m := re.FindSubmatch(out)
			switch {
			case tc.want == "" && m != nil:
				t.Fatalf("GOMEMLIMIT = %q, want it absent", m[1])
			case tc.want != "" && m == nil:
				t.Fatalf("GOMEMLIMIT absent, want %q", tc.want)
			case tc.want != "" && string(m[1]) != tc.want:
				t.Fatalf("GOMEMLIMIT = %q, want %q", m[1], tc.want)
			}
		})
	}
}
