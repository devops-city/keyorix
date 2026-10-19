//go:build e2e

package journeys

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_CLIDocsAndCompletion drives the built CLI binary the way a packager or a
// shell user does (CLI-UX-1 item 4): the reference and man page it prints are the ones
// committed under docs/, and its completion scripts load in a real shell and complete this
// CLI's commands. No server is involved; the binary is the real one.
func TestJourney_CLIDocsAndCompletion(t *testing.T) {
	_, cliBin := harness.BuildBinaries(t)
	home := t.TempDir()
	env := []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "XDG_CONFIG_HOME=" + home}
	run := func(args ...string) string {
		cmd := exec.Command(cliBin, args...) // #nosec G204 -- the journey's own freshly built binary, fixed arguments
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("keyorix %s: %v", strings.Join(args, " "), err)
		}
		return string(out)
	}

	t.Run("the committed reference and man page are what the binary prints", func(t *testing.T) {
		for sub, file := range map[string]string{
			"markdown": filepath.Join("..", "..", "..", "docs", "cli-reference.md"),
			"man":      filepath.Join("..", "..", "..", "docs", "man", "keyorix.1"),
		} {
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if got := run("docs", sub); got != string(want) {
				t.Errorf("%s is stale against `keyorix docs %s`: run `make -C cli docs`", file, sub)
			}
		}
	})

	t.Run("the man page renders", func(t *testing.T) {
		man := run("docs", "man")
		if !strings.HasPrefix(man, ".TH ") || !strings.Contains(man, ".SS keyorix secret get") {
			t.Fatalf("not a man page:\n%.300s", man)
		}
		if bin, err := exec.LookPath("mandoc"); err == nil {
			cmd := exec.Command(bin, "-Tutf8") // #nosec G204 -- fixed binary found on PATH, fixed flag
			cmd.Stdin = strings.NewReader(man)
			out, err := cmd.Output()
			if err != nil || !strings.Contains(string(out), "Usage:") {
				t.Fatalf("mandoc could not render the page: %v", err)
			}
		}
	})

	t.Run("completion scripts load in the shell", func(t *testing.T) {
		for shell, check := range map[string][]string{"bash": {"bash", "-n"}, "zsh": {"zsh", "-n"}, "fish": {"fish", "--no-execute"}} {
			script := run("completion", shell)
			if len(script) < 500 {
				t.Fatalf("%s completion script too short: %d bytes", shell, len(script))
			}
			bin, err := exec.LookPath(check[0])
			if err != nil {
				t.Logf("%s not installed; script generated but not syntax-checked", shell)
				continue
			}
			cmd := exec.Command(bin, check[1:]...) // #nosec G204 -- fixed shell binary and flags
			cmd.Stdin = strings.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s rejects the completion script: %v\n%s", shell, err, out)
			}
		}
	})

	t.Run("completion offers commands and flags", func(t *testing.T) {
		if out := run("__complete", "secret", "li"); !strings.Contains(out, "list") {
			t.Errorf("`secret li<TAB>` should offer list:\n%s", out)
		}
		if out := run("__complete", "secret", "list", "--pro"); !strings.Contains(out, "--project") {
			t.Errorf("`secret list --pro<TAB>` should offer --project:\n%s", out)
		}
	})
}
