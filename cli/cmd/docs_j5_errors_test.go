package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// docs/operator/j5-lost-admin.md shows the CLI's refusals for a setup-only session
// ("Error: failed to list secrets: ..."). Each such line must be exactly what
// httpStatusError prints for the message and status the doc line carries, so a change to
// the CLI's wording or its "Next step" hint breaks the doc visibly. The server-side
// message text is pinned the other way round in server/middleware
// (TestJ5Doc_SetupRefusalMessagesAreQuoted).
var j5ErrorLine = regexp.MustCompile(`(?m)^Error: (failed to list secrets): (.+) \(HTTP (\d{3})\)(.*)$`)

func TestJ5Doc_ErrorLinesMatchWhatTheCLIPrints(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "operator", "j5-lost-admin.md"))
	if err != nil {
		t.Fatal(err)
	}
	lines := j5ErrorLine.FindAllStringSubmatch(string(doc), -1)
	if len(lines) < 2 {
		t.Fatalf("j5-lost-admin.md should show the 403 and the 401 refusal, found %d error line(s) with a message", len(lines))
	}
	for _, m := range lines {
		status, _ := strconv.Atoi(m[3])
		body, _ := json.Marshal(map[string]any{"message": m[2], "code": status})
		want := "Error: " + httpStatusError(m[1], status, body).Error()
		if m[0] != want {
			t.Errorf("doc line differs from the CLI's output\n doc: %s\nreal: %s", m[0], want)
		}
	}
}
