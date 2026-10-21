package middleware

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

// docs/operator/j5-lost-admin.md quotes the server's refusal messages for a setup-only
// session as the CLI prints them. The CLI formats those lines
// (cli/cmd TestJ5Doc_ErrorLinesMatchWhatTheCLIPrints); this test pins the message text
// they carry to what the middleware really sends, so a reworded refusal breaks the doc check.
func TestJ5Doc_SetupRefusalMessagesAreQuoted(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "operator", "j5-lost-admin.md"))
	if err != nil {
		t.Fatal(err)
	}
	messageOf := func(rec *httptest.ResponseRecorder) string {
		var body struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Message == "" {
			t.Fatalf("no message in %q: %v", rec.Body.String(), err)
		}
		return body.Message
	}

	owed := httptest.NewRecorder()
	accountSetupRequiredResponse(owed, []string{core.SetupStepChangePassword, core.SetupStepEnrollMFA})
	done := httptest.NewRecorder()
	reauthenticationRequiredResponse(done, true)

	for name, msg := range map[string]string{
		"403 while both steps are owed":  messageOf(owed),
		"401 once the setup is complete": messageOf(done),
	} {
		if !strings.Contains(string(doc), msg) {
			t.Errorf("j5-lost-admin.md does not quote the server's %s message: %q", name, msg)
		}
	}
}
