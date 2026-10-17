package main

// FIRST-RUN-1: the generated bootstrap token is logged masked, so the message must not tell
// the operator to "retrieve the full token" from a variable they never set. It has to name
// the file form and the command that creates the file.

import (
	"strings"
	"testing"
)

func TestGeneratedBootstrapTokenHint_NamesAWayForward(t *testing.T) {
	got := generatedBootstrapTokenHint("abcdefgh***wxyz")
	for _, want := range []string{
		"abcdefgh***wxyz",
		"KEYORIX_BOOTSTRAP_TOKEN_FILE",
		"admin generate-secrets",
		"cannot be recovered",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("hint missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "retrieve the full token") {
		t.Errorf("hint still sends the operator to a variable they never set:\n%s", got)
	}
}
