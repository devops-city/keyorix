package cmd

// #2923: `keyorix login` tells a user without a second factor that the server is
// in ADR-112's require_mfa upgrade grace period, how long it lasts and how to
// enrol, from the profile's mfa_grace. Nothing is printed without it.

import (
	"strings"
	"testing"
)

func TestMFAGraceWarning(t *testing.T) {
	w := mfaGraceWarning(loginBody(t, "", map[string]any{
		"username":  "alice",
		"mfa_grace": map[string]any{"ends_at": "2026-11-16T09:00:00Z", "days_left": 12},
	}))
	for _, want := range []string{"12 day(s) left", "2026-11-16T09:00:00Z", "first administrator enrols MFA", "sent to MFA enrolment", "keyorix mfa enroll"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning missing %q: %q", want, w)
		}
	}
	if w := mfaGraceWarning(loginBody(t, "", map[string]any{"username": "alice"})); w != "" {
		t.Errorf("no mfa_grace, no warning; got %q", w)
	}
	if w := mfaGraceWarning([]byte("not json")); w != "" {
		t.Errorf("an unreadable profile prints nothing; got %q", w)
	}
}
