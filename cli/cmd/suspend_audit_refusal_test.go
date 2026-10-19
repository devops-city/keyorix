package cmd

import (
	"strings"
	"testing"
)

// SUSPEND-HINT-1: a clear-synced-copies suspend refused because the audit log cannot record
// it answers HTTP 500 with the stable code SuspendAuditUnavailable. The CLI must print the
// server's reason AND the command that cuts access now (the same suspend, without the flag).
// The cli module cannot import internal/core, so the wire values are pinned here; the
// server side asserts the same pair (server/http/secret_suspend_clear_copies_audit_test.go).
var suspendAuditRefusal = readRefusal{
	status:  500,
	code:    "SuspendAuditUnavailable",
	message: "The audit log could not record this suspension, so clearing synced copies was refused. Retry, or suspend without clearing synced copies to cut access immediately; clearing needs the audit log back.",
}

func wantSuspendRefusalOutput() []string {
	return []string{
		suspendAuditRefusal.message,
		"(HTTP 500)",
		"Next step:",
		"without `--clear-synced-copies`",
		"cut access now",
	}
}

func TestSecretSuspend_AuditRefusalShowsHintAndPlainSuspendCommand(t *testing.T) {
	refusingServer(t, suspendAuditRefusal)
	oldID, oldClear := secretSuspendID, secretSuspendClearCopies
	t.Cleanup(func() { secretSuspendID, secretSuspendClearCopies = oldID, oldClear })
	secretSuspendID, secretSuspendClearCopies = 7, true

	var err error
	out := captureStdout(t, func() { err = secretSuspendCmd.RunE(secretSuspendCmd, nil) })
	if err == nil {
		t.Fatalf("want an error, got output %q", out)
	}
	for _, w := range wantSuspendRefusalOutput() {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("error %q does not contain %q", err, w)
		}
	}
	if strings.Contains(out, "suspended") {
		t.Fatalf("a refused suspend must not print the success line: %q", out)
	}
}

func TestProjectSuspendSecrets_AuditRefusalShowsHintAndPlainSuspendCommand(t *testing.T) {
	refusingServer(t, suspendAuditRefusal)
	oldID, oldClear := projectFreezeID, projectFreezeClearCopies
	t.Cleanup(func() { projectFreezeID, projectFreezeClearCopies = oldID, oldClear })
	projectFreezeID, projectFreezeClearCopies = 3, true

	var err error
	out := captureStdout(t, func() { err = projectSuspendSecretsCmd.RunE(projectSuspendSecretsCmd, nil) })
	if err == nil {
		t.Fatalf("want an error, got output %q", out)
	}
	for _, w := range wantSuspendRefusalOutput() {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("error %q does not contain %q", err, w)
		}
	}
}

// The hint names a flag; it must exist on both commands.
func TestSuspendAuditRefusalHint_NamesRealFlag(t *testing.T) {
	for _, path := range [][]string{{"secret", "suspend"}, {"project", "suspend-secrets"}} {
		cmd, _, err := rootCmd.Find(path)
		if err != nil || cmd == nil || cmd.Name() != path[len(path)-1] {
			t.Fatalf("`keyorix %s` is not registered: %v", strings.Join(path, " "), err)
		}
		if cmd.Flags().Lookup("clear-synced-copies") == nil {
			t.Fatalf("`keyorix %s` has no --clear-synced-copies flag, which the refusal hint names", strings.Join(path, " "))
		}
	}
}
