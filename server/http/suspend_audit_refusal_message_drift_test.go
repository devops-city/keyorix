package http

// SUSPEND-LOUD-1: the refusal of a clear-synced-copies suspend (SuspendAuditUnavailable)
// carries its next step ("suspend without clearing ... to cut access immediately") in the
// server's fixed message. The server tests assert core.SuspendAuditUnavailableMessage
// directly, but the CLI and web tests pin a COPY of the text in their fixtures (the CLI
// is its own module and the web is TypeScript, so neither can import the constant). This
// test fails when a fixture's copy drifts from the constant, so a reworded message cannot
// leave a client test asserting text the server no longer sends. It checks the fixtures,
// not the clients' rendering (the client tests do that against the same text).

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestSuspendAuditRefusalMessage_ClientFixturesMatchServerText(t *testing.T) {
	require.Contains(t, core.SuspendAuditUnavailableMessage, core.SuspendWithoutClearingHint,
		"the hint is the part of the message that tells the person how to cut access now")

	fixtures := []string{
		"../../cli/cmd/suspend_audit_refusal_test.go",
		"../../web/src/features/secrets/__tests__/SuspendAuditRefusal.test.tsx",
		"../../web/src/features/secrets/__tests__/SuspendSecretModal.test.tsx",
	}
	for _, f := range fixtures {
		t.Run(f, func(t *testing.T) {
			b, err := os.ReadFile(f) // #nosec G304 -- fixed in-repo test paths
			require.NoError(t, err)
			assert.Contains(t, string(b), core.SuspendAuditUnavailableMessage,
				"this fixture pins a copy of the refusal message that no longer matches core.SuspendAuditUnavailableMessage")
		})
	}
}
