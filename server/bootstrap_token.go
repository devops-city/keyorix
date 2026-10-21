package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// generatedBootstrapTokenHint is the log line printed on an uninitialised install when no
// bootstrap token was configured and one was generated for this run. The generated value is
// only ever shown masked, so the line must say how to get a token the operator actually
// holds, not point back at a variable they never set (FIRST-RUN-1).
func generatedBootstrapTokenHint(masked string) string {
	return "system not initialised — no bootstrap token was configured, so this run generated one " +
		"(first 8 + last 4 chars shown; the full value is never logged and cannot be recovered):\n" +
		"    BOOTSTRAP TOKEN: " + masked + "\n" +
		"    To create the first admin, stop the server and start it again with a token you hold: " +
		"set KEYORIX_BOOTSTRAP_TOKEN_FILE to a 0600 file containing it (`keyorix-server admin generate-secrets` creates one), " +
		"then run `keyorix system init --server <url>`"
}

// resolveBootstrapToken returns the operator-pinned bootstrap token from
// KEYORIX_BOOTSTRAP_TOKEN or the file named by KEYORIX_BOOTSTRAP_TOKEN_FILE, or
// "" when neither is set (the caller then generates a one-time token). Both set,
// or an unreadable/empty file, is an error -- never a silent fall-through to a
// generated token.
func resolveBootstrapToken() (string, error) {
	v, found, err := secretenv.Lookup("KEYORIX_BOOTSTRAP_TOKEN")
	if err != nil {
		return "", err
	}
	if !found {
		return "", nil
	}
	v = strings.TrimSpace(v)
	// The bootstrap token is the only thing standing between a fresh,
	// network-reachable server and anyone claiming its first admin over
	// POST /system/init. A generated token is 256-bit; a pinned one must not be a
	// guessable phrase. The rejected value is never echoed.
	if len(v) < minBootstrapTokenLen {
		return "", errBootstrapTokenTooShort
	}
	return v, nil
}

// minBootstrapTokenLen is the shortest operator-pinned KEYORIX_BOOTSTRAP_TOKEN
// the server starts with (Andrei, 2026-10-16).
const minBootstrapTokenLen = 32

var errBootstrapTokenTooShort = errors.New("KEYORIX_BOOTSTRAP_TOKEN too short (min 32 characters): generate one with: openssl rand -hex 32")

// wireBootstrapToken is a core wiring step (coreWiringSteps in main.go).
func wireBootstrapToken(cw *coreWiring) error {
	coreService := cw.core
	// Wire the bootstrap token that gates POST /system/init. Prefer an operator-set
	// KEYORIX_BOOTSTRAP_TOKEN (for automation); otherwise generate one and, while the
	// install is still empty, log it so the operator can complete first-boot init. This
	// closes the unauthenticated, first-caller-wins admin-claim race on a fresh, reachable
	// instance.
	bootstrapToken, btErr := resolveBootstrapToken()
	if btErr != nil {
		// Both KEYORIX_BOOTSTRAP_TOKEN and _FILE set, the file unreadable, or the pinned
		// token shorter than 32 characters: do not fall through to a generated token the
		// operator never asked for.
		return fmt.Errorf("bootstrap token: %w", btErr)
	}
	bootstrapTokenGenerated := false
	if bootstrapToken == "" {
		if t, gerr := core.GenerateBootstrapToken(); gerr == nil {
			bootstrapToken, bootstrapTokenGenerated = t, true
		} else {
			log.Printf("failed to generate a bootstrap token: %v (API system-init will be disabled)", gerr)
		}
	}
	coreService.SetBootstrapToken(bootstrapToken)
	// Let core token-revocation paths (e.g. revoking PATs on a password change) evict the
	// HTTP auth cache immediately, rather than waiting out the positive-cache TTL.
	coreService.SetTokenCacheInvalidator(middleware.InvalidateTokenCacheByHash)
	// Let a transition toward active (ReactivateUser) clear a STALE existing cache
	// entry without ever writing a new negative one for a never-cached credential —
	// see setAccountState's "becoming active" branch.
	coreService.SetTokenCacheClearer(middleware.ClearTokenCacheIfCached)
	// Fail-closed fallback for TransitionMachineIdentity when it can't determine exactly
	// which credential hashes to evict individually (see evictMachineIdentityCacheOrFlush).
	coreService.SetMachineTokenCacheFlusher(middleware.InvalidateAllMachineTokenCache)
	if needs, berr := coreService.SystemNeedsBootstrap(context.Background()); berr == nil && needs && bootstrapToken != "" {
		if bootstrapTokenGenerated {
			masked := bootstrapToken[:8] + "***" + bootstrapToken[len(bootstrapToken)-4:]
			log.Print(generatedBootstrapTokenHint(masked))
		} else {
			log.Printf("system not initialised — run `keyorix system init` with the configured KEYORIX_BOOTSTRAP_TOKEN")
		}
	}
	return nil
}
