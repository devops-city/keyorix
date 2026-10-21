// account_sessions.go — admin force-logout: revoke every active session of a user
// without changing their account state. Distinct from suspension (which also drops
// sessions but blocks login): use this when a user's sessions may be compromised
// (stolen laptop, leaked token) but the account should stay active once they
// re-authenticate. Complements offboarding ([[secret_orphaned]]) and PAT hygiene
// ([[pat_hygiene]]) — the human-session half of cutting off access. Admin-only
// (route-gated users.write); audited.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// EventUserSessionsRevoked is audited when an admin force-logs-out a user.
const EventUserSessionsRevoked = "account.sessions_revoked"

// testRevokeUserSessionsPreInvalidate, when non-nil, is invoked by
// RevokeUserSessions immediately after DeleteSessionsForUserExcept has
// committed and before invalidateTokenCache runs. Test-only seam (always nil
// in production) for deterministically forcing the exact interleaving a
// descheduled/delayed invalidate call can hit — see
// server/http/session_revoke_race_test.go.
var testRevokeUserSessionsPreInvalidate func()

// SetTestRevokeUserSessionsPreInvalidateHook installs testRevokeUserSessionsPreInvalidate.
// Exported (mirrors SetTokenCacheInvalidator) so a cross-package test
// (server/http, which cannot see this package's unexported var directly) can
// force the exact DELETE-committed/pre-invalidate interleaving; production
// code never calls this.
func SetTestRevokeUserSessionsPreInvalidateHook(fn func()) {
	testRevokeUserSessionsPreInvalidate = fn
}

// RevokeUserSessions terminates every active session belonging to userID, returning
// the number revoked. The account state is left unchanged — the user can log back in.
// adminID is the actor (for the audit trail); a non-zero, non-self adminID must
// also hold the admin-rank ceiling requireAdminRankCeilingForTarget enforces (S1
// sweep, CLI-split inventory #2012) -- force-logging-out a HIGHER-privileged
// account is a real DoS lever for a mere users.write holder even though it
// grants no new access itself.
func (c *KeyorixCore) RevokeUserSessions(ctx context.Context, adminID, userID uint) (int, error) {
	if userID == 0 {
		return 0, fmt.Errorf("user ID is required")
	}
	if adminID != userID {
		if err := c.requireAdminRankCeilingForTarget(ctx, adminID, userID, "revoke the sessions of"); err != nil {
			return 0, err
		}
	}
	if _, err := c.storage.GetUser(ctx, userID); err != nil {
		return 0, fmt.Errorf("user not found: %w", err)
	}

	// #G06: the eviction list must be built from the SAME (user_id=? OR
	// impersonated_by=?) predicate DeleteSessionsForUserExcept below actually
	// deletes with — ListSessionsByUser only matches user_id, so a session this
	// user STARTED as an impersonator (impersonated_by = userID) was deleted from
	// the DB but never evicted from the auth cache, leaving it live until the
	// positive-cache TTL expired. ListSessionTokenHashesForUser already unions
	// both predicates (it backs the same eviction need on other state-change
	// paths) and returns the exact session_token hashes invalidateTokenCache needs.
	tokens, err := c.storage.ListSessionTokenHashesForUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to list sessions: %w", err)
	}
	n := len(tokens)
	// exceptID 0 matches no session, so this drops them all.
	//
	// AUDIT-TX-3: a revocation: its row is owed from this transaction and appended
	// after the eviction below, so the audit log never delays the force-logout.
	aid := adminID
	settle, err := c.runOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.DeleteSessionsForUserExcept(ctx, userID, 0); err != nil {
			return fmt.Errorf("failed to revoke sessions: %w", err)
		}
		c.writeAuditEventFullOn(ctx, tgt, EventUserSessionsRevoked, &aid, nil, nil, "",
			fmt.Sprintf("revoked %d active session(s) for user %d", n, userID))
		return nil
	})
	if err != nil {
		return 0, err
	}
	if testRevokeUserSessionsPreInvalidate != nil {
		testRevokeUserSessionsPreInvalidate()
	}
	// Evict every revoked session from the HTTP auth cache so a compromised token stops
	// authenticating on the NEXT request instead of lingering for the positive-cache TTL
	// — this is the incident-response control, so the residual window matters. The stored
	// session_token IS the SHA-256 cache key.
	c.invalidateTokenCache(tokens...)
	settle()
	return n, nil
}
