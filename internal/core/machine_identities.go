// machine_identities.go — non-human project identities and their lifecycle (ADR-023).
//
// A machine identity (CI runner, k8s workload, service, automation) is a
// first-class project member kept separate from human users so the Members view
// can segment the two. Lifecycle is a 4-state machine:
//
//	pending → active → suspended ⇄ active        (revoked is terminal, reachable
//	                                              from any non-revoked state)
//
// `pending` is the credential-awaiting state for the machine-token issuance
// flow (ADR-030, see machine_token.go); identities created today start
// `active`. Every transition is audited. Machine-token issuance, hashing,
// revocation, and validation are fully implemented and wired into both the
// HTTP and gRPC auth middleware.
package core

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"slices"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Machine identity types.
const (
	MachineTypeCI         = "ci"
	MachineTypeK8s        = "k8s"
	MachineTypeService    = "service"
	MachineTypeAutomation = "automation"
	MachineTypeOther      = "other"
	// MachineTypeNode identifies a credential issued to a downstream Keyorix node
	// (storage.type: remote) — see #G79. RETAINED per ADR-085 even though the
	// RemoteStorage-sync proxy tree it originally gated is deleted and
	// server/middleware/node_credential.go's RequireNodeCredential has never
	// actually gated any real route (see that file's own doc) — `keyorix machine
	// create --type node` remains a valid command, and removing the type
	// forecloses a real node component being built properly later. It carries no
	// implicit RBAC permission of its own and must never be included in any role's
	// default/admin permission bundle.
	MachineTypeNode = "node"
)

var validMachineTypes = map[string]struct{}{
	MachineTypeCI: {}, MachineTypeK8s: {}, MachineTypeService: {},
	MachineTypeAutomation: {}, MachineTypeOther: {}, MachineTypeNode: {},
}

// Machine identity states.
const (
	MachinePending   = "pending"
	MachineActive    = "active"
	MachineSuspended = "suspended"
	MachineRevoked   = "revoked"
)

// machineTransitions lists allowed next states. revoked is terminal.
var machineTransitions = map[string][]string{
	MachinePending:   {MachineActive, MachineRevoked},
	MachineActive:    {MachineSuspended, MachineRevoked},
	MachineSuspended: {MachineActive, MachineRevoked},
	MachineRevoked:   {},
}

func canTransitionMachine(from, to string) bool {
	return slices.Contains(machineTransitions[from], to)
}

// IsValidMachineTransition reports whether from->to is a legal machine-identity
// state transition (revoked is terminal). Exported so the raw-storage
// TransitionMachineIdentityStateProxy handler (server/http/handlers/machine_identities_proxy.go)
// can enforce the same legality check TransitionMachineIdentity's transaction body
// (transitionMachineInTx) applies, without duplicating machineTransitions — this is
// the one part of that check that is target-state-only (no actor/project context
// needed), unlike the cross-project guard, which is a caller-side concern that
// already ran on whichever server's core.TransitionMachineIdentity initiated the
// relayed call and cannot be meaningfully re-derived from the wire alone.
func IsValidMachineTransition(from, to string) bool {
	return canTransitionMachine(from, to)
}

// CreateMachineIdentity creates an active machine identity in a project.
func (c *KeyorixCore) CreateMachineIdentity(ctx context.Context, projectID uint, name, identityType, description, classification string, createdBy, createdByMachineID uint) (*models.MachineIdentity, error) {
	m, err := c.newMachineIdentityForCreate(projectID, name, identityType, description, classification, createdBy, createdByMachineID)
	if err != nil {
		return nil, err
	}
	// AUDIT-TX-2: the identity and its machine_identity.created row commit in
	// ONE transaction.
	var created *models.MachineIdentity
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var err error
		if created, err = tx.CreateMachineIdentity(ctx, m); err != nil {
			return fmt.Errorf("failed to create machine identity: %w", err)
		}
		c.logMachineEventOn(ctx, tgt, "machine_identity.created", created, createdBy)
		return nil
	}); err != nil {
		return nil, err
	}
	return created, nil
}

// newMachineIdentityForCreate validates the inputs and builds the row
// CreateMachineIdentity would insert, WITHOUT writing anything. Extracted
// (#2867) so MigrateUserToMachine can run the validation before it takes any
// lock, and then do the insert on a tx handle it shares with the source user's
// suspension — the two must commit or roll back together.
//
// Deliberately takes no ctx and touches no storage: everything here is pure
// validation plus field assembly, which is what makes it safe to call before a
// transaction is open. The audit event (machine_identity.created) belongs to
// whoever does the insert, after commit, and is NOT emitted here.
func (c *KeyorixCore) newMachineIdentityForCreate(projectID uint, name, identityType, description, classification string, createdBy, createdByMachineID uint) (*models.MachineIdentity, error) {
	if projectID == 0 || name == "" {
		return nil, fmt.Errorf("project ID and name are required")
	}
	if identityType == "" {
		identityType = MachineTypeOther
	}
	if _, ok := validMachineTypes[identityType]; !ok {
		return nil, fmt.Errorf("invalid identity_type %q (want ci|k8s|service|automation|other)", identityType)
	}
	if !IsValidClassification(classification) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty)")
	}
	now := c.now()
	return &models.MachineIdentity{
		ProjectID:                  projectID,
		Name:                       name,
		IdentityType:               identityType,
		State:                      MachineActive,
		Description:                description,
		Classification:             classification,
		CreatedBy:                  createdBy,
		CreatedByMachineIdentityID: createdByMachineID,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}, nil
}

// ListMachineIdentities returns the machine identities in a project.
func (c *KeyorixCore) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	return c.storage.ListMachineIdentities(ctx, projectID)
}

// ListStaleMachineIdentities returns a project's ACTIVE machine identities that have
// not authenticated within olderThan — abandoned credentials that are candidates for
// revocation (a security-hygiene aid). An identity that has never been seen counts
// from its creation time, so a freshly-created one isn't flagged until it has had the
// full window to be used. Suspended/revoked identities are excluded (already handled).
func (c *KeyorixCore) ListStaleMachineIdentities(ctx context.Context, projectID uint, olderThan time.Duration) ([]*models.MachineIdentity, error) {
	all, err := c.storage.ListMachineIdentities(ctx, projectID)
	if err != nil {
		return nil, err
	}
	cutoff := c.now().Add(-olderThan)
	var stale []*models.MachineIdentity
	for _, m := range all {
		if m.State != MachineActive {
			continue
		}
		last := m.CreatedAt
		if m.LastSeenAt != nil {
			last = *m.LastSeenAt
		}
		if last.Before(cutoff) {
			stale = append(stale, m)
		}
	}
	return stale, nil
}

// TransitionMachineIdentity advances a machine identity to a new state,
// enforcing the state machine, and audits the change. The machine must belong to
// projectID — the caller's authorization is scoped to that project, so a machine
// in another project must not be reachable through it (cross-project guard).
//
// #388: the read-check-write is done inside a transaction against a row obtained via
// LockMachineIdentityForUpdate, not a plain GetMachineIdentity — without a DB-level
// guard, two concurrent transitions racing off the same pre-transition state (e.g.
// one to revoked, one racing back to active from suspended) can each independently
// pass canTransitionMachine, and whichever write landed last would silently win
// outright, un-revoking a just-revoked machine identity. The row lock (Postgres:
// SELECT ... FOR UPDATE) serializes this across replicas; the transaction alone
// serializes it on SQLite (always single-process).
//
// Finding #518: the actual write goes through TransitionMachineIdentityState, a
// conditional "WHERE id = ? AND state = ?" persist, rather than a plain
// UpdateMachineIdentity — because storage.type: remote's RemoteStorage.WithTransaction
// was a no-op passthrough over HTTP (no real transaction/row-lock spanned the Lock
// call and the write), so a plain Lock-then-Update proxy pair would have silently
// lost the #388 guarantee entirely under remote mode. Gating the write itself on
// the state this call observed under the lock restored the guarantee across that
// HTTP hop: a lost race reports matched=false, treated identically to an illegal
// transition. This makes no behavioral difference against LocalStorage (the lock
// already guarantees the state can't have moved by the time the conditional write
// runs).
// transitionMachineInTx performs the state transition inside an existing transaction.
// It is the body of TransitionMachineIdentity's WithTransaction closure, extracted to
// keep the outer function's cognitive complexity within limits.
func (c *KeyorixCore) transitionMachineInTx(ctx context.Context, tx storage.Storage, projectID, id uint, to string, now time.Time) (*models.MachineIdentity, error) {
	m, err := tx.LockMachineIdentityForUpdate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("machine identity not found")
	}
	if m.ProjectID != projectID {
		// Cross-project guard: report as "not found" (not a permission error) to
		// avoid confirming the machine's existence to a caller scoped elsewhere.
		return nil, fmt.Errorf("machine identity not found")
	}
	fromState := m.State
	if !canTransitionMachine(fromState, to) {
		return nil, fmt.Errorf("cannot transition machine identity from %s to %s", fromState, to)
	}
	m.State = to
	m.UpdatedAt = now
	if to == MachineRevoked {
		m.RevokedAt = &now
	}
	matched, err := tx.TransitionMachineIdentityState(ctx, m, fromState)
	if err != nil {
		return nil, fmt.Errorf("failed to update machine identity: %w", err)
	}
	if !matched {
		// Lost the race: the row's persisted state moved away from fromState
		// between the lock read and this write (#388) — treat exactly like an
		// illegal transition rather than silently overwriting the winner.
		return nil, fmt.Errorf("cannot transition machine identity from %s to %s", fromState, to)
	}
	return m, nil
}

func (c *KeyorixCore) TransitionMachineIdentity(ctx context.Context, projectID, id uint, to string, actorID uint) (*models.MachineIdentity, error) {
	now := c.now()
	var result *models.MachineIdentity
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var err error
		result, err = c.transitionMachineInTx(ctx, tx, projectID, id, to, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	// Suspend or revoke must evict every credential from the auth cache
	// immediately so the identity stops authenticating on the next HTTP request
	// rather than after validTokenTTL (30s). The HTTP handler also calls
	// InvalidateTokenCacheByHash directly (defence-in-depth); this call moves
	// the eviction into the core so gRPC callers (which have no HTTP middleware
	// reference) get the same guarantee automatically (#r124).
	if to == MachineSuspended || to == MachineRevoked {
		c.evictMachineIdentityCacheOrFlush(ctx, id, to)
	}
	c.logMachineEvent(ctx, "machine_identity."+machineVerb(to), result, actorID)
	return result, nil
}

// evictMachineIdentityCacheOrFlush evicts machine identity id's credentials from the HTTP
// auth cache after its state transition to `to` has ALREADY committed (called only from
// TransitionMachineIdentity, after its WithTransaction has returned successfully) — this
// is best-effort cache immediacy, not the durable control; the transition itself already
// succeeded regardless of what happens in here.
//
// Found live by FuzzStorageFaultOperations (kind=panic on ListMachineIdentityCredentials's
// first call, input ff58003231): the previous version of this logic had no recover(), so a
// panic here — not just an error return — unwound past the already-committed transition,
// through the HTTP handler, and was caught by the outer Recovery middleware as a generic
// 500, misreporting a successful revoke/suspend as a failure (oracle (a) violation). The
// panic itself is fault-injection-only (internal/faultstorage's KindPanic, a deliberate
// resilience probe -- the fuzz harness's own way of asking "what if a storage call panics
// instead of erroring", not evidence of a real nil-pointer bug in ListMachineIdentityCredentials
// itself), but the missing recover() was real: any future genuine panic in the storage layer
// (a nil driver, a corrupted-row type assertion, anything) would have hit the exact same gap.
// This is the same failure shape evictUserSessionCache (account.go) was fixed for after
// docs/findings/2026-09-23-FINDING-breakglass-revoke-half-commit.md -- that fix recovers and
// logs but otherwise gives up on eviction; this one goes further (see below) because a missed
// machine-token eviction is reachable over gRPC too, which has no independent fallback evictor.
//
// Fail-closed on top of best-effort: when the exact credential hashes can't be determined
// (the lookup errored after one retry, or panicked), evicting nothing would leave EVERY
// credential of this identity live in cache for up to validTokenTTL after a revoke/suspend
// that already took effect in storage. Instead, flush every machine-token cache entry
// system-wide (c.machineTokenCacheFlusher) -- broader than this one identity, but bounded to
// machine principals only (human sessions/PATs are untouched), and self-healing: every
// machine principal simply re-validates against the DB (which will correctly see this
// identity's new state) on its next request.
func (c *KeyorixCore) evictMachineIdentityCacheOrFlush(ctx context.Context, id uint, to string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: machine identity %d: eviction after transition to %q panicked (state transition already committed, unaffected): %v — flushing all machine-token cache entries\n%s", id, to, r, debug.Stack())
			if c.machineTokenCacheFlusher != nil {
				c.machineTokenCacheFlusher()
			}
		}
	}()
	hashes, herr := c.MachineTokenHashes(ctx, id)
	if herr != nil {
		// CMI-3: one immediate retry before giving up — a missed eviction here
		// is not just defence-in-depth for gRPC-originated transitions (unlike
		// the HTTP handler, server/grpc/services/machine_identity_service.go's
		// TransitionMachineIdentity has no independent fallback eviction), so
		// it's worth absorbing a single transient storage blip.
		hashes, herr = c.MachineTokenHashes(ctx, id)
	}
	if herr != nil {
		// Give up on a precise eviction rather than block the already-committed state
		// transition on further storage retries, but fail CLOSED: flush every
		// machine-token cache entry so nothing of this identity's can be served from a
		// stale positive cache hit, visible to operators via the SECURITY log rather
		// than silently swallowed.
		log.Printf("SECURITY: machine identity %d: failed to evict credentials from the auth cache after transition to %q: %v — flushing all machine-token cache entries", id, to, herr)
		if c.machineTokenCacheFlusher != nil {
			c.machineTokenCacheFlusher()
		}
		return
	}
	c.invalidateTokenCache(hashes...)
}

// ClassifyMachineIdentity sets (or clears, with "") the data-classification label
// on a machine identity, project-scoped (cross-project guard), and audits the change.
func (c *KeyorixCore) ClassifyMachineIdentity(ctx context.Context, projectID, id uint, level string, actorID uint) (*models.MachineIdentity, error) {
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	m, err := c.machineInProject(ctx, projectID, id)
	if err != nil {
		return nil, err
	}
	if m.Classification == level {
		return m, nil // no-op
	}
	old := m.Classification
	fromState := m.State
	m.Classification = level
	m.UpdatedAt = c.now()
	// #G42: a blind c.storage.UpdateMachineIdentity (full-row Save) here would
	// race TransitionMachineIdentity — m was read above via machineInProject,
	// so a concurrent suspend/revoke landing between that read and this write
	// would be silently reverted (or, if this write lands first, silently
	// clobbered), resurrecting a just-revoked identity. Route through the
	// same conditional write TransitionMachineIdentity itself uses, gated on
	// the state this call actually observed.
	matched, err := c.storage.TransitionMachineIdentityState(ctx, m, fromState)
	if err != nil {
		return nil, fmt.Errorf("failed to update machine identity: %w", err)
	}
	if !matched {
		return nil, fmt.Errorf("machine identity %d: %w", m.ID, ErrMachineStateConflict)
	}
	aid, pid := actorID, m.ProjectID
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "machine_identity.classified", &aid, nil, &pid, "",
		fmt.Sprintf("machine identity %d (%s) classification set to %q", m.ID, m.Name, level), diff)
	return m, nil
}

func machineVerb(to string) string {
	switch to {
	case MachineActive:
		return "activated"
	case MachineSuspended:
		return "suspended"
	case MachineRevoked:
		return "revoked"
	default:
		return to
	}
}

func (c *KeyorixCore) logMachineEvent(ctx context.Context, eventType string, m *models.MachineIdentity, actorID uint) {
	c.logMachineEventOn(ctx, c.auditNow(), eventType, m, actorID)
}

// logMachineEventOn is logMachineEvent against an explicit audit target
// (audit_target.go) — the access-review revoke path writes a machine role
// removal's event inside the same transaction as the removal.
func (c *KeyorixCore) logMachineEventOn(ctx context.Context, tgt auditTarget, eventType string, m *models.MachineIdentity, actorID uint) {
	aid, pid := actorID, m.ProjectID
	c.writeAuditEventFullOn(ctx, tgt, eventType, &aid, nil, &pid, "",
		machineEventDescription(eventType, m))
}

// machineEventDescription words the audit description for what happened
// (the event), then appends the identity's name, type, project and current
// state so no field of the earlier "machine identity … → state" text is lost.
func machineEventDescription(eventType string, m *models.MachineIdentity) string {
	what := "machine identity event " + eventType
	switch eventType {
	case "machine_identity.created":
		what = "created machine identity"
	case "machine_identity.token_issued":
		what = "issued token for machine identity"
	case "machine_identity.token_rotated":
		what = "rotated token for machine identity"
	case "machine_identity.token_revoked":
		what = "revoked token of machine identity"
	case "machine_identity.role_granted":
		what = "granted role to machine identity"
	case "machine_identity.role_removed":
		what = "removed role from machine identity"
	case "machine_identity.oidc_bound":
		what = "bound OIDC trust to machine identity"
	case "machine_identity.oidc_unbound":
		what = "unbound OIDC trust from machine identity"
	case "machine_identity.activated":
		what = "activated machine identity"
	case "machine_identity.suspended":
		what = "suspended machine identity"
	case "machine_identity.revoked":
		what = "revoked machine identity"
	}
	return fmt.Sprintf("%s %q (%s) in project %d (state: %s)", what, m.Name, m.IdentityType, m.ProjectID, m.State)
}
