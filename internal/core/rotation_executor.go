// rotation_executor.go — automated secret rotation (ADR-046). Rotation policies say
// WHEN a secret should rotate and reminders nudge admins; this executor actually
// rotates the secrets that opted in (SecretNode.AutoRotate) by regenerating their
// value when they are overdue under an active covering policy.
//
// Only auto-rotate-enabled secrets are touched, and the new value is a freshly
// generated random string — so this is for secrets whose value Keyorix owns. A secret
// that mirrors an external system's credential must NOT enable auto-rotation, since
// regenerating it here does not update the upstream.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventAutoRotationFailures is audited once per run when one or more secrets failed.
const EventAutoRotationFailures = "rotation.failures_alerted"

// EventSecretRotateFailed and EventSecretRotateIncomplete are audited by
// RotateSecretOnDemand (#193) when a manual/operator-triggered rotation of a
// backend-bound secret fails outright, or partially completes (new credential minted
// but a prior one survived upstream), respectively — distinct from the plain
// "secret.rotated" success event so an operator can find and act on them.
//
// EventSecretRotateBackendStarted is emitted immediately before calling the upstream
// rotation backend (ROTATION-001: crash-recovery observability). If the server crashes
// after upstream rotation succeeds but before RotateSecret stores the new value, the
// audit trail will contain a "started" event without any subsequent completion or
// failure event — an operator scanning for orphaned "started" events can identify
// secrets that need manual reconciliation (the upstream may have a new credential
// while Keyorix still holds the old one).
const (
	EventSecretRotateFailed         = "secret.rotate_failed"
	EventSecretRotateIncomplete     = "secret.rotate_incomplete"
	EventSecretRotateBackendStarted = "secret.rotate_backend_started"
)

// notifyRotationFailures broadcasts a single summary of ONE project's rotation
// failures to the configured deployment-wide notification channel (Slack/Teams/
// webhook/email) — a silently-failed credential rotation is a security event
// operators must see. Scoped to a single project: the caller (RunAutoRotation) calls
// this once per project rather than once per run, so a broadcast never bundles
// unrelated projects' secret names/failure reasons into one message (#391) — a
// deployment-wide channel is still an appropriate destination for this event (unlike
// the per-user events in notifications.go), it just must not cross project
// boundaries within a single message. No-op when nothing failed for this project;
// the sink is non-blocking. If every configured channel is a no-op for this event
// (e.g. an email-only deployment with no broadcast destination configured, #221),
// that is logged so the gap is discoverable — this alert is the only signal an
// operator gets that auto-rotation is silently failing, separate from the
// EventAutoRotationFailures audit row the caller writes for the rotation failure
// itself (which is accurate regardless of whether this alert lands).
func (c *KeyorixCore) notifyRotationFailures(ctx context.Context, projectID uint, failed map[uint]rotationFailureDetail) {
	if len(failed) == 0 || c.notificationSink == nil {
		return
	}
	// Allowlist: only the secret name reaches the external message. Deliberately
	// NOT interpolating f.Detail here — it may carry the upstream backend name,
	// ref, and raw error text, which must not reach a third-party webhook/chat
	// sink (Group 1 fix). That detail stays in the audit trail and rotation-state
	// API, both internal to Keyorix.
	lines := make([]string, 0, len(failed))
	for _, f := range failed {
		lines = append(lines, fmt.Sprintf("• rotation failed for secret %q", f.SecretName))
	}
	sort.Strings(lines) // stable, deterministic ordering
	pid := projectID
	attempted := c.notificationSink.Deliver(NotificationEvent{
		Type:      "rotation.failed",
		Title:     fmt.Sprintf("Auto-rotation: %d secret(s) failed to rotate in %s", len(failed), c.projectLabel(ctx, projectID)),
		Message:   "The following secrets could not be auto-rotated:\n" + strings.Join(lines, "\n"),
		ProjectID: &pid,
		Link:      fmt.Sprintf("/projects/%d/secrets", projectID),
	})
	if !attempted {
		log.Printf("rotation: %d secret(s) failed to rotate in project %d, but no configured notification channel could accept the alert (e.g. email-only with no broadcast destination) — the alert was NOT delivered", len(failed), projectID)
	}
}

// SetRotationManager wires the configured backend rotation executors (ADR-047) that
// apply a new credential to an upstream system. nil (the default) leaves backend
// rotation disabled — auto-rotation then only regenerates Keyorix-owned values.
func (c *KeyorixCore) SetRotationManager(m ports.RotationExecutorResolver) {
	c.rotationManager = m
}

// RotationBackendNames lists the configured rotation-backend names (for discovery).
func (c *KeyorixCore) RotationBackendNames() []string {
	if c.rotationManager == nil {
		return nil
	}
	return c.rotationManager.Names()
}

// Audit events for automated rotation (ADR-046).
const (
	EventSecretAutoRotated      = "secret.auto_rotated"
	EventSecretAutoRotateConfig = "secret.auto_rotate_configured"
)

// Default generated value: 32 chars over a 62-symbol alphanumeric set (~190 bits).
// Alphanumeric so a consumer reading it back never trips over shell/URL metacharacters.
const (
	rotatedValueLength    = 32
	rotatedValueMinLength = 8
	rotatedValueMaxLength = 256
)

// Named charsets a secret may select via RotationCharset (ADR-046). "" = alphanumeric.
const (
	charsetAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	charsetLowerAlnum   = "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetHex          = "0123456789abcdef"
	charsetAlnumSymbols = charsetAlphanumeric + "!@#$%^&*-_=+"
	rotatedValueCharset = charsetAlphanumeric // back-compat alias (default)
)

// resolveCharset maps a RotationCharset name to its character set, defaulting to
// alphanumeric for "" or an unknown name (fail-safe: never an empty alphabet).
func resolveCharset(name string) string {
	switch name {
	case "lower_alphanumeric":
		return charsetLowerAlnum
	case "hex":
		return charsetHex
	case "alphanumeric_symbols":
		return charsetAlnumSymbols
	default:
		return charsetAlphanumeric
	}
}

// resolveLength clamps a requested length into [min,max], defaulting to 32 for 0.
func resolveLength(n int) int {
	if n <= 0 {
		return rotatedValueLength
	}
	if n < rotatedValueMinLength {
		return rotatedValueMinLength
	}
	if n > rotatedValueMaxLength {
		return rotatedValueMaxLength
	}
	return n
}

// generateRotatedValue returns a fresh random value of the default shape (crypto/rand).
func generateRotatedValue() (string, error) {
	return generateRotatedValueSpec(0, "")
}

// generateRotatedValueSpec returns a fresh random value of the requested length and
// charset (crypto/rand), applying the defaults/clamping above.
func generateRotatedValueSpec(length int, charset string) (string, error) {
	n := resolveLength(length)
	set := resolveCharset(charset)
	b := make([]byte, n)
	for i := range b {
		ch, err := randChar(set)
		if err != nil {
			return "", err
		}
		b[i] = ch
	}
	return string(b), nil
}

// dueRotation is a secret that is due for auto-rotation this run, with the policy it is
// due under (for the audit trail).
type dueRotation struct {
	secret *models.SecretNode
	policy *models.RotationPolicy
}

// rotationFailureDetail records why a single secret's auto-rotation attempt
// did not succeed this run (a genuine failure, a dependency-driven deferral,
// or an upstream-incomplete partial rotation). SecretName alone is safe to
// broadcast to an external channel (notifyRotationFailures uses only this
// field for NotificationEvent.Message). Detail may additionally carry the
// upstream RotationBackend name, its RotationRef (an IAM username/DB role/
// service-account email), and the raw upstream error text — this is exactly
// the kind of backend/connection detail that must stay internal (the audit
// trail via writeAuditEventFull, and the rotation-state API), never reach a
// third-party webhook/chat sink (Group 1 fix).
type rotationFailureDetail struct {
	SecretName string
	Detail     string
}

// RunAutoRotation rotates every auto-rotate-enabled secret that is overdue under an
// active rotation policy, regenerating its value (a new version) and auditing each
// rotation. A secret covered by multiple policies is rotated at most once per run.
//
// Rotations are ordered by the secret dependency graph (ADR-052): within a project a
// secret rotates only after the secrets it depends on, mirroring the dependency-safe
// waves the rotation planner computes (ADR-053). When a dependency does NOT rotate this
// run — it failed, or was itself deferred — the dependent is DEFERRED rather than
// rotated against a now-stale dependency (dependency-first auto-rotation), and audited
// so an operator can act. Otherwise best-effort per secret: a generate/rotate failure is
// logged and skipped, never aborting the run. Returns the number of secrets rotated.
func (c *KeyorixCore) RunAutoRotation(ctx context.Context) (int, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, nil, nil)
	if err != nil {
		return 0, fmt.Errorf("auto-rotation: list policies: %w", err)
	}
	due, dueOrder := c.collectDueRotations(ctx, policies, c.now())
	if len(due) == 0 {
		return 0, nil
	}
	byProject, projectOrder := groupDueByProject(due, dueOrder)
	rotated := 0
	for _, pid := range projectOrder {
		r, _ := c.rotateProject(ctx, pid, byProject[pid], due)
		rotated += r
	}
	return rotated, nil
}

// collectDueRotations gathers all auto-rotate-enabled secrets overdue under any active
// policy this run. A secret covered by several policies is rotated at most once, under
// the first active policy it is due under (first-policy-wins). dueOrder preserves
// discovery order so project grouping in the caller is deterministic.
func (c *KeyorixCore) collectDueRotations(ctx context.Context, policies []*models.RotationPolicy, now time.Time) (map[uint]*dueRotation, []uint) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- policies is admin-configured rotation policies fetched from storage, not a raw client-supplied array in one request
	due := map[uint]*dueRotation{}
	var dueOrder []uint
	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}
		c.collectPolicySecrets(ctx, policy, now, due, &dueOrder)
	}
	return due, dueOrder
}

// collectPolicySecrets appends to due/dueOrder the secrets that are overdue under
// policy. Skips secrets already seen under an earlier policy (dedup by secret ID).
// #364: a list error logs and skips the policy rather than silently losing coverage.
func (c *KeyorixCore) collectPolicySecrets(ctx context.Context, policy *models.RotationPolicy, now time.Time, due map[uint]*dueRotation, dueOrder *[]uint) {
	secrets, err := c.scopedPolicySecrets(ctx, policy, nil)
	if err != nil {
		log.Printf("auto-rotation: list scoped secrets for policy %d (%q): %v — skipping this policy's secrets this run", policy.ID, policy.Name, err)
		return
	}
	for _, secret := range secrets {
		if !secret.AutoRotate || due[secret.ID] != nil {
			continue
		}
		lastRotated := secret.CreatedAt
		if secret.LastRotatedAt != nil {
			lastRotated = *secret.LastRotatedAt
		}
		if int(now.Sub(lastRotated).Hours()/24) < policy.IntervalDays {
			continue
		}
		due[secret.ID] = &dueRotation{secret: secret, policy: policy}
		*dueOrder = append(*dueOrder, secret.ID)
	}
}

// groupDueByProject partitions the due-rotation map into per-project slices, preserving
// discovery order. Rotation dependencies are per-project (ADR-052 edges never cross
// a project boundary), so ordering is computed per project in the caller.
func groupDueByProject(due map[uint]*dueRotation, dueOrder []uint) (map[uint][]uint, []uint) {
	byProject := map[uint][]uint{}
	var projectOrder []uint
	for _, id := range dueOrder {
		pid := due[id].secret.ProjectID
		if _, ok := byProject[pid]; !ok {
			projectOrder = append(projectOrder, pid)
		}
		byProject[pid] = append(byProject[pid], id)
	}
	return byProject, projectOrder
}

// rotateProject rotates all due secrets for one project in dependency-safe wave order
// (ADR-052/ADR-053). Returns (rotated count, failure count).
func (c *KeyorixCore) rotateProject(ctx context.Context, pid uint, ids []uint, due map[uint]*dueRotation) (rotated, failures int) {
	candidateSet := make(map[uint]bool, len(ids))
	for _, id := range ids {
		candidateSet[id] = true
	}
	edges, eerr := c.storage.ListSecretDependenciesForProject(ctx, pid)
	if eerr != nil {
		// Can't determine dependency order; degrade to a flat best-effort pass (no deferral).
		log.Printf("auto-rotation: list dependencies for project %d: %v — rotating without dependency ordering", pid, eerr)
		edges = nil
	}
	waves, ok := rotationWaves(edges, candidateSet)
	if !ok {
		// A cycle should not occur (graph kept acyclic at add, ADR-052). Fall back to a
		// single flat wave with deferral disabled so a malformed graph never blocks rotation.
		log.Printf("auto-rotation: dependency graph for project %d has a cycle — rotating without dependency ordering", pid)
		flat := append([]uint(nil), ids...)
		slices.Sort(flat)
		waves = [][]uint{flat}
		edges = nil
	}
	// In-run dependencies per secret (edges between due secrets in this project only).
	dependsOnInRun := map[uint][]uint{}
	for _, e := range edges {
		if candidateSet[e.DependentSecretID] && candidateSet[e.DependsOnSecretID] {
			dependsOnInRun[e.DependentSecretID] = append(dependsOnInRun[e.DependentSecretID], e.DependsOnSecretID)
		}
	}
	// failed records why each non-rotated secret in THIS project did not rotate (genuine
	// failure or dependency-driven deferral). Scoped to this project only (#391) and
	// broadcast right after this project finishes, before moving on to the next.
	failed, n := c.rotateProjectWaves(ctx, waves, due, dependsOnInRun)
	c.notifyRotationFailures(ctx, pid, failed)
	if len(failed) > 0 {
		// #G23: scoped to this project (pid is known here, unlike the old
		// run-wide summary this replaced, which had to write ProjectID=nil
		// because it aggregated failures across every project in the run).
		sysCtx := WithActorType(ctx, ActorTypeSystem)
		p := pid
		c.writeAuditEventFull(sysCtx, EventAutoRotationFailures, nil, nil, &p, "",
			fmt.Sprintf("auto-rotation: %d secret(s) failed to rotate in project %d", len(failed), pid))
	}
	return n, len(failed)
}

// rotateProjectWaves rotates secrets in dependency-ordered waves. A secret whose
// dependency did not rotate this run is DEFERRED rather than rotated against a stale
// dependency. Returns (failures, rotated count).
func (c *KeyorixCore) rotateProjectWaves(ctx context.Context, waves [][]uint, due map[uint]*dueRotation, dependsOnInRun map[uint][]uint) (failed map[uint]rotationFailureDetail, rotated int) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- waves is computed internally by the rotation scheduler from due secrets in this project, not a raw client-supplied array
	failed = map[uint]rotationFailureDetail{}
	blocked := map[uint]bool{}
	for _, wave := range waves {
		for _, id := range wave {
			dr := due[id]
			if depID, isBlocked := lowestBlockedDep(dependsOnInRun[id], blocked); isBlocked {
				blocked[id] = true
				depName := ""
				if d, ok := due[depID]; ok {
					depName = d.secret.Name
				}
				sid := id
				pid := dr.secret.ProjectID
				c.writeAuditEventFull(ctx, EventSecretAutoRotated, nil, &sid, &pid, "",
					fmt.Sprintf("auto-rotation DEFERRED for secret %q: it depends on %q which did not rotate this run", dr.secret.Name, depName))
				failed[id] = rotationFailureDetail{
					SecretName: dr.secret.Name,
					Detail:     fmt.Sprintf("deferred — depends on %q which did not rotate this run", depName),
				}
				continue
			}
			if c.rotateOneSecret(ctx, dr.secret, dr.policy, failed) {
				rotated++
			} else {
				blocked[id] = true
			}
		}
	}
	return
}

// lowestBlockedDep returns the lowest-id dependency that is in blocked (and true), or
// 0/false if none of deps is blocked. Lowest-id makes the chosen dependency — and thus
// the deferral audit message — deterministic when several dependencies are blocked.
func lowestBlockedDep(deps []uint, blocked map[uint]bool) (uint, bool) {
	found := false
	var lowest uint
	for _, d := range deps {
		if blocked[d] && (!found || d < lowest) {
			found, lowest = true, d
		}
	}
	return lowest, found
}

// rotateOneSecret performs the actual rotation of a single due secret: generate a new
// value, optionally apply it to the configured backend (ADR-047) before storing so the
// two never drift, store the new version, and audit the outcome. Any failure is recorded
// in failed and logged; it returns true only when the secret was rotated and stored
// successfully. Best-effort: it never returns an error or aborts the run.
func (c *KeyorixCore) rotateOneSecret(ctx context.Context, secret *models.SecretNode, policy *models.RotationPolicy, failed map[uint]rotationFailureDetail) bool {
	// #G43: SetRotationState/GetRotationState (rotation_state.go) were fully
	// wired at the storage layer and exposed via GET /secrets/{id}/rotation-state,
	// with a doc comment claiming "called by the rotation executor when a
	// rotation job starts, completes, or fails" — but nothing here ever actually
	// called it, so the endpoint always reported "idle" regardless of real
	// activity. Best-effort: a failure to stamp state must not abort a
	// rotation that otherwise succeeded or genuinely failed.
	c.stampRotationState(ctx, policy.ID, RotationStateRotating, "")
	val, gerr := generateRotatedValueSpec(secret.RotationLength, secret.RotationCharset)
	if gerr != nil {
		log.Printf("auto-rotation: generate value for secret %d: %v", secret.ID, gerr)
		failed[secret.ID] = rotationFailureDetail{SecretName: secret.Name, Detail: fmt.Sprintf("generate value: %v", gerr)}
		c.stampRotationState(ctx, policy.ID, RotationStateFailed, failed[secret.ID].Detail)
		return false
	}
	// Backend rotation (ADR-047): if the secret names a configured executor, rotate the
	// credential UPSTREAM first and store the resulting value only on success. For a
	// generate-upstream backend (e.g. a cloud key API) the stored value is what the
	// upstream minted; for a password-set backend it is the candidate we generated. A
	// backend that is unconfigured/unknown or whose upstream apply fails is skipped.
	storeVal := val
	incompleteMsg := ""
	if secret.RotationBackend != "" {
		// ROTATION-001: emit before calling upstream so a crash between upstream success
		// and Keyorix store is visible in the audit trail as an orphaned "started" event.
		sid := secret.ID
		pid := secret.ProjectID
		c.writeAuditEventFull(ctx, EventSecretRotateBackendStarted, nil, &sid, &pid, "",
			fmt.Sprintf("auto-rotation: calling upstream backend %q ref %q for secret %q",
				secret.RotationBackend, secret.RotationRef, secret.Name))
		upstreamVal, err := c.applyBackendRotation(ctx, secret, val)
		var partial *ports.RotationPartialError
		switch {
		case errors.As(err, &partial):
			// The upstream minted the new credential but a prior, possibly compromised one
			// could not be removed. Store the new value (a cloud key API returns the key
			// material only once, so discarding it would orphan a live key) but flag the
			// rotation incomplete below so the run records a failure and alerts an operator
			// to remove the leftover.
			storeVal = partial.Value
			incompleteMsg = fmt.Sprintf("via backend %q ref %q: %v", secret.RotationBackend, secret.RotationRef, err)
		case err != nil:
			sid := secret.ID
			pid := secret.ProjectID
			c.writeAuditEventFull(ctx, EventSecretAutoRotated, nil, &sid, &pid, "",
				fmt.Sprintf("auto-rotation FAILED for secret %q via backend %q ref %q: %v", secret.Name, secret.RotationBackend, secret.RotationRef, err))
			log.Printf("auto-rotation: backend rotate secret %d: %v", secret.ID, err)
			failed[secret.ID] = rotationFailureDetail{
				SecretName: secret.Name,
				Detail:     fmt.Sprintf("via backend %q ref %q: %v", secret.RotationBackend, secret.RotationRef, err),
			}
			c.stampRotationState(ctx, policy.ID, RotationStateFailed, failed[secret.ID].Detail)
			return false
		default:
			storeVal = upstreamVal
		}
	}
	if _, rerr := c.RotateSecret(ctx, secret.ID, []byte(storeVal), 0, "system:auto-rotation"); rerr != nil {
		log.Printf("auto-rotation: rotate secret %d: %v", secret.ID, rerr)
		failed[secret.ID] = rotationFailureDetail{SecretName: secret.Name, Detail: fmt.Sprintf("store new version: %v", rerr)}
		sid := secret.ID
		pid := secret.ProjectID
		if secret.RotationBackend != "" {
			// The upstream credential was rotated but storing the new value failed: the
			// live credential and Keyorix's record have now DRIFTED. Audit it distinctly
			// (the backend-apply-failure path above is audited too) so an operator can
			// reconcile — the live secret may no longer match Keyorix.
			c.writeAuditEventFull(ctx, EventSecretAutoRotated, nil, &sid, &pid, "",
				fmt.Sprintf("auto-rotation DRIFT for secret %q: backend %q ref %q rotated upstream but storing the new value failed: %v — the live credential may no longer match Keyorix",
					secret.Name, secret.RotationBackend, secret.RotationRef, rerr))
		} else {
			c.writeAuditEventFull(ctx, EventSecretAutoRotated, nil, &sid, &pid, "",
				fmt.Sprintf("auto-rotation FAILED to store new version for secret %q: %v", secret.Name, rerr))
		}
		c.stampRotationState(ctx, policy.ID, RotationStateFailed, failed[secret.ID].Detail)
		return false
	}
	if incompleteMsg != "" {
		// The new credential is stored (so dependents may still rotate against it), but a
		// prior, possibly compromised credential survived upstream. Record it as a failure
		// (NOT a clean success) so the operator is notified to remove the leftover, and
		// audit it distinctly.
		failed[secret.ID] = rotationFailureDetail{SecretName: secret.Name, Detail: incompleteMsg}
		sid := secret.ID
		pid := secret.ProjectID
		c.writeAuditEventFull(ctx, EventSecretAutoRotated, nil, &sid, &pid, "",
			fmt.Sprintf("auto-rotation INCOMPLETE for secret %q: new credential stored but a prior credential is still live and must be removed manually — %s", secret.Name, incompleteMsg))
		log.Printf("auto-rotation: incomplete cleanup for secret %d: %s", secret.ID, incompleteMsg)
		c.stampRotationState(ctx, policy.ID, RotationStateFailed, incompleteMsg)
		return true
	}
	delete(failed, secret.ID)
	sid := secret.ID
	pid := secret.ProjectID
	via := ""
	if secret.RotationBackend != "" {
		via = fmt.Sprintf(" via backend %q ref %q", secret.RotationBackend, secret.RotationRef)
	}
	c.writeAuditEventFull(ctx, EventSecretAutoRotated, nil, &sid, &pid, "",
		fmt.Sprintf("auto-rotated secret %q (policy %q, interval %dd)%s", secret.Name, policy.Name, policy.IntervalDays, via))
	c.stampRotationState(ctx, policy.ID, RotationStateSucceeded, "")
	return true
}

// stampRotationState calls SetRotationState best-effort — a failure to persist
// the execution-state marker must never abort or fail an otherwise-complete
// rotation attempt, so it is logged rather than propagated.
func (c *KeyorixCore) stampRotationState(ctx context.Context, policyID uint, state, errMsg string) {
	if err := c.SetRotationState(ctx, policyID, state, errMsg); err != nil {
		log.Printf("auto-rotation: policy %d: failed to stamp rotation state %q: %v", policyID, state, err)
	}
}

// rotationLockKey identifies the (backend, ref) pair rotationBackendLocks serializes
// on. A struct key (rather than a delimited string concatenation) avoids any ambiguity
// between e.g. backend="a", ref="b:c" and backend="a:b", ref="c".
type rotationLockKey struct{ backend, ref string }

// rotationBackendLock returns the mutex serializing applyBackendRotation calls for the
// given (backend, ref) pair, creating one on first use. See rotationBackendLocks' doc
// comment (service.go) for why this is keyed per-pair rather than a single global lock,
// and for the scope/limits of what it does and does not close. The mutex is never
// removed — fine, since backend names and refs are operator-configured (bounded
// cardinality), mirroring the reasoning the now-removed internal/rotation/awsiam.go
// refLocks documented for the same tradeoff.
func (c *KeyorixCore) rotationBackendLock(backend, ref string) *sync.Mutex {
	v, _ := c.rotationBackendLocks.LoadOrStore(rotationLockKey{backend, ref}, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// applyBackendRotation resolves the secret's named rotation executor and rotates the
// upstream credential (ADR-047). It returns the VALUE to store in Keyorix: for a
// generate-upstream backend (ports.GeneratingRotationExecutor, e.g. a cloud key API) that is
// the value the upstream minted; for a password-set backend it is the candidate passed
// in (which the executor applied). Returns an error (so the caller does NOT store
// anything) when no manager is configured, the backend is unknown, or the apply fails.
//
// Serializes against any other in-flight applyBackendRotation call for this SAME
// (backend, ref) pair, across BOTH callers of this function — the auto-rotation
// scheduler (rotateOneSecret) and on-demand rotation (RotateSecretOnDemand) — for the
// ENTIRE upstream call (GenerateUpstream's list/evict/create/delete sequence, or
// Rotate's apply), released only once it returns. This is a single, generic choke
// point: it locks BEFORE inspecting whether exec is a GeneratingExecutor, so every
// backend registered in c.rotationManager is covered uniformly regardless of its
// concrete type — see rotationBackendLocks' doc comment (service.go) for the full
// rationale and its scope/limits (in-process only; does not close the orphan-on-crash
// window, which is unrelated and out of scope here).
func (c *KeyorixCore) applyBackendRotation(ctx context.Context, secret *models.SecretNode, candidate string) (string, error) {
	if c.rotationManager == nil {
		return "", fmt.Errorf("no rotation backends configured")
	}
	exec, ok := c.rotationManager.Get(secret.RotationBackend)
	if !ok {
		return "", fmt.Errorf("unknown rotation backend %q", secret.RotationBackend)
	}
	if secret.RotationRef == "" {
		return "", fmt.Errorf("rotation_ref is required for backend rotation")
	}

	mu := c.rotationBackendLock(secret.RotationBackend, secret.RotationRef)
	mu.Lock()
	defer mu.Unlock()

	if gen, ok := exec.(ports.GeneratingRotationExecutor); ok {
		return gen.GenerateUpstream(ctx, secret.RotationRef)
	}
	if err := exec.Rotate(ctx, secret.RotationRef, candidate); err != nil {
		return "", err
	}
	return candidate, nil
}

// RotateSecretOnDemand handles a manual/operator-triggered rotation request (e.g. the
// POST /secrets/{id}/rotate API) with the same backend awareness as the auto-rotation
// scheduler (#193): if the secret is bound to a configured rotation backend (ADR-047),
// the upstream credential is rotated FIRST via applyBackendRotation — the exact machinery
// rotateOneSecret uses — and the value actually stored in Keyorix is the one the backend
// produced/confirmed, never an arbitrary caller-supplied value that could silently drift
// from what's live upstream. Previously this path stored the caller's value verbatim,
// left the real (possibly suspected-compromised) upstream credential fully untouched, and
// still reported "rotated successfully" — an actively misleading incident-response tool.
//
// newValue is used as the candidate applied upstream for a password-SET backend; for a
// generate-upstream backend (e.g. a cloud key API) it is ignored — the upstream mints its
// own value, matching automated-rotation semantics. A secret with no configured backend
// rotates exactly as before (delegates straight to RotateSecret).
//
// If the upstream rotation fails outright, nothing is stored and an error is returned —
// the caller must never be told "success" while the suspected-compromised credential is
// still live and untouched. If it only partially completes (a new credential was minted
// but a prior one could not be removed upstream — ports.RotationPartialError), the new
// value is still stored (never orphan a freshly minted credential — a cloud key API often
// returns key material only once) but an error is still returned, so the HTTP response is
// never a clean "success" while a leftover credential needs manual operator removal; the
// audit trail records the partial state distinctly either way.
// actorID (added for #G09) threads through to RotateSecret's read-guard
// check on the no-op-detection comparison — 0 for callers with no single
// identifiable user (e.g. a bulk operation not yet threading a per-secret
// actor), which only means that comparison is skipped for a
// classification-restricted secret with a gate enabled, never that the
// rotation itself is blocked.
func (c *KeyorixCore) RotateSecretOnDemand(ctx context.Context, id uint, newValue []byte, actorID uint, rotatedBy string) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	if secret.RotationBackend == "" {
		return c.RotateSecret(ctx, id, newValue, actorID, rotatedBy)
	}

	// ROTATION-001: emit before calling upstream so a crash between upstream success
	// and Keyorix store is visible in the audit trail as an orphaned "started" event.
	oidSid := id
	pid := secret.ProjectID
	// AUDIT-MUTATION-TX-1: fail closed here too. The upstream change cannot share a
	// database transaction, so its record has to exist before it happens: if the
	// started row cannot be written, the upstream credential is not touched.
	if !c.writeAuditEventFull(ctx, EventSecretRotateBackendStarted, nil, &oidSid, &pid, "",
		fmt.Sprintf("on-demand rotation: calling upstream backend %q ref %q for secret %q",
			secret.RotationBackend, secret.RotationRef, secret.Name)) {
		return nil, ErrSecretMutationAuditUnavailable
	}
	upstreamVal, berr := c.applyBackendRotation(ctx, secret, string(newValue))
	var partial *ports.RotationPartialError
	switch {
	case errors.As(berr, &partial):
		// The upstream minted the new credential but a prior, possibly compromised one
		// could not be removed. Store the new value (discarding it would orphan a live,
		// untracked credential) but still fail the call — the leftover needs an operator.
		updated, serr := c.RotateSecret(ctx, id, []byte(partial.Value), actorID, rotatedBy)
		if serr != nil {
			return nil, serr
		}
		sid := id
		c.writeAuditEventFull(ctx, EventSecretRotateIncomplete, nil, &sid, &pid, "",
			fmt.Sprintf("on-demand rotation INCOMPLETE for secret %q via backend %q ref %q: new credential stored but a prior credential is still live and must be removed manually: %v",
				secret.Name, secret.RotationBackend, secret.RotationRef, berr))
		return updated, fmt.Errorf("backend %q rotation for secret %q partially completed: new credential stored but a prior credential is still live upstream and must be removed manually: %w",
			secret.RotationBackend, secret.Name, berr)
	case berr != nil:
		sid := id
		c.writeAuditEventFull(ctx, EventSecretRotateFailed, nil, &sid, &pid, "",
			fmt.Sprintf("on-demand rotation FAILED for secret %q via backend %q ref %q: %v", secret.Name, secret.RotationBackend, secret.RotationRef, berr))
		return nil, fmt.Errorf("backend %q rotation failed for secret %q (upstream credential NOT rotated): %w", secret.RotationBackend, secret.Name, berr)
	default:
		return c.RotateSecret(ctx, id, []byte(upstreamVal), actorID, rotatedBy)
	}
}

// rotationRefDisallowedChars are the URL/path and SQL metacharacters rejected in a
// rotation_ref (validateRotationRef also separately rejects control characters). This
// is a DENYLIST, not a strict allowlist: a strict allowlist would break real, already-
// exercised ref shapes — GCP service-account refs are emails ('@', '.'), AWS IAM
// usernames can legitimately contain '+', '=', ',' per AWS's own naming rules — so we
// only reject characters that have no legitimate role in a service-account email, IAM
// username, or DB role/user name.
const rotationRefDisallowedChars = "/?#%'\"\\;"

// validateRotationRef rejects a rotation_ref containing a URL/path metacharacter, a SQL
// metacharacter, or a control character, BEFORE it is ever persisted to
// secret.RotationRef in SetSecretAutoRotate. This is the single choke point every
// transport (HTTP/gRPC/CLI) goes through to set a rotation ref, so this is the earliest
// and only fully-shared layer of defense against a malicious ref (e.g. SQL injection via
// a crafted role name, or path traversal via "<allowed-prefix>/../<victim>").
//
// This is layer ONE of defense-in-depth, not a replacement for the backend-specific
// checks in internal/rotation/{azure,gcpsa}.go (layer TWO, at ROTATION time) or the
// SQL-quoting functions in internal/rotation/{postgres,mysql}.go (also layer TWO) — keep
// all of them; each guards a slightly different trust boundary and this function must
// never narrow to only what one particular backend needs.
func validateRotationRef(ref string) error {
	for i := 0; i < len(ref); i++ {
		if b := ref[i]; b <= 0x1F || b == 0x7F {
			return fmt.Errorf("rotation_ref %q contains a disallowed control character %#02x — refs must not contain quotes, backslashes, semicolons, path/query metacharacters, or control characters", ref, b)
		}
	}
	if i := strings.IndexAny(ref, rotationRefDisallowedChars); i >= 0 {
		return fmt.Errorf("rotation_ref %q contains a disallowed character %q — refs must not contain quotes, backslashes, semicolons, path/query metacharacters, or control characters", ref, ref[i])
	}
	return nil
}

// knownRotationCharset reports whether name is a recognized charset (or "" = default).
func knownRotationCharset(name string) bool {
	switch name {
	case "", "alphanumeric", "lower_alphanumeric", "hex", "alphanumeric_symbols":
		return true
	default:
		return false
	}
}

// AutoRotateSpec is the per-secret automated-rotation configuration set via
// SetSecretAutoRotate (ADR-046/047). Length 0 = default; Charset "" = default
// alphanumeric. Backend "" = regenerate in Keyorix only; when Backend names a
// configured executor, Ref is the upstream identifier it rotates (required iff Backend
// is set).
type AutoRotateSpec struct {
	Enabled bool
	Length  int
	Charset string
	Backend string
	Ref     string
}

// SetSecretAutoRotate configures automated rotation for a secret and audits the change.
// Enable only for secrets whose value Keyorix owns, OR point Backend at an executor that
// rotates the upstream credential too (ADR-047). The caller (transport) must have
// enforced scoped secrets.write.
func (c *KeyorixCore) SetSecretAutoRotate(ctx context.Context, id uint, spec AutoRotateSpec, actorID uint) error { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	if !knownRotationCharset(spec.Charset) {
		return fmt.Errorf("unknown rotation charset %q (want alphanumeric|lower_alphanumeric|hex|alphanumeric_symbols)", spec.Charset)
	}
	if spec.Length != 0 && (spec.Length < rotatedValueMinLength || spec.Length > rotatedValueMaxLength) {
		return fmt.Errorf("rotation length %d out of range (%d–%d, or 0 for default)", spec.Length, rotatedValueMinLength, rotatedValueMaxLength)
	}
	// Backend and ref are both-or-neither: a backend with no ref can't be applied, and a
	// ref with no backend is meaningless.
	if (spec.Backend == "") != (spec.Ref == "") {
		return fmt.Errorf("rotation_backend and rotation_ref must be set together (or both empty)")
	}
	// Reject dangerous ref metacharacters here, at CONFIGURATION time — the single
	// shared choke point every transport goes through — rather than relying solely on
	// the per-backend defenses discovered/added after the fact (see validateRotationRef).
	if spec.Ref != "" {
		if err := validateRotationRef(spec.Ref); err != nil {
			return err
		}
	}
	// Reject an unknown backend at configuration time (the backend's own allowed_refs
	// then bounds, at rotation time, which refs it will actually rotate).
	if spec.Backend != "" {
		if c.rotationManager == nil {
			return fmt.Errorf("no rotation backends are configured")
		}
		if _, ok := c.rotationManager.Get(spec.Backend); !ok {
			return fmt.Errorf("unknown rotation backend %q", spec.Backend)
		}
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	// Binding a backend is a materially bigger grant than scoped secrets.write alone:
	// the backend often carries an org-wide, admin-credentialed connection (AWS/GCP/
	// Azure IAM, a shared DB superuser), and the ref only has to pass that backend's
	// deployment-wide allowed_refs prefix — not any project/segment boundary. Without
	// this, any project editor could point an org-wide-credentialed backend at a ref
	// they can influence and have the next scheduler run mint that credential into
	// their own readable secret (or reset an unrelated target's password) — the same
	// escalation-by-proxy shape #93/#107 closed for role grants, applied here to
	// credential-minting backends (#90).
	//
	// The same authority is required to CLEAR an existing binding: an admin decided this
	// secret should auto-rotate against an upstream backend, and undoing that decision is
	// just as security-relevant as making it — otherwise a plain secrets.write caller
	// could silently strip an admin-configured rotation binding they were never allowed
	// to set up in the first place. `secret` here still holds the PRE-update value (it
	// was fetched above, before spec is applied below), so secret.RotationBackend is the
	// backend that was bound before this call — non-empty only when there is something to
	// unbind. An unbind-when-nothing-was-bound (both empty) stays a no-op and isn't gated.
	if spec.Backend != "" || secret.RotationBackend != "" {
		if err := c.requireAdminAuthorityAt(ctx, actorID, secret.ProjectID); err != nil {
			action := "binding"
			if spec.Backend == "" {
				action = "unbinding"
			}
			return fmt.Errorf("%s a rotation backend requires admin authority on this project: %w", action, err)
		}
	}
	// Persist only the rotation columns, conditional on the facts checked above
	// still holding: the secret is live, still in secret.ProjectID (where the
	// admin gate ran), and still bound to the backend the gate was decided on.
	// A full-row UpdateSecret of this snapshot undeleted a concurrently deleted
	// secret and reverted concurrent binding/ownership changes (#2650).
	fromBackend := secret.RotationBackend
	secret.AutoRotate = spec.Enabled
	secret.RotationLength = spec.Length
	secret.RotationCharset = spec.Charset
	secret.RotationBackend = spec.Backend
	secret.RotationRef = spec.Ref
	secret.UpdatedAt = c.now()
	matched, err := c.storage.UpdateSecretRotationConfig(ctx, secret, fromBackend)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}
	if !matched {
		return fmt.Errorf("secret %d was deleted, moved or its rotation backend changed concurrently; retry", id)
	}
	uid := actorID
	sid := id
	verb := "disabled"
	if spec.Enabled {
		verb = "enabled"
	}
	via := ""
	if spec.Backend != "" {
		via = fmt.Sprintf(" (backend %q ref %q)", spec.Backend, spec.Ref)
	}
	pid := secret.ProjectID
	c.writeAuditEventFull(ctx, EventSecretAutoRotateConfig, &uid, &sid, &pid, "",
		fmt.Sprintf("auto-rotation %s for secret %q%s", verb, secret.Name, via))
	return nil
}
