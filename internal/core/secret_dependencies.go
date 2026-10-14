// secret_dependencies.go — the per-project secret dependency graph (ADR-052).
// An operator declares that one secret "depends on" another (e.g. an app token
// derived from a DB password); Keyorix maintains the directed graph and answers two
// questions from it: impact analysis ("if I rotate this secret, what else is
// affected?" — its transitive dependents) and rotation ordering (a safe sequence to
// rotate a project's secrets so each is rotated before anything that depends on it).
// The graph is kept acyclic: self-edges, duplicates, and cycles are rejected at add.
// Metadata only — secret values are never read. Authz is enforced at the HTTP layer
// (secrets.read to view, secrets.write to mutate) for the FOCAL (path) secret; every
// function below additionally checks each PEER secret's authorization independently
// (see canReadSecret) before disclosing or acting on it — same project+environment
// membership is not sufficient on its own, since a per-secret ACL grant on the focal
// secret does not extend to a peer merely because they share an environment (#G32).
package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Secret-dependency audit event types.
const (
	EventSecretDependencyAdded       = "secret.dependency_added"       // #nosec G101 -- audit event type, not a credential
	EventSecretDependencyRemoved     = "secret.dependency_removed"     // #nosec G101 -- audit event type, not a credential
	EventSecretDependencyInvalidated = "secret.dependency_invalidated" // #nosec G101 -- emitted when a soft-delete breaks a dependency edge
	EventSecretDependencyRestored    = "secret.dependency_restored"    // #nosec G101 -- emitted when a restore re-activates a broken dependency edge
)

// SecretRef is a secret identified for a dependency view (id + name; never a value).
type SecretRef struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
}

// DependencyEdge is one edge as seen from a focal secret: the other secret it links
// to, plus the edge id (so it can be removed) and the operator's note.
type DependencyEdge struct {
	ID         uint   `json:"id"`
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Note       string `json:"note,omitempty"`
}

// SecretDependencies is a focal secret's direct neighbours in both directions.
type SecretDependencies struct {
	SecretID   uint             `json:"secret_id"`
	DependsOn  []DependencyEdge `json:"depends_on"` // secrets this one depends on
	Dependents []DependencyEdge `json:"dependents"` // secrets that depend on this one
}

// ImpactedSecret is a transitive dependent reached during impact analysis, with the
// shortest hop-distance from the rotated secret.
type ImpactedSecret struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Depth      int    `json:"depth"`
}

// SecretImpact is the blast radius of rotating/changing a secret.
type SecretImpact struct {
	SecretID   uint             `json:"secret_id"`
	SecretName string           `json:"secret_name"`
	Affected   []ImpactedSecret `json:"affected"`
	// Truncated is true when the true affected set may extend beyond what
	// Affected contains -- the underlying BFS hit maxDependencyBFSNodes or
	// maxDependencyBFSDepth (see transitiveDependents).
	Truncated bool `json:"truncated"`
}

// RotationOrder is a safe rotation sequence for a project's dependency graph: each
// secret appears before any secret that depends on it.
type RotationOrder struct {
	ProjectID uint        `json:"project_id"`
	Order     []SecretRef `json:"order"`
}

// AddSecretDependency declares that dependentID depends on dependsOnID. Both must be
// real secrets in the same project; self-edges, duplicates, and edges that would
// introduce a cycle are rejected. actorID is the acting principal.
//
// The duplicate/cycle check and the edge write are performed by ONE atomic storage call
// (CreateSecretDependencyExclusive, #260) rather than this method orchestrating a
// ListSecretDependenciesForProjectForUpdate read and a separate CreateSecretDependency
// write itself inside a WithTransaction — see the storage.Storage interface doc
// (internal/core/storage/interface.go) for the full reasoning. secretDependencyMu is
// still held for the call's duration, still serializing same-process callers (SQLite,
// single instance) exactly as before; the storage layer's own lock (Postgres FOR
// UPDATE on LocalStorage) is what also serializes across replicas — the same
// two-layer pattern login_lockout.go's recordFailedLogin and RemoveUserRole's
// guardLastGlobalAdmin use.
func (c *KeyorixCore) AddSecretDependency(ctx context.Context, actorKind string, actorID, dependentID, dependsOnID uint, note string, createdByMachineID uint) (*models.SecretDependency, error) {
	if dependentID == dependsOnID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a secret cannot depend on itself")
	}
	dependent, err := c.requireSecret(ctx, dependentID)
	if err != nil {
		return nil, err // the caller is authorized on the path secret, so its status may differ
	}
	// Resolve the dependency target, but DON'T distinguish "not found" / "is a folder" /
	// "in another project or environment" — the caller is only authorized on the path
	// (dependent) secret's scope, so a differentiated error here is a cross-scope
	// existence-and-type oracle (probe arbitrary IDs by 404-vs-400). Collapse them into a
	// single opaque error.
	dependsOn, derr := c.requireSecret(ctx, dependsOnID)
	if derr != nil || dependsOn.ProjectID != dependent.ProjectID || dependsOn.EnvironmentID != dependent.EnvironmentID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the dependency target must be a secret in the same project and environment")
	}
	// #G32: same project+environment is NOT the same as "the caller is authorized on
	// it" — a per-secret ACL grant on the dependent (path) secret does not extend to
	// dependsOn. Require the caller to be independently authorized to write the
	// dependency target too, before linking it into the graph.
	if allowed, aerr := c.AuthorizeSecretPrincipal(ctx, actorKind, actorID, dependsOnID, permSecretsWrite); aerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), aerr)
	} else if !allowed {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "not authorized on the dependency target")
	}

	// #1623: actorID alone cannot be persisted into CreatedBy for a machine
	// caller -- AuthorizeSecretPrincipal above needs actorID as the real
	// PrincipalID (a machine's own MachineIdentity.ID) to resolve its grants,
	// but persisting that same raw value into CreatedBy is ambiguous against
	// User.ID's own independent auto-increment sequence. actorKind (already a
	// parameter) discriminates which ID space actorID actually came from, the
	// same split #1573's PR2 applies via actorID(r)/machineID(r) at the HTTP
	// layer for every other machine-actor attribution field.
	createdBy := actorID
	if actorKind == ActorTypeMachine {
		createdBy = 0
	}
	created, err := c.LockedCreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID:                  dependent.ProjectID,
		DependentSecretID:          dependentID,
		DependsOnSecretID:          dependsOnID,
		Note:                       note,
		CreatedBy:                  createdBy,
		CreatedByMachineIdentityID: createdByMachineID,
		CreatedAt:                  c.now(),
	})
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrDuplicateSecretDependency):
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this dependency already exists")
		case errors.Is(err, storage.ErrSecretDependencyCycle):
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this dependency would create a cycle")
		default:
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}
	c.writeAuditEvent(ctx, EventSecretDependencyAdded, actorPtr(actorID), &dependentID,
		fmt.Sprintf("declared secret %q depends on %q", dependent.Name, dependsOn.Name))
	return created, nil
}

// LockedCreateSecretDependencyExclusive persists d via
// storage.CreateSecretDependencyExclusive while holding secretDependencyMu —
// the same mutex AddSecretDependency holds around the identical storage call
// above. #G79: CreateSecretDependencyExclusiveProxy (server/http/handlers/
// secret_dependencies_proxy.go, deleted along with the rest of the /system
// tier, ADR-108) called the raw storage primitive directly
// rather than through AddSecretDependency, since the caller's authorization
// is now re-derived at the HTTP layer (AuthorizeSecretPrincipal on both
// endpoints, #SecretDependency, system-proxy-target-authority audit) before
// this is ever reached — this is a raw CAS write with its own authorization
// already done, not an unauthenticated passthrough. [The prior text here
// claimed the caller "already ran AddSecretDependency's authorization checks
// itself" as a downstream-relay assumption — the same relay-trust reasoning
// ADR-085 found cannot hold anywhere in this codebase
// (validateRemoteStorageNotServer rejects storage.type: remote for any
// server process, so no such relay topology can exist); that was wrong, and
// was the actual root cause of the gap this fix closes.] It still
// needs the SAME in-process serialization AddSecretDependency provides:
// storage.CreateSecretDependencyExclusive's cycle check has no row to lock on
// SQLite (no FOR UPDATE support) or on Postgres when the project has zero
// existing edges (FOR UPDATE only locks rows that already exist), so two
// concurrent same-process calls adding A→B and B→A could otherwise both pass
// the cycle check before either commits.
//
// #2660: secretDependencyMu is per-process, and on Postgres FOR UPDATE on the
// existing edges does not block a phantom INSERT, so two replicas adding A->B
// and B->A could each read the graph without the other's edge, both pass the
// cycle check, and both commit a cycle (INV-CORE-31). Every write that can add
// an edge now runs under WithNamedLock(secretDependencyGraphLockKey(project)),
// which serializes the whole read-check-insert across replicas; the mutex is
// kept as the cheap same-process fast path, taken inside the named lock (the
// same named-lock-then-mutex order removeGlobalAdminRoleIfApplicable uses).
// AddSecretDependency goes through here, so both callers share the lock.
func (c *KeyorixCore) LockedCreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	var created *models.SecretDependency
	err := c.storage.WithNamedLock(ctx, secretDependencyGraphLockKey(d.ProjectID), func(ctx context.Context) error {
		c.secretDependencyMu.Lock()
		defer c.secretDependencyMu.Unlock()
		var cerr error
		created, cerr = c.storage.CreateSecretDependencyExclusive(ctx, d)
		return cerr
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// secretDependencyGraphLockKey is the WithNamedLock key serializing every edge
// insert into one project's secret dependency graph (#2660). The cycle check
// reads the project's whole graph, so the key is per project, not per edge.
func secretDependencyGraphLockKey(projectID uint) string {
	return fmt.Sprintf("secret-dependency-graph:%d", projectID)
}

// RemoveSecretDependency deletes one edge. focalSecretID is the secret the request is
// scoped to (the {id} in the route): the edge must actually reference that secret, so
// the environment-scoped authorization the caller passed on focalSecretID also governs
// the edge. Matching on project alone would be too coarse — authorization is
// environment-granular, and a caller could otherwise delete an edge between two secrets
// in another environment of the same project. actorID is the acting principal.
//
// #G32: focalSecretID is only ONE endpoint of the edge — the other endpoint (the peer)
// gets independently authorized below before the edge can be removed, since a per-secret
// ACL grant on focalSecretID does not extend to it.
func (c *KeyorixCore) RemoveSecretDependency(ctx context.Context, actorKind string, actorID, focalSecretID, edgeID uint) error {
	if _, err := c.requireSecret(ctx, focalSecretID); err != nil {
		return err
	}
	edge, err := c.storage.GetSecretDependency(ctx, edgeID)
	if err != nil {
		return err
	}
	if edge.DependentSecretID != focalSecretID && edge.DependsOnSecretID != focalSecretID {
		return fmt.Errorf("%s: dependency %d does not reference secret %d", i18n.T("ErrorNotFound", nil), edgeID, focalSecretID)
	}
	peerID := edge.DependentSecretID
	if peerID == focalSecretID {
		peerID = edge.DependsOnSecretID
	}
	if allowed, aerr := c.AuthorizeSecretPrincipal(ctx, actorKind, actorID, peerID, permSecretsWrite); aerr != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), aerr)
	} else if !allowed {
		return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "not authorized on the dependency target")
	}
	if err := c.storage.DeleteSecretDependency(ctx, edgeID); err != nil {
		return err
	}
	dep := edge.DependentSecretID
	c.writeAuditEvent(ctx, EventSecretDependencyRemoved, actorPtr(actorID), &dep,
		fmt.Sprintf("removed dependency of secret %d on secret %d", edge.DependentSecretID, edge.DependsOnSecretID))
	return nil
}

// ListSecretDependencies returns a secret's direct dependencies and dependents, with
// names resolved.
func (c *KeyorixCore) ListSecretDependencies(ctx context.Context, actorKind string, actorID, secretID uint) (*SecretDependencies, error) {
	secret, err := c.requireSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	edges, err := c.storage.ListSecretDependenciesForProject(ctx, secret.ProjectID)
	if err != nil {
		return nil, err
	}
	info := c.resolveSecretInfo(ctx, edges)
	// Defence-in-depth: only consider edges whose BOTH endpoints actually live in the
	// focal secret's environment — independent of the add-time same-environment guard —
	// so the view can never surface a name from another environment the caller may not
	// be authorized on, even if a cross-environment edge were somehow present.
	edges = edgesWithinEnvironment(edges, info, secret.EnvironmentID)
	out := &SecretDependencies{SecretID: secretID, DependsOn: []DependencyEdge{}, Dependents: []DependencyEdge{}}
	for _, e := range edges {
		switch secretID {
		case e.DependentSecretID:
			// #G32: same environment is not the same as "independently authorized" —
			// don't disclose a peer the caller has no grant on of their own.
			if !c.canReadSecret(ctx, actorKind, actorID, e.DependsOnSecretID) {
				continue
			}
			out.DependsOn = append(out.DependsOn, DependencyEdge{ID: e.ID, SecretID: e.DependsOnSecretID, SecretName: info[e.DependsOnSecretID].name, Note: e.Note})
		case e.DependsOnSecretID:
			if !c.canReadSecret(ctx, actorKind, actorID, e.DependentSecretID) {
				continue
			}
			out.Dependents = append(out.Dependents, DependencyEdge{ID: e.ID, SecretID: e.DependentSecretID, SecretName: info[e.DependentSecretID].name, Note: e.Note})
		}
	}
	return out, nil
}

// GetSecretImpact returns the blast radius of rotating/changing a secret: every
// secret that transitively depends on it, with hop-distance, in breadth-first order.
func (c *KeyorixCore) GetSecretImpact(ctx context.Context, actorKind string, actorID, secretID uint) (*SecretImpact, error) {
	secret, err := c.requireSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	edges, err := c.storage.ListSecretDependenciesForProject(ctx, secret.ProjectID)
	if err != nil {
		return nil, err
	}
	info := c.resolveSecretInfo(ctx, edges)
	edges = edgesWithinEnvironment(edges, info, secret.EnvironmentID) // defence-in-depth, as in ListSecretDependencies
	affected, truncated := transitiveDependents(edges, secretID)
	out := &SecretImpact{SecretID: secretID, SecretName: secret.Name, Affected: make([]ImpactedSecret, 0, len(affected)), Truncated: truncated}
	for _, a := range affected {
		// #G32: the BFS traverses the full graph so a hop through an unauthorized peer
		// still surfaces further, independently-authorized dependents — but a peer the
		// caller has no grant of their own on is never disclosed in the output.
		if !c.canReadSecret(ctx, actorKind, actorID, a.id) {
			continue
		}
		out.Affected = append(out.Affected, ImpactedSecret{SecretID: a.id, SecretName: info[a.id].name, Depth: a.depth})
	}
	return out, nil
}

// canReadSecret reports whether actor is independently authorized to read secretID —
// used to decide whether a peer secret's name/id may be disclosed to the caller in a
// dependency/impact/blast-radius view. #G32: dependency edges are confined to the focal
// secret's own project+environment, but authorization is per-secret (a SecretACL grant
// on the focal secret does not extend to a peer merely because they share an
// environment), so same-environment membership alone is not sufficient to disclose a
// peer's identity — this calls the same actor-aware, ACL-inclusive primitive
// server/middleware/auth.go's RequireScopedSecretPermission uses to authorize the path
// secret at the HTTP layer.
func (c *KeyorixCore) canReadSecret(ctx context.Context, actorKind string, actorID, secretID uint) bool {
	allowed, err := c.AuthorizeSecretPrincipal(ctx, actorKind, actorID, secretID, permSecretsRead)
	return err == nil && allowed
}

// GetProjectRotationOrder returns a safe rotation sequence for a project's dependency
// graph: each secret precedes any secret that depends on it. Only secrets that appear
// in the graph are ordered (standalone secrets can rotate at any time).
func (c *KeyorixCore) GetProjectRotationOrder(ctx context.Context, projectID uint) (*RotationOrder, error) {
	edges, err := c.storage.ListSecretDependenciesForProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	// Rotation order is project-wide (authorized by a project-scoped grant that spans
	// all environments), so no per-environment filter here — but a soft-deleted secret
	// (ADR-033) must not appear in the order. Resolve names first, then drop any edge
	// incident to a secret that no longer resolves, so the graph follows the secret's
	// soft-delete/restore lifecycle (the env-scoped views filter the same way).
	info := c.resolveSecretInfo(ctx, edges)
	edges = edgesBetweenLiveSecrets(edges, info)
	order, ok := topologicalRotationOrder(edges)
	if !ok {
		// Defensive: cycles are rejected at add, so a remaining cycle is a data fault.
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorInternal", nil), "the dependency graph contains a cycle")
	}
	out := &RotationOrder{ProjectID: projectID, Order: make([]SecretRef, 0, len(order))}
	for _, id := range order {
		out.Order = append(out.Order, SecretRef{SecretID: id, SecretName: info[id].name})
	}
	return out, nil
}

// requireSecret loads a secret node and verifies it is an actual secret (not a folder)
// — the endpoints of a dependency must both be secrets.
func (c *KeyorixCore) requireSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	node, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: secret %d not found", i18n.T("ErrorNotFound", nil), id)
	}
	if !node.IsSecret {
		return nil, fmt.Errorf("%s: %d is not a secret", i18n.T("ErrorValidation", nil), id)
	}
	return node, nil
}

// emitDependencyLifecycleEvents emits one audit event per dependency edge that is
// incident to secretID (either as the dependent or the depended-on target).
// eventType is EventSecretDependencyInvalidated on soft-delete or
// EventSecretDependencyRestored on restore. projectID is used to load the full edge
// list; secretName is included in the human-readable description. Errors from the
// edge list query are logged but never surface to the caller — the delete/restore
// already succeeded and the audit emission is best-effort. A panic during that
// same query is recovered here too (found live by FuzzStorageFaultOperations,
// server/faultops): without the recover, a panic propagates straight through
// DeleteSecret/RestoreSecret and out to the real Recovery middleware, which
// turns it into a 500 — but the delete/restore has ALREADY committed by this
// point, so the caller is told the request failed when it actually succeeded
// (oracle (a): reported ERROR, but SecretNode state changed anyway). An error
// return was already handled correctly; only the panic path was missing.
func (c *KeyorixCore) emitDependencyLifecycleEvents(ctx context.Context, eventType string, actorID, secretID, projectID uint, secretName string) {
	besteffort.Run(ctx, "secret_dependencies.emitDependencyLifecycleEvents", func() error {
		edges, err := c.storage.ListSecretDependenciesForProject(ctx, projectID)
		if err != nil {
			return err // best-effort; the primary operation already succeeded
		}
		for _, e := range edges {
			switch secretID {
			case e.DependsOnSecretID:
				// secretID is the "depends-on" target — its dependent loses its upstream.
				dep := e.DependentSecretID
				c.writeAuditEvent(ctx, eventType, actorPtr(actorID), &dep,
					fmt.Sprintf("dependency of secret %d on %q (id %d) %s due to secret lifecycle event",
						e.DependentSecretID, secretName, secretID, lifecycleVerb(eventType)))
			case e.DependentSecretID:
				// secretID is the dependent — the edge it owns is now unresolvable.
				src := e.DependentSecretID
				c.writeAuditEvent(ctx, eventType, actorPtr(actorID), &src,
					fmt.Sprintf("dependency of %q (id %d) on secret %d %s due to secret lifecycle event",
						secretName, secretID, e.DependsOnSecretID, lifecycleVerb(eventType)))
			}
		}
		return nil
	})
}

// lifecycleVerb returns a short past-tense word for an audit description.
func lifecycleVerb(eventType string) string {
	if eventType == EventSecretDependencyRestored {
		return "restored"
	}
	return "invalidated"
}

// secretInfo is the per-secret metadata the views need: its name and the environment
// it actually lives in (the latter is the authoritative value for the env filter).
type secretInfo struct {
	name string
	env  uint
}

// resolveSecretInfo builds an id→{name,env} map for every secret referenced by edges,
// so the views can show names and filter by real environment without an extra
// round-trip per row. A secret that no longer resolves is absent from the map (zero
// value), so it is treated as not in any caller's environment.
func (c *KeyorixCore) resolveSecretInfo(ctx context.Context, edges []*models.SecretDependency) map[uint]secretInfo { // nosemgrep: keyorix-unbounded-bulk-slice-param -- edges is a dependency-graph query result for one project, not a raw client-supplied array in one request
	ids := make(map[uint]struct{})
	for _, e := range edges {
		ids[e.DependentSecretID] = struct{}{}
		ids[e.DependsOnSecretID] = struct{}{}
	}
	info := make(map[uint]secretInfo, len(ids))
	for id := range ids {
		if node, err := c.storage.GetSecret(ctx, id); err == nil {
			info[id] = secretInfo{name: node.Name, env: node.EnvironmentID}
		}
	}
	return info
}

// --- pure graph helpers (no storage; unit-testable in isolation) ---

// edgesWithinEnvironment keeps only edges whose BOTH endpoints actually live in the
// given environment, per the resolved info. Edges never cross environments (enforced at
// add), so this is defence-in-depth: it keeps the read paths safe even if a
// cross-environment edge were somehow present, because it checks the endpoints' real
// environments rather than trusting any field on the edge.
func edgesWithinEnvironment(edges []*models.SecretDependency, info map[uint]secretInfo, environmentID uint) []*models.SecretDependency {
	out := make([]*models.SecretDependency, 0, len(edges))
	for _, e := range edges {
		if info[e.DependentSecretID].env == environmentID && info[e.DependsOnSecretID].env == environmentID {
			out = append(out, e)
		}
	}
	return out
}

// edgesBetweenLiveSecrets keeps only edges whose BOTH endpoints resolved to a live
// secret (present in info). A soft-deleted endpoint does not resolve — GetSecret hides it
// (ADR-033) — so it is absent from info, dropping every edge incident to it. The edge
// rows are never mutated, so restoring the secret brings its edges back into the graph
// automatically. Used by the project-wide rotation order, which (unlike the env-scoped
// views) has no environment filter to exclude a deleted endpoint for it.
func edgesBetweenLiveSecrets(edges []*models.SecretDependency, info map[uint]secretInfo) []*models.SecretDependency {
	out := make([]*models.SecretDependency, 0, len(edges))
	for _, e := range edges {
		_, dependentLive := info[e.DependentSecretID]
		_, dependsOnLive := info[e.DependsOnSecretID]
		if dependentLive && dependsOnLive {
			out = append(out, e)
		}
	}
	return out
}

// dependentsAdjacency builds the reverse adjacency for impact analysis: for each
// secret, the set of secrets that directly depend on it (its dependents). Neighbour
// lists are sorted for deterministic traversal.
func dependentsAdjacency(edges []*models.SecretDependency) map[uint][]uint {
	adj := make(map[uint][]uint)
	for _, e := range edges {
		adj[e.DependsOnSecretID] = append(adj[e.DependsOnSecretID], e.DependentSecretID)
	}
	for k := range adj {
		slices.Sort(adj[k])
	}
	return adj
}

// dependencyReachable reports whether `to` is reachable from `from` following
// depends-on edges (from depends on … depends on to). Used to detect cycles before
// adding an edge.
func dependencyReachable(edges []*models.SecretDependency, from, to uint) bool {
	adj := make(map[uint][]uint)
	for _, e := range edges {
		adj[e.DependentSecretID] = append(adj[e.DependentSecretID], e.DependsOnSecretID)
	}
	seen := map[uint]bool{from: true}
	stack := []uint{from}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, next := range adj[n] {
			if next == to {
				return true
			}
			if !seen[next] {
				seen[next] = true
				stack = append(stack, next)
			}
		}
	}
	return false
}

type impacted struct {
	id    uint
	depth int
}

// maxDependencyBFSNodes bounds transitiveDependents' total node count — the
// same resource-exhaustion vector blastBFS's maxBlastRadiusNodes guards
// (#G44, blast_radius.go): both GetSecretImpact and GetSecretImpactPreview
// do a per-node canReadSecret call over the result afterward, so an unbounded
// node count is a per-request cost multiplier reachable via dependency-edge
// fan-out within a single project (AddSecretDependency rejects cycles and
// self-edges, but has no cap on total edge/node count). Independently
// tunable from maxBlastRadiusNodes even though the value matches it today —
// the two features may need different limits later.
const maxDependencyBFSNodes = 2000

// maxDependencyBFSDepth mirrors blastBFS's maxDepth, same reasoning.
const maxDependencyBFSDepth = 10

// transitiveDependents returns every secret that transitively depends on secretID, in
// breadth-first order with the shortest hop-distance, up to maxDependencyBFSNodes
// total and maxDependencyBFSDepth deep. Excludes secretID itself. truncated is true
// when either bound was hit — the true dependent set may extend further than what's
// returned; callers must surface this rather than silently reporting a possibly
// truncated result as complete (same discipline as blastBFS/#G24).
func transitiveDependents(edges []*models.SecretDependency, secretID uint) (result []impacted, truncated bool) {
	adj := dependentsAdjacency(edges)
	seen := map[uint]bool{secretID: true}
	out := []impacted{}
	queue := []impacted{{id: secretID, depth: 0}}
	for len(queue) > 0 && len(out) < maxDependencyBFSNodes {
		cur := queue[0]
		queue = queue[1:]
		for _, dep := range adj[cur.id] {
			if seen[dep] {
				continue
			}
			seen[dep] = true
			next := impacted{id: dep, depth: cur.depth + 1}
			out = append(out, next)
			if next.depth < maxDependencyBFSDepth {
				queue = append(queue, next)
			} else {
				truncated = true
			}
			if len(out) >= maxDependencyBFSNodes {
				truncated = true
				break
			}
		}
	}
	return out, truncated
}

// topologicalRotationOrder returns the secrets in a project's dependency graph in a
// safe rotation order — each secret before any that depends on it — using Kahn's
// algorithm with deterministic tie-breaking (ascending secret id). ok is false if a
// cycle prevents a complete ordering (should not happen: cycles are rejected at add).
func topologicalRotationOrder(edges []*models.SecretDependency) (order []uint, ok bool) {
	// Prerequisite graph: rotate a dependency before its dependent, so an edge
	// (dependent depends on dependsOn) means dependsOn → dependent must precede.
	adj := make(map[uint][]uint) // dependsOn → its dependents
	indeg := make(map[uint]int)  // count of prerequisites (dependencies) per node
	nodes := make(map[uint]struct{})
	for _, e := range edges {
		adj[e.DependsOnSecretID] = append(adj[e.DependsOnSecretID], e.DependentSecretID)
		indeg[e.DependentSecretID]++
		nodes[e.DependentSecretID] = struct{}{}
		nodes[e.DependsOnSecretID] = struct{}{}
	}
	// Seed the queue with nodes that depend on nothing, smallest id first.
	ready := []uint{}
	for n := range nodes {
		if indeg[n] == 0 {
			ready = append(ready, n)
		}
	}
	slices.Sort(ready)

	order = make([]uint, 0, len(nodes))
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		order = append(order, n)
		next := append([]uint(nil), adj[n]...)
		slices.Sort(next)
		for _, m := range next {
			indeg[m]--
			if indeg[m] == 0 {
				// Insert keeping `ready` sorted so the output is deterministic.
				pos := sort.Search(len(ready), func(i int) bool { return ready[i] >= m })
				ready = append(ready, 0)
				copy(ready[pos+1:], ready[pos:])
				ready[pos] = m
			}
		}
	}
	return order, len(order) == len(nodes)
}
