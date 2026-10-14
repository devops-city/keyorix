// rotation_planner.go — automated rotation planning (ADR-053). Given a project's
// rotation posture (which policy-covered secrets are overdue / due soon), the secrets'
// composite risk, and the secret dependency graph (ADR-052), GenerateRotationPlan
// produces an ordered, batched, explainable plan: dependency-respecting *waves* of
// secrets safe to rotate together, each secret prioritised by urgency and annotated
// with why it is in the plan and what it must follow.
//
// The "planning" is a deterministic, explainable algorithm (urgency scoring +
// dependency-aware wave batching), not an opaque model — appropriate for a security
// operation in an on-prem / air-gapped deployment. An optional LLM advisor that
// narrates or further optimises the plan can later sit on top of this structured
// output (see ADR-053); it is not in the rotation decision path.
package core

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PlannedRotation is one secret's place in the rotation plan, with the rationale an
// operator needs to act on (or override) it.
type PlannedRotation struct {
	SecretID    uint   `json:"secret_id"`
	SecretName  string `json:"secret_name"`
	Status      string `json:"status"`       // overdue | due_soon
	DaysOverdue int    `json:"days_overdue"` // positive = overdue, negative = days remaining
	RiskScore   int    `json:"risk_score"`   // 0-100 composite (0 if not computable)
	RiskBand    string `json:"risk_band"`    // low | medium | high
	// RiskDegraded is true either when RiskScore/RiskBand were computed from an
	// incomplete exposure count (#407, SecretRiskScore.Degraded — ComputeSecretRiskScore
	// already fails the exposure factor toward its worst case in this situation, so
	// RiskScore here is a floor, not an inflated or deflated guess), or when
	// ComputeSecretRiskScore returned an outright error and RiskScore/RiskBand are
	// zero values (#486 — a storage flake computing risk must not read the same as
	// a genuine, fully-resolved zero-risk secret, since rotationUrgency shifts
	// intra-wave ordering by risk score). Either way, RiskDegraded makes the gap
	// visible instead of indistinguishable from a fully resolved score.
	RiskDegraded   bool     `json:"risk_degraded"`
	Urgency        int      `json:"urgency"`          // composite priority; higher rotates sooner
	AutoRotate     bool     `json:"auto_rotate"`      // self-rotates (ADR-046) vs needs a human
	AfterSecretIDs []uint   `json:"after_secret_ids"` // in-plan dependencies that must rotate first
	Reasons        []string `json:"reasons"`          // human-readable rationale
}

// RotationWave is a set of secrets with no rotation dependency on each other, safe to
// rotate together (in parallel). Wave 0 has no in-plan dependencies; a secret in wave
// N depends only on secrets in waves < N.
type RotationWave struct {
	Index   int               `json:"index"`
	Secrets []PlannedRotation `json:"secrets"`
}

// RotationPlan is the full ordered plan for a project.
type RotationPlan struct {
	ProjectID    uint           `json:"project_id"`
	TotalSecrets int            `json:"total_secrets"`
	OverdueCount int            `json:"overdue_count"`
	DueSoonCount int            `json:"due_soon_count"`
	Waves        []RotationWave `json:"waves"`
}

// GenerateRotationPlan builds the rotation plan for a project: every policy-covered
// secret that is overdue or due soon, ordered into dependency-respecting waves and
// prioritised by urgency within each wave. Returns an empty plan (no waves) when
// nothing needs rotation.
func (c *KeyorixCore) GenerateRotationPlan(ctx context.Context, projectID uint) (*RotationPlan, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	status, err := c.GetRotationStatus(ctx, &projectID, nil)
	if err != nil {
		return nil, err
	}

	// Candidates: secrets needing rotation, deduped per secret (a secret covered by
	// several policies appears once, keeping the most urgent classification).
	candidates := collectRotationCandidates(status)

	plan := &RotationPlan{ProjectID: projectID, Waves: []RotationWave{}}
	if len(candidates) == 0 {
		return plan, nil
	}

	candidateSet := make(map[uint]bool, len(candidates))
	candidateIDs := make([]uint, 0, len(candidates))
	for id := range candidates {
		candidateSet[id] = true
		candidateIDs = append(candidateIDs, id)
	}

	// #409: risk-score every candidate secret with a small constant number of
	// batched storage queries (see ComputeSecretRiskScoresBatch), not by calling
	// ComputeSecretRiskScore fresh — with its own several queries — once per
	// candidate. planSecret below never touches storage itself; it only reads
	// from riskScores/riskErr computed here, once, for the whole project.
	riskScores, riskErr := c.ComputeSecretRiskScoresBatch(ctx, candidateIDs)

	edges, err := c.storage.ListSecretDependenciesForProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	waves, ok := rotationWaves(edges, candidateSet)
	if !ok {
		// Defensive: the dependency graph is kept acyclic at add (ADR-052).
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorInternal", nil), "the dependency graph contains a cycle")
	}

	// In-plan dependencies per candidate (edges to other candidates).
	dependsOnInPlan := map[uint][]uint{}
	for _, e := range edges {
		if candidateSet[e.DependentSecretID] && candidateSet[e.DependsOnSecretID] {
			dependsOnInPlan[e.DependentSecretID] = append(dependsOnInPlan[e.DependentSecretID], e.DependsOnSecretID)
		}
	}

	for wi, ids := range waves {
		wave := RotationWave{Index: wi, Secrets: make([]PlannedRotation, 0, len(ids))}
		for _, id := range ids {
			entry := candidates[id]
			pr := c.planSecret(entry, dependsOnInPlan[id], candidates, riskScores, riskErr)
			wave.Secrets = append(wave.Secrets, pr)
			if entry.Status == RotationStatusOverdue {
				plan.OverdueCount++
			} else {
				plan.DueSoonCount++
			}
		}
		// Most urgent first within the wave; secret id breaks ties for determinism.
		sort.Slice(wave.Secrets, func(i, j int) bool {
			if wave.Secrets[i].Urgency != wave.Secrets[j].Urgency {
				return wave.Secrets[i].Urgency > wave.Secrets[j].Urgency
			}
			return wave.Secrets[i].SecretID < wave.Secrets[j].SecretID
		})
		plan.Waves = append(plan.Waves, wave)
	}
	plan.TotalSecrets = len(candidates)
	return plan, nil
}

// DeploymentRotationPlan aggregates every project's rotation plan into the install-wide
// rotation picture (ADR-053 deferred follow-up): the roll-up totals a security lead needs at
// a glance, plus each project's own plan. Rotation dependencies are per-project (ADR-052
// edges never cross a project boundary), so this is a roll-up of per-project plans rather
// than a single global wave ordering. Only projects with something to rotate are listed.
type DeploymentRotationPlan struct {
	ProjectsScanned  int            `json:"projects_scanned"`   // projects examined
	ProjectsWithWork int            `json:"projects_with_work"` // projects with at least one secret to rotate
	TotalSecrets     int            `json:"total_secrets"`      // secrets needing rotation, deployment-wide
	OverdueCount     int            `json:"overdue_count"`
	DueSoonCount     int            `json:"due_soon_count"`
	Projects         []RotationPlan `json:"projects"` // most-overdue project first; only projects with work
	// BrokenProjects flags every project whose plan could not be computed (in
	// practice: a cyclic dependency graph — cycles are rejected at add, ADR-052,
	// so this should not happen, but a persisted cycle should never take down the
	// whole deployment-wide view, #260) rather than aborting the entire roll-up —
	// mirroring CompliancePosture's Degraded/DegradedReasons pattern
	// (compliance_posture.go): a per-project failure surfaces as an explicit,
	// named gap in an otherwise-complete result, not a hard error for every other
	// project's viewers.
	BrokenProjects []BrokenRotationProject `json:"broken_projects,omitempty"`
}

// BrokenRotationProject names a project GenerateDeploymentRotationPlan could not
// compute a plan for, with the underlying error, so an operator can find and fix
// it (e.g. locate and delete a stuck cyclic edge) without every other project's
// viewers losing the deployment-wide rotation plan in the meantime.
type BrokenRotationProject struct {
	ProjectID uint   `json:"project_id"`
	Error     string `json:"error"`
}

// GenerateDeploymentRotationPlan builds the deployment-wide rotation plan by aggregating
// every project's plan (ADR-053). Projects with nothing to rotate are omitted from the
// list but still counted in ProjectsScanned. Projects are ordered most-overdue first so the
// install's most pressing rotation work surfaces at the top.
//
// A project whose plan fails to compute (in practice, a cyclic dependency graph
// slipping past AddSecretDependency's cycle check via a race, #260) is skipped and
// flagged in BrokenProjects rather than aborting the whole call: without this, one
// project's stuck cycle 500s the install-wide GET /rotation-plan endpoint for every
// viewer across the entire deployment. Mirrors RunAutoRotation's graceful
// degrade-and-log behaviour on the same condition (rotation_executor.go).
func (c *KeyorixCore) GenerateDeploymentRotationPlan(ctx context.Context) (*DeploymentRotationPlan, error) {
	projects, err := c.storage.ListProjects(ctx)
	if err != nil {
		return nil, err
	}

	dp := &DeploymentRotationPlan{Projects: []RotationPlan{}}
	for _, p := range projects {
		dp.ProjectsScanned++
		plan, err := c.GenerateRotationPlan(ctx, p.ID)
		if err != nil {
			log.Printf("deployment rotation plan: project %d: %v — skipping this project, continuing the deployment-wide roll-up", p.ID, err)
			dp.BrokenProjects = append(dp.BrokenProjects, BrokenRotationProject{ProjectID: p.ID, Error: err.Error()})
			continue
		}
		if plan.TotalSecrets == 0 {
			continue // nothing to rotate here — keep the deployment view focused
		}
		dp.ProjectsWithWork++
		dp.TotalSecrets += plan.TotalSecrets
		dp.OverdueCount += plan.OverdueCount
		dp.DueSoonCount += plan.DueSoonCount
		dp.Projects = append(dp.Projects, *plan)
	}

	// Most overdue projects first; project id breaks ties for a deterministic order.
	sort.Slice(dp.Projects, func(i, j int) bool {
		if dp.Projects[i].OverdueCount != dp.Projects[j].OverdueCount {
			return dp.Projects[i].OverdueCount > dp.Projects[j].OverdueCount
		}
		return dp.Projects[i].ProjectID < dp.Projects[j].ProjectID
	})
	sort.Slice(dp.BrokenProjects, func(i, j int) bool {
		return dp.BrokenProjects[i].ProjectID < dp.BrokenProjects[j].ProjectID
	})
	return dp, nil
}

// planSecret turns a candidate entry into a PlannedRotation with urgency and
// reasons. It never touches storage itself — riskScores/riskErr are computed once
// for every candidate in the project by ComputeSecretRiskScoresBatch (#409), not
// freshly per secret here.
func (c *KeyorixCore) planSecret(e *RotationStatusEntry, deps []uint, candidates map[uint]*RotationStatusEntry, riskScores map[uint]*SecretRiskScore, riskErr error) PlannedRotation {
	riskScore, riskBand := 0, ""
	riskDegraded := false
	riskDegradedReason := "risk score based on incomplete exposure data (treated as worst-case, not deprioritized)"
	switch {
	case riskErr != nil:
		// #486: an outright failure to compute risk scores (e.g. a storage flake
		// on the batched secret lookup) must NOT read the same as a genuine,
		// fully-resolved zero-risk score — that would silently under-rank an
		// actually-risky overdue secret, since rotationUrgency shifts intra-wave
		// ordering by risk score. Degrade the same way ComputeSecretRiskScore's
		// own incomplete-exposure case does below, so callers can't tell the two
		// "the score is 0" cases apart from a real, verified low-risk secret.
		log.Printf("rotation plan: risk score for secret %d (%s): %v — treating as degraded, not silently zero", e.SecretID, e.SecretName, riskErr)
		riskDegraded = true
		riskDegradedReason = fmt.Sprintf("risk score: %v (treated as worst-case, not deprioritized)", riskErr)
	case riskScores[e.SecretID] != nil:
		r := riskScores[e.SecretID]
		riskScore, riskBand = r.Score, r.Band
		riskDegraded = r.Degraded
	default:
		// The secret is a candidate (it exists in RotationStatusEntry form) but has
		// no entry in the batch result — e.g. deleted between candidate listing and
		// the risk-score batch call. Same #486 treatment as an outright per-secret
		// error: never silently zero.
		log.Printf("rotation plan: risk score for secret %d (%s): not found in batch result — treating as degraded, not silently zero", e.SecretID, e.SecretName)
		riskDegraded = true
		riskDegradedReason = "risk score: secret not found (treated as worst-case, not deprioritized)"
	}

	pr := PlannedRotation{
		SecretID:     e.SecretID,
		SecretName:   e.SecretName,
		Status:       e.Status,
		DaysOverdue:  e.DaysOverdue,
		RiskScore:    riskScore,
		RiskBand:     riskBand,
		RiskDegraded: riskDegraded,
		Urgency:      rotationUrgency(e.Status, e.DaysOverdue, riskScore),
		AutoRotate:   e.AutoRotate,
	}

	if e.Status == RotationStatusOverdue {
		pr.Reasons = append(pr.Reasons, fmt.Sprintf("%d days overdue", e.DaysOverdue))
	} else {
		pr.Reasons = append(pr.Reasons, fmt.Sprintf("due in %d days", -e.DaysOverdue))
	}
	if riskScore >= 34 {
		pr.Reasons = append(pr.Reasons, fmt.Sprintf("%s risk (score %d)", riskBand, riskScore))
	}
	if riskDegraded {
		pr.Reasons = append(pr.Reasons, riskDegradedReason)
	}
	if e.AutoRotate {
		pr.Reasons = append(pr.Reasons, "self-rotating")
	}
	if len(deps) > 0 {
		slices.Sort(deps)
		pr.AfterSecretIDs = deps
		names := make([]string, 0, len(deps))
		for _, d := range deps {
			if dc, ok := candidates[d]; ok {
				names = append(names, dc.SecretName)
			}
		}
		if len(names) > 0 {
			pr.Reasons = append(pr.Reasons, "rotate after "+strings.Join(names, ", "))
		}
	}
	return pr
}

// moreUrgentEntry reports whether a is a more urgent rotation classification than b
// (overdue beats due_soon; within a class, the larger DaysOverdue is more urgent).
func moreUrgentEntry(a, b *RotationStatusEntry) bool {
	rank := func(s string) int {
		if s == RotationStatusOverdue {
			return 2
		}
		return 1
	}
	if ra, rb := rank(a.Status), rank(b.Status); ra != rb {
		return ra > rb
	}
	return a.DaysOverdue > b.DaysOverdue
}

// rotationUrgency scores a candidate so the plan rotates the most pressing secrets
// first. Overdue always outranks due-soon; within a class, more time past due (or less
// time remaining) and higher composite risk raise the score. Deterministic.
func rotationUrgency(status string, daysOverdue, riskScore int) int {
	base := 0
	switch status {
	case RotationStatusOverdue:
		// 1000 + days past due (capped so a single ancient secret can't dominate).
		over := min(daysOverdue, 365)
		base = 1000 + over
	case RotationStatusDueSoon:
		// 500 + (negative days-remaining) → closer to due ranks higher.
		base = 500 + daysOverdue
	}
	return base + riskScore
}

// rotationWaves partitions the candidate secrets into dependency-ordered waves via a
// level-by-level Kahn topological sort over the dependency subgraph induced by the
// candidates: wave 0 holds candidates with no in-plan dependency, and a candidate
// appears one wave after the last candidate it depends on. ok is false if a cycle
// prevents a complete ordering (not expected: the graph is acyclic by construction).
//
// Uses the same ready-queue approach as topologicalRotationOrder (#368): each wave's
// members are exactly the nodes a PRIOR wave's processing just brought to indegree
// zero, discovered by walking only THOSE nodes' outgoing edges — never a rescan of
// every remaining candidate. Each node is placed into exactly one wave and each edge
// is walked exactly once over the whole call, so the total work is O(V+E) rather
// than the O(V) per-wave rescan (up to O(V) waves deep) the prior implementation
// did, which made a long dependency chain O(V²).
func rotationWaves(edges []*models.SecretDependency, candidates map[uint]bool) (waves [][]uint, ok bool) {
	adj := map[uint][]uint{} // dependsOn -> dependents, among candidates
	indeg := make(map[uint]int, len(candidates))
	for id := range candidates {
		indeg[id] = 0
	}
	for _, e := range edges {
		if candidates[e.DependentSecretID] && candidates[e.DependsOnSecretID] {
			adj[e.DependsOnSecretID] = append(adj[e.DependsOnSecretID], e.DependentSecretID)
			indeg[e.DependentSecretID]++
		}
	}

	// Seed wave 0 with every candidate that has no in-plan dependency, smallest id
	// first for a deterministic, stable ordering.
	current := make([]uint, 0, len(candidates))
	for id := range candidates {
		if indeg[id] == 0 {
			current = append(current, id)
		}
	}
	slices.Sort(current)

	placed := 0
	for len(current) > 0 {
		waves = append(waves, current)
		placed += len(current)
		current = bfsNextWave(adj, current, indeg)
	}
	return waves, placed == len(candidates) // false = a cycle prevented a complete ordering
}

func bfsNextWave(adj map[uint][]uint, current []uint, indeg map[uint]int) []uint {
	next := []uint{}
	for _, id := range current {
		for _, dep := range adj[id] {
			indeg[dep]--
			if indeg[dep] == 0 {
				next = append(next, dep)
			}
		}
	}
	slices.Sort(next)
	return next
}

func collectRotationCandidates(status []*RotationStatusEntry) map[uint]*RotationStatusEntry {
	candidates := map[uint]*RotationStatusEntry{}
	for _, e := range status {
		if e.Status != RotationStatusOverdue && e.Status != RotationStatusDueSoon {
			continue
		}
		if prev, ok := candidates[e.SecretID]; !ok || moreUrgentEntry(e, prev) {
			candidates[e.SecretID] = e
		}
	}
	return candidates
}
