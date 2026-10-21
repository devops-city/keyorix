package core

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type CreateRotationPolicyRequest struct {
	Name            string `json:"name" validate:"required,min=1,max=255"`
	Description     string `json:"description"`
	Scope           string `json:"scope" validate:"required,oneof=project environment"`
	ProjectID       *uint  `json:"project_id"`
	EnvironmentID   *uint  `json:"environment_id"`
	IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
	AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
	NotifyOnBreach  bool   `json:"notify_on_breach"`
	CreatedBy       string `json:"created_by" validate:"required"`
}

type UpdateRotationPolicyRequest struct {
	ID              uint   `json:"id" validate:"required"`
	Name            string `json:"name" validate:"required,min=1,max=255"`
	Description     string `json:"description"`
	IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
	AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
	NotifyOnBreach  bool   `json:"notify_on_breach"`
	IsActive        bool   `json:"is_active"`
}

type RotationPolicyEvaluation struct {
	PolicyID      uint       `json:"policy_id"`
	PolicyName    string     `json:"policy_name"`
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	ProjectID     uint       `json:"project_id"`
	LastRotatedAt *time.Time `json:"last_rotated_at"`
	DaysOverdue   int        `json:"days_overdue"` // positive = overdue, negative = days remaining
	IsOverdue     bool       `json:"is_overdue"`
	IsApproaching bool       `json:"is_approaching"`
}

// Rotation-policy lifecycle audit event types. Like other governance mutations,
// policy create/update/delete are recorded in the audit log.
const (
	EventRotationPolicyCreated = "rotation_policy.created"
	EventRotationPolicyUpdated = "rotation_policy.updated"
	EventRotationPolicyDeleted = "rotation_policy.deleted"
)

// CreateRotationPolicy creates a rotation policy. actorID is the admin performing it
// (0 = no authenticated principal).
func (c *KeyorixCore) CreateRotationPolicy(ctx context.Context, actorID uint, req *CreateRotationPolicyRequest) (*models.RotationPolicy, error) {
	if req.Scope == "environment" && req.EnvironmentID == nil {
		return nil, fmt.Errorf("environment_id is required when scope is 'environment'")
	}
	if req.Scope == "project" && req.ProjectID == nil {
		return nil, fmt.Errorf("project_id is required when scope is 'project'")
	}
	if req.AlertDaysBefore >= req.IntervalDays {
		return nil, fmt.Errorf("alert_days_before must be less than interval_days")
	}
	if err := validateDescription(req.Description); err != nil {
		return nil, err
	}

	// When an environment is given, resolve its true owning project and use that
	// to populate/validate ProjectID — never trust a caller-supplied ProjectID on
	// its own. Without this, a policy could be created (or, historically, an
	// environment-scoped policy's ProjectID could be left nil) with a
	// ProjectID/EnvironmentID pair that don't actually belong together;
	// scopedPolicySecrets then resolves the policy's secret scope from these two
	// fields, so a mismatched or missing ProjectID lets an environment-scoped
	// policy's secret lookup drift onto (or span) a different project entirely.
	// Mirrors CreateFolder's parent.ProjectID != projectID consistency check.
	effectiveProjectID := req.ProjectID
	if req.EnvironmentID != nil {
		env, err := c.storage.GetEnvironment(ctx, *req.EnvironmentID)
		if err != nil {
			return nil, fmt.Errorf("environment %d not found: %w", *req.EnvironmentID, err)
		}
		if req.ProjectID != nil && *req.ProjectID != env.ProjectID {
			return nil, fmt.Errorf("environment %d does not belong to project %d", *req.EnvironmentID, *req.ProjectID)
		}
		effectiveProjectID = &env.ProjectID
	}

	policy := &models.RotationPolicy{
		Name:            req.Name,
		Description:     req.Description,
		Scope:           req.Scope,
		ProjectID:       effectiveProjectID,
		EnvironmentID:   req.EnvironmentID,
		IntervalDays:    req.IntervalDays,
		AlertDaysBefore: req.AlertDaysBefore,
		NotifyOnBreach:  req.NotifyOnBreach,
		IsActive:        true,
		CreatedBy:       req.CreatedBy,
	}

	// AUDIT-TX-3: the policy and its audit row commit together (fail closed).
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.CreateRotationPolicy(ctx, policy); err != nil {
			return err
		}
		c.writeAuditEventFullOn(ctx, tgt, EventRotationPolicyCreated, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("rotation policy %q (id %d, %s scope) created", policy.Name, policy.ID, policy.Scope))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to create rotation policy: %w", err)
	}
	return policy, nil
}

func (c *KeyorixCore) GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error) {
	policy, err := c.storage.GetRotationPolicy(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}
	return policy, nil
}

func (c *KeyorixCore) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, projectID, environmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	return policies, nil
}

// UpdateRotationPolicy updates a rotation policy. See CreateRotationPolicy for actorID.
func (c *KeyorixCore) UpdateRotationPolicy(ctx context.Context, actorID uint, req *UpdateRotationPolicyRequest) (*models.RotationPolicy, error) {
	if req.AlertDaysBefore >= req.IntervalDays {
		return nil, fmt.Errorf("alert_days_before must be less than interval_days")
	}
	if err := validateDescription(req.Description); err != nil {
		return nil, err
	}

	policy, err := c.storage.GetRotationPolicy(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}

	// #2700: a column-scoped write of the six fields this request owns, onto a
	// row that is still live. The previous full-row Save persisted the whole
	// pre-read struct: its upsert fallback brought a concurrently deleted policy
	// back ACTIVE (resuming rotation and breach alerts), and it reverted the
	// executor's rotation_state/last_rotation_error, hiding a failed rotation.
	//
	// AUDIT-TX-3: the update and its audit row commit together (fail closed): a
	// rotation policy is never relaxed or deactivated unrecorded.
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		matched, uerr := tx.UpdateRotationPolicyFields(ctx, policy.ID, storage.RotationPolicyFieldUpdate{
			Name:            req.Name,
			Description:     req.Description,
			IntervalDays:    req.IntervalDays,
			AlertDaysBefore: req.AlertDaysBefore,
			NotifyOnBreach:  req.NotifyOnBreach,
			IsActive:        req.IsActive,
		}, c.now())
		if uerr != nil {
			return fmt.Errorf("failed to update rotation policy: %w", uerr)
		}
		if !matched {
			return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		policy.Name = req.Name
		policy.Description = req.Description
		policy.IntervalDays = req.IntervalDays
		policy.AlertDaysBefore = req.AlertDaysBefore
		policy.NotifyOnBreach = req.NotifyOnBreach
		policy.IsActive = req.IsActive
		c.writeAuditEventFullOn(ctx, tgt, EventRotationPolicyUpdated, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("rotation policy %q (id %d) updated", policy.Name, policy.ID))
		return nil
	}); err != nil {
		return nil, err
	}
	return policy, nil
}

// DeleteRotationPolicy deletes a rotation policy. See CreateRotationPolicy for actorID.
func (c *KeyorixCore) DeleteRotationPolicy(ctx context.Context, actorID, id uint) error {
	policy, err := c.storage.GetRotationPolicy(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get rotation policy: %w", err)
	}
	// AUDIT-TX-3: the delete and its audit row commit together (fail closed).
	return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.DeleteRotationPolicy(ctx, id); err != nil {
			return fmt.Errorf("failed to delete rotation policy: %w", err)
		}
		c.writeAuditEventFullOn(ctx, tgt, EventRotationPolicyDeleted, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("rotation policy %q (id %d) deleted", policy.Name, id))
		return nil
	})
}

// Rotation status values returned by GetRotationStatus.
const (
	RotationStatusOverdue = "overdue"
	RotationStatusDueSoon = "due_soon"
	RotationStatusOK      = "ok"
)

// RotationStatusEntry is the per-secret rotation posture under a policy. Unlike
// RotationPolicyEvaluation (which only surfaces overdue/approaching secrets),
// GetRotationStatus returns every policy-covered secret with an explicit status,
// so the dashboard can render a full inspector and a rotation health score.
type RotationStatusEntry struct {
	PolicyID        uint   `json:"policy_id"`
	PolicyName      string `json:"policy_name"`
	IntervalDays    int    `json:"interval_days"`
	AlertDaysBefore int    `json:"alert_days_before"`
	SecretID        uint   `json:"secret_id"`
	SecretName      string `json:"secret_name"`
	// ProjectID is the covered secret's project — always populated from the secret
	// row itself (no extra query), regardless of whether GetRotationStatus was
	// called project-scoped or deployment-wide. Lets a deployment-wide caller (the
	// hygiene rollup, #393) group entries by project without a per-project call.
	ProjectID         uint       `json:"project_id"`
	EnvironmentID     uint       `json:"environment_id"`
	LastRotatedAt     *time.Time `json:"last_rotated_at"`
	DaysSinceRotation int        `json:"days_since_rotation"`
	DaysOverdue       int        `json:"days_overdue"` // positive = overdue, negative = days remaining
	Status            string     `json:"status"`       // overdue | due_soon | ok
	// AutoRotate / RotationBackend surface whether this covered secret self-rotates
	// (ADR-046/047) and via which backend ("" = regenerate in Keyorix), so an operator
	// can tell a self-rotating secret from a reminder-only one at a glance.
	AutoRotate      bool   `json:"auto_rotate"`
	RotationBackend string `json:"rotation_backend,omitempty"`
}

// GetRotationStatus returns the rotation posture of every secret covered by an
// active rotation policy (optionally scoped to a project), classified as
// overdue / due_soon / ok. Secrets never rotated fall back to their creation
// time, mirroring EvaluateRotationPolicies.
// scopedPolicySecrets returns every secret in a rotation policy's scope, paging
// through all of them. Rotation evaluation must NOT silently cap: a project (or
// environment) with more than one page of secrets would otherwise have the
// secrets past the cap never checked for rotation — so overdue ones would be
// missed by both the reminder scheduler and the status/evaluate views.
func (c *KeyorixCore) scopedPolicySecrets(ctx context.Context, policy *models.RotationPolicy, reqEnvID *uint) ([]*models.SecretNode, error) {
	const pageSize = 500
	var projectID, environmentID *uint
	if policy.Scope == "project" {
		projectID = policy.ProjectID
		// When the caller restricted the view to a specific environment, confine a
		// PROJECT-scoped policy's secret enumeration to that environment too — otherwise
		// an environment-scoped reader would see secret metadata (name, last-rotated,
		// overdue status, backend) for every environment of the project. nil = all envs.
		environmentID = reqEnvID
	} else {
		// Environment-scoped policy: scope by BOTH the environment and its owning
		// project. EnvironmentID alone is not sufficient — LocalStorage.ListSecrets
		// only applies its project-ownership JOIN when ProjectID is non-nil, so an
		// environment-only filter matches every secret with that environment ID
		// across every project (environment IDs are not globally unique in
		// intent, just numerically). CreateRotationPolicy always populates
		// ProjectID from the environment's true owning project, so this is safe
		// for policies created after that fix; it's a no-op (still environment-
		// only) for any pre-existing policy whose ProjectID is nil.
		projectID = policy.ProjectID
		environmentID = policy.EnvironmentID
	}

	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			Page: page, PageSize: pageSize, ProjectID: projectID, EnvironmentID: environmentID,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, secrets...)
		if len(secrets) < pageSize || int64(len(all)) >= total {
			break
		}
	}
	return all, nil
}

// policyAppliesToEnv reports whether a policy should be included when the caller
// restricted the view to reqEnvID. A nil reqEnvID (project-wide / internal callers)
// includes everything. A project-scoped policy always applies (its secrets are then
// confined to reqEnvID by scopedPolicySecrets); an environment-scoped policy applies
// only when it targets reqEnvID, so a reader scoped to one environment can't see
// another environment's policy posture.
func policyAppliesToEnv(policy *models.RotationPolicy, reqEnvID *uint) bool {
	if reqEnvID == nil || policy.Scope == "project" {
		return true
	}
	return policy.EnvironmentID != nil && *policy.EnvironmentID == *reqEnvID
}

func (c *KeyorixCore) GetRotationStatus(ctx context.Context, projectID, environmentID *uint) ([]*RotationStatusEntry, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}

	var entries []*RotationStatusEntry
	now := c.now()
	var failedPolicies int

	for _, policy := range policies {
		if !policy.IsActive || !policyAppliesToEnv(policy, environmentID) {
			continue
		}

		secrets, err := c.scopedPolicySecrets(ctx, policy, environmentID)
		if err != nil {
			// #363: a per-policy scope-listing failure must not silently vanish that
			// policy's secrets from the result — every caller here (compliance
			// posture/evidence, the rotation-plan/status HTTP routes, the reminder
			// scheduler) already treats a non-nil error as "don't trust this result",
			// so failing the whole call (after logging + finishing the loop so every
			// failure is recorded) surfaces as degraded/unknown instead of a silently
			// short count that reads as "fully covered".
			log.Printf("rotation status: list secrets for policy %d (%q): %v", policy.ID, policy.Name, err)
			failedPolicies++
			continue
		}

		entries = appendSecretRotationEntries(entries, secrets, policy, now)
	}

	if failedPolicies > 0 {
		return nil, fmt.Errorf("rotation status: %d rotation polic(y/ies) could not be evaluated due to a storage error — result is incomplete", failedPolicies)
	}

	return entries, nil
}

// appendSecretRotationEntries builds RotationStatusEntry records for each secret
// covered by policy and appends them to entries. Extracted from GetRotationStatus
// to reduce its cognitive complexity.
func appendSecretRotationEntries(entries []*RotationStatusEntry, secrets []*models.SecretNode, policy *models.RotationPolicy, now time.Time) []*RotationStatusEntry {
	for _, secret := range secrets {
		lastRotated := secret.CreatedAt
		if secret.LastRotatedAt != nil {
			lastRotated = *secret.LastRotatedAt
		}

		daysSince := int(now.Sub(lastRotated).Hours() / 24)
		daysOverdue := daysSince - policy.IntervalDays

		status := RotationStatusOK
		if daysOverdue > 0 {
			status = RotationStatusOverdue
		} else if (policy.IntervalDays - daysSince) <= policy.AlertDaysBefore {
			status = RotationStatusDueSoon
		}

		entries = append(entries, &RotationStatusEntry{
			PolicyID:          policy.ID,
			PolicyName:        policy.Name,
			IntervalDays:      policy.IntervalDays,
			AlertDaysBefore:   policy.AlertDaysBefore,
			SecretID:          secret.ID,
			SecretName:        secret.Name,
			ProjectID:         secret.ProjectID,
			EnvironmentID:     secret.EnvironmentID,
			LastRotatedAt:     secret.LastRotatedAt,
			DaysSinceRotation: daysSince,
			DaysOverdue:       daysOverdue,
			Status:            status,
			AutoRotate:        secret.AutoRotate,
			RotationBackend:   secret.RotationBackend,
		})
	}
	return entries
}

func (c *KeyorixCore) EvaluateRotationPolicies(ctx context.Context, projectID, environmentID *uint) ([]*RotationPolicyEvaluation, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	policies, err := c.storage.ListRotationPolicies(ctx, projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}

	var evaluations []*RotationPolicyEvaluation
	now := c.now()
	var failedPolicies int

	for _, policy := range policies {
		if !policy.IsActive || !policyAppliesToEnv(policy, environmentID) {
			continue
		}

		secrets, err := c.scopedPolicySecrets(ctx, policy, environmentID)
		if err != nil {
			// #363: see the identical handling + rationale in GetRotationStatus above —
			// this result also feeds the admin-nudge reminder scheduler
			// (rotation_reminders.go), which already bails out on a non-nil error rather
			// than sending reminders derived from a silently-incomplete evaluation.
			log.Printf("rotation evaluate: list secrets for policy %d (%q): %v", policy.ID, policy.Name, err)
			failedPolicies++
			continue
		}

		for _, secret := range secrets {
			var lastRotated time.Time
			if secret.LastRotatedAt != nil {
				lastRotated = *secret.LastRotatedAt
			} else {
				lastRotated = secret.CreatedAt
			}

			daysSinceRotation := int(now.Sub(lastRotated).Hours() / 24)
			daysOverdue := daysSinceRotation - policy.IntervalDays
			isOverdue := daysOverdue > 0
			isApproaching := !isOverdue && (policy.IntervalDays-daysSinceRotation) <= policy.AlertDaysBefore

			if isOverdue || isApproaching {
				evaluations = append(evaluations, &RotationPolicyEvaluation{
					PolicyID:      policy.ID,
					PolicyName:    policy.Name,
					SecretID:      secret.ID,
					SecretName:    secret.Name,
					ProjectID:     secret.ProjectID,
					LastRotatedAt: secret.LastRotatedAt,
					DaysOverdue:   daysOverdue,
					IsOverdue:     isOverdue,
					IsApproaching: isApproaching,
				})
			}
		}
	}

	if failedPolicies > 0 {
		return nil, fmt.Errorf("rotation evaluate: %d rotation polic(y/ies) could not be evaluated due to a storage error — result is incomplete", failedPolicies)
	}

	return evaluations, nil
}
