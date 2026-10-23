// access_review.go — access recertification (ISO 27001 A.5.18 / SOC 2 CC6.2-6.3).
//
// GenerateProjectAccessReview enumerates who can reach a project's secrets and how:
// the role-based standing access (project-scoped role grants whose role confers a
// secrets.* permission) plus the per-secret grants (ownership and direct/group
// shares). Each entry's Source says which mechanism conferred the access.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AccessReviewEntry is one grant of access to a project's secrets, for an access
// review. Source distinguishes how the access is conferred:
//   - "role"          — a project-scoped role grant (project-wide; SecretID 0,
//     RoleName set, AccessLevel = the role's highest secrets.* action)
//   - "owner"         — the principal owns a specific secret (SecretID set)
//   - "direct_share"  — a secret shared directly with a user (SecretID set)
//   - "group_share"   — a secret shared with a group (SecretID set)
type AccessReviewEntry struct {
	PrincipalType string `json:"principal_type"` // "user" | "group" | "machine"
	PrincipalID   uint   `json:"principal_id"`
	PrincipalName string `json:"principal_name"` // username or group name
	Email         string `json:"email,omitempty"`
	Source        string `json:"source"` // role | owner | direct_share | group_share
	RoleID        uint   `json:"role_id,omitempty"`
	RoleName      string `json:"role_name,omitempty"`
	AccessLevel   string `json:"access_level"`   // read|write|delete|admin (role) or read|write|owner (share)
	EnvironmentID uint   `json:"environment_id"` // 0 = the whole project (role grants)
	SecretID      uint   `json:"secret_id,omitempty"`
	SecretName    string `json:"secret_name,omitempty"`
	// LastUsedAt is the principal's most recent secret access in the project (from
	// the audit trail) within the report's ActivityWindowDays — nil = no recorded
	// activity in that window, the signal for dormant standing access. Set for user
	// principals only; group last-use is not aggregated.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// AccessReviewReport is the full access-review result for a project: every
// grant (Entries) plus a signal for whether it is complete. #453: when
// LastUserSecretActivity's query fails, this human-facing, compliance-critical
// report's dormant-access signal (LastUsedAt) must not be silently left nil
// with no indication anything was missing — indistinguishable from "genuinely
// never used". Degraded + DegradedReasons make that detectable, mirroring
// CompliancePosture.Degraded (compliance_posture.go) and
// SecretAccessorsResult.Degraded (secret_access_list.go, #417).
type AccessReviewReport struct {
	Entries []*AccessReviewEntry `json:"entries"`
	// Degraded is true when the last-secret-access lookup could not be queried —
	// every entry's LastUsedAt is then unknown, never verified "never used" — or
	// when a grant applies in the project but is not among Entries: a legacy
	// grant at {project_id: 0, environment_id: an environment of this project}
	// (flagEnvironmentWithoutProjectGrants, ROLE-SHAPE-1), one reason per grant.
	Degraded bool `json:"degraded"`
	// DegradedReasons names the failed sub-query with its underlying error.
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
	// ActivityWindowDays is the look-back of every entry's LastUsedAt: the last N days
	// of the audit trail, the recertification period (capped at
	// storage.ActivityLookbackMaxDays). A nil LastUsedAt means no activity WITHIN this
	// window, not no activity ever.
	ActivityWindowDays int `json:"activity_window_days"`
}

// degrade records that a sub-query of the access review could not be answered:
// it flips Degraded and appends a human-readable reason, mirroring
// CompliancePosture.degrade (compliance_posture.go).
func (r *AccessReviewReport) degrade(area string, err error) {
	r.Degraded = true
	r.DegradedReasons = append(r.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

// secretsActionRank orders secrets.* actions so a review reports the strongest
// access a role confers.
var secretsActionRank = map[string]int{"read": 1, "write": 2, "delete": 3, "admin": 4}

// highestSecretsAction returns the strongest secrets.* action in a permission set,
// or "" when the role grants no secret access at all.
func highestSecretsAction(perms []*models.Permission) string {
	best, bestRank := "", 0
	for _, p := range perms {
		if p.Resource != "secrets" {
			continue
		}
		if r := secretsActionRank[p.Action]; r > bestRank {
			best, bestRank = p.Action, r
		}
	}
	return best
}

// nonSecretsAdminPermissions are permission names, outside the secrets resource,
// that confer administrative capability over the PROJECT itself — granting/
// revoking access for other principals, or install-wide control — rather than
// merely reading/writing secret values. Holding one of these makes a role
// "admin-tier" for roleIsAdminTier (#258), alongside secrets.delete/admin.
var nonSecretsAdminPermissions = map[string]bool{
	"roles.assign": true,
	"roles.write":  true,
	"roles.delete": true,
	"users.write":  true,
	"users.delete": true,
	"system.write": true,
	"system.admin": true,
}

// roleIsAdminTier reports whether a role's permission set confers administrative
// capability: destructive/whole-secret control (secrets.delete or secrets.admin) or
// the ability to manage who else has access (role assignment, user/system
// management) — as opposed to plain secrets.read/secrets.write.
//
// This is the classification behind the admin-tier half of dormant-role-grant
// detection (#258): a role's grant should only be considered "used" by ordinary
// secret-read/write activity when the role ITSELF is only read/write-tier. An
// admin-tier role (e.g. project_admin) needs evidence of an actually-exercised
// elevated action (see LastUserRoleManagementActivity / LastUserSecretDeletionActivity)
// — a user reading secrets under a separate, lower-tier grant must not mask an
// unused admin-tier standing grant.
//
// This is a practical approximation, not a perfect per-permission attribution: the
// audit trail records WHICH ACTION occurred (e.g. "a role was assigned"), not
// WHICH GRANT the actor invoked to authorize it. countDormantRoleGrants (#487)
// narrows this further than a single combined "elevated activity" bucket by
// checking each grant's OWN permission bundle against the specific capability the
// observed action demonstrates (role-management vs. secrets-deletion), so two
// admin-tier grants conferring DIFFERENT elevated capabilities no longer mask each
// other. Two admin-tier grants that bundle the SAME specific capability remain
// genuinely indistinguishable — either would have authorized the observed action,
// so both are credited.
func roleIsAdminTier(perms []*models.Permission) bool {
	for _, p := range perms {
		if p.Resource == "secrets" && (p.Action == "delete" || p.Action == "admin") {
			return true
		}
		if nonSecretsAdminPermissions[p.Name] {
			return true
		}
	}
	return false
}

// GenerateProjectAccessReview returns every grant of access to a project's secrets
// (ISO 27001 A.5.18): the role-based standing access (project-scoped role grants
// whose role confers a secrets.* permission) and the per-secret grants (ownership
// and direct/group shares). Each entry's Source identifies the mechanism. The
// returned report's Degraded/DegradedReasons signal when the dormant-access
// annotation (LastUsedAt) could not be computed, rather than silently reading as
// "no entry has ever been used" (#453).
func (c *KeyorixCore) GenerateProjectAccessReview(ctx context.Context, projectID uint) (*AccessReviewReport, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Machine identities (CI runners, k8s workloads, service accounts) are project
	// members with role grants exactly like users/groups, but were never enumerated
	// here — a privileged CI/k8s principal held a secrets.write/delete-conferring
	// role and passed through a "completed" recertification campaign entirely
	// un-attested (#91).
	machineAssignments, err := c.storage.ListProjectMachineRoleAssignments(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	assignments = append(assignments, machineAssignments...)

	res := newAccessReviewResolver(c.storage)
	report := &AccessReviewReport{}
	var entries []*AccessReviewEntry

	if err := c.appendRoleEntries(ctx, assignments, &entries, res); err != nil {
		return nil, err
	}
	secrets, err := c.listAllProjectSecrets(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	c.appendSecretGrantEntries(ctx, secrets, report, &entries, res)
	report.Entries = entries
	c.annotateLastUsedAt(ctx, entries, report, projectID)
	c.flagEnvironmentWithoutProjectGrants(ctx, projectID, report)
	return report, nil
}

// listAllProjectSecrets pages through every secret in a project (no silent cap).
func (c *KeyorixCore) listAllProjectSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	const pageSize = 500
	pid := projectID
	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			ProjectID: &pid, Page: page, PageSize: pageSize,
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

// roleInfo holds a role's name and its highest secrets.* action for an access review.
type roleInfo struct{ name, action string }

// accessReviewResolver caches storage lookups (roles, users, groups, machines) within
// a single access review so each entity is fetched at most once.
type accessReviewResolver struct {
	store    storage.Storage
	roles    map[uint]roleInfo
	users    map[uint][2]string // id → {username, email}
	groups   map[uint]string
	machines map[uint]string
}

func newAccessReviewResolver(store storage.Storage) *accessReviewResolver {
	return &accessReviewResolver{
		store:    store,
		roles:    map[uint]roleInfo{},
		users:    map[uint][2]string{},
		groups:   map[uint]string{},
		machines: map[uint]string{},
	}
}

// prefetch fills the user, group and machine caches for the given ids with one
// batched lookup per kind (LIST-ENDPOINTS-1), instead of one lookup per distinct
// principal. An id with no readable row is cached empty, exactly what a failed
// per-id lookup produced; a failed batch leaves the ids uncached so resolve* falls
// back to the per-id lookup.
func (r *accessReviewResolver) prefetch(ctx context.Context, userIDs, groupIDs, machineIDs []uint) {
	if ids := r.missing(userIDs, func(id uint) bool { _, ok := r.users[id]; return ok }); len(ids) > 0 {
		if briefs, err := r.store.GetUserBriefsByIDs(ctx, ids); err == nil {
			for _, id := range ids {
				b := briefs[id]
				r.users[id] = [2]string{b.Username, b.Email}
			}
		}
	}
	if ids := r.missing(groupIDs, func(id uint) bool { _, ok := r.groups[id]; return ok }); len(ids) > 0 {
		if names, err := r.store.GetGroupNamesByIDs(ctx, ids); err == nil {
			for _, id := range ids {
				r.groups[id] = names[id]
			}
		}
	}
	if ids := r.missing(machineIDs, func(id uint) bool { _, ok := r.machines[id]; return ok }); len(ids) > 0 {
		if names, err := r.store.GetMachineIdentityNamesByIDs(ctx, ids); err == nil {
			for _, id := range ids {
				r.machines[id] = names[id]
			}
		}
	}
}

// missing returns the distinct ids (never 0) that cached reports as not yet resolved.
func (r *accessReviewResolver) missing(ids []uint, cached func(uint) bool) []uint {
	seen := make(map[uint]struct{}, len(ids))
	var out []uint
	for _, id := range ids {
		if _, dup := seen[id]; dup || id == 0 || cached(id) {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func (r *accessReviewResolver) resolveRole(ctx context.Context, roleID uint) (roleInfo, error) {
	if ri, ok := r.roles[roleID]; ok {
		return ri, nil
	}
	perms, err := r.store.GetRolePermissions(ctx, roleID)
	if err != nil {
		return roleInfo{}, err
	}
	ri := roleInfo{action: highestSecretsAction(perms)}
	if role, err := r.store.GetRole(ctx, roleID); err == nil && role != nil {
		ri.name = role.Name
	}
	r.roles[roleID] = ri
	return ri, nil
}

func (r *accessReviewResolver) resolveUser(ctx context.Context, id uint) (string, string) {
	if ne, ok := r.users[id]; ok {
		return ne[0], ne[1]
	}
	ne := [2]string{}
	if u, err := r.store.GetUser(ctx, id); err == nil && u != nil {
		ne = [2]string{u.Username, u.Email}
	}
	r.users[id] = ne
	return ne[0], ne[1]
}

func (r *accessReviewResolver) resolveGroup(ctx context.Context, id uint) string {
	if n, ok := r.groups[id]; ok {
		return n
	}
	n := ""
	if g, err := r.store.GetGroup(ctx, id); err == nil && g != nil {
		n = g.Name
	}
	r.groups[id] = n
	return n
}

func (r *accessReviewResolver) resolveMachine(ctx context.Context, id uint) string {
	if n, ok := r.machines[id]; ok {
		return n
	}
	n := ""
	if m, err := r.store.GetMachineIdentity(ctx, id); err == nil && m != nil {
		n = m.Name
	}
	r.machines[id] = n
	return n
}

// appendRoleEntries adds role-based standing access entries for all project assignments
// (role grants whose role confers a secrets.* permission).
func (c *KeyorixCore) appendRoleEntries(ctx context.Context, assignments []storage.RoleAssignment, entries *[]*AccessReviewEntry, res *accessReviewResolver) error { // nosemgrep: keyorix-unbounded-bulk-slice-param -- assignments is a storage query result (existing role grants in the DB), not a raw client-supplied array in one request
	var userIDs, groupIDs, machineIDs []uint
	for _, a := range assignments {
		switch a.PrincipalType {
		case "group":
			groupIDs = append(groupIDs, a.PrincipalID)
		case "machine":
			machineIDs = append(machineIDs, a.PrincipalID)
		default:
			userIDs = append(userIDs, a.PrincipalID)
		}
	}
	res.prefetch(ctx, userIDs, groupIDs, machineIDs)
	for _, a := range assignments {
		ri, err := res.resolveRole(ctx, a.RoleID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		if ri.action == "" {
			continue // role grants no secret access
		}
		entry := &AccessReviewEntry{
			PrincipalType: a.PrincipalType,
			PrincipalID:   a.PrincipalID,
			Source:        "role",
			RoleID:        a.RoleID,
			RoleName:      ri.name,
			AccessLevel:   ri.action,
			EnvironmentID: a.EnvironmentID,
		}
		switch a.PrincipalType {
		case "group":
			entry.PrincipalName = res.resolveGroup(ctx, a.PrincipalID)
		case "machine":
			entry.PrincipalName = res.resolveMachine(ctx, a.PrincipalID)
		default:
			entry.PrincipalName, entry.Email = res.resolveUser(ctx, a.PrincipalID)
		}
		*entries = append(*entries, entry)
	}
	return nil
}

// appendSecretGrantEntries adds per-secret access entries: ownership and direct/group
// shares. #483: a transient share-list error for ONE secret degrades (not aborts) the
// report so that coverage for remaining secrets is not silently dropped.
func (c *KeyorixCore) appendSecretGrantEntries(ctx context.Context, secrets []*models.SecretNode, report *AccessReviewReport, entries *[]*AccessReviewEntry, res *accessReviewResolver) {
	// Every secret's active shares in batches (LIST-ENDPOINTS-1), not one
	// ListSharesBySecret per secret.
	sharesBySecret := make(map[uint][]*models.ShareRecord, len(secrets))
	failedShares := map[uint]error{}
	now := c.shareEffectiveNow()
	for start := 0; start < len(secrets); start += listBatchSize {
		end := min(start+listBatchSize, len(secrets))
		ids := make([]uint, 0, end-start)
		for _, s := range secrets[start:end] {
			ids = append(ids, s.ID)
		}
		batch, err := c.storage.ListSharesBySecretIDs(ctx, ids, now)
		if err != nil {
			// A failed batch falls back to per-secret lookups, so one bad read still
			// degrades only its own secret (#483) and not the whole chunk.
			for _, id := range ids {
				shares, serr := c.storage.ListSharesBySecret(ctx, id, now)
				if serr != nil {
					failedShares[id] = serr
					continue
				}
				sharesBySecret[id] = shares
			}
			continue
		}
		for _, sh := range batch {
			sharesBySecret[sh.SecretID] = append(sharesBySecret[sh.SecretID], sh)
		}
	}
	var userIDs, groupIDs []uint
	for _, s := range secrets {
		userIDs = append(userIDs, s.OwnerID)
		for _, sh := range sharesBySecret[s.ID] {
			if sh.IsGroup {
				groupIDs = append(groupIDs, sh.RecipientID)
			} else {
				userIDs = append(userIDs, sh.RecipientID)
			}
		}
	}
	res.prefetch(ctx, userIDs, groupIDs, nil)

	for _, s := range secrets {
		if s.OwnerID != 0 {
			name, email := res.resolveUser(ctx, s.OwnerID)
			*entries = append(*entries, &AccessReviewEntry{
				PrincipalType: "user", PrincipalID: s.OwnerID, PrincipalName: name, Email: email,
				Source: "owner", AccessLevel: "owner", SecretID: s.ID, SecretName: s.Name,
			})
		}
		if err := failedShares[s.ID]; err != nil {
			report.degrade(fmt.Sprintf("shares:secret=%d", s.ID), err)
			continue
		}
		for _, sh := range sharesBySecret[s.ID] {
			e := &AccessReviewEntry{
				PrincipalID: sh.RecipientID, AccessLevel: sh.Permission,
				SecretID: s.ID, SecretName: s.Name,
			}
			if sh.IsGroup {
				e.PrincipalType, e.Source = "group", "group_share"
				e.PrincipalName = res.resolveGroup(ctx, sh.RecipientID)
			} else {
				e.PrincipalType, e.Source = "user", "direct_share"
				e.PrincipalName, e.Email = res.resolveUser(ctx, sh.RecipientID)
			}
			*entries = append(*entries, e)
		}
	}
}

// annotateLastUsedAt stamps each user entry with their most recent secret-access time
// within the recertification period (dormant-access detection): an entry with no
// activity in the last report.ActivityWindowDays days keeps a nil LastUsedAt.
// #453: a lookup failure must degrade the report rather than silently leave every
// LastUsedAt nil — that would read as "no activity in the window."
func (c *KeyorixCore) annotateLastUsedAt(ctx context.Context, entries []*AccessReviewEntry, report *AccessReviewReport, projectID uint) {
	days := storage.ActivityLookbackDays(c.recertCadence())
	report.ActivityWindowDays = days
	activity, err := c.storage.LastUserSecretActivity(ctx, projectID, storage.ActivityLookbackSince(c.now(), days))
	if err != nil {
		report.degrade(fmt.Sprintf("last_used:project=%d", projectID), err)
		return
	}
	for _, e := range entries {
		if e.PrincipalType == "user" {
			if t, ok := activity[e.PrincipalID]; ok {
				tt := t
				e.LastUsedAt = &tt
			}
		}
	}
}
