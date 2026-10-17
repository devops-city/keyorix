// local_machine_credentials.go — machine-token credentials + machine role grants
// (ADR-030). Credentials mirror personal_access_tokens; role grants mirror
// user_roles. For the remote (HTTP) equivalent see remote_machine_identities.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Machine-token credentials ---

func (ls *LocalStorage) CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error) {
	if err := ls.db.WithContext(ctx).Create(c).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return c, nil
}

func (ls *LocalStorage) GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error) {
	var c models.MachineIdentityCredential
	if err := ls.db.WithContext(ctx).Where("token_hash = ?", hash).First(&c).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &c, nil
}

// credentialWithIdentityState scans a JOIN row: the credential's own columns
// (matched by name via the embedded struct, selected through modelColumns --
// kept in sync with models.MachineIdentityCredential automatically,
// no hand-maintained column list to drift) plus one extra scalar from the
// joined machine_identities row.
type credentialWithIdentityState struct {
	models.MachineIdentityCredential
	IdentityState string `gorm:"column:identity_state"`
}

// GetMachineIdentityCredentialWithIdentityStateByHash is the live
// revocation re-check every machine-token request runs, cache hit or miss
// (PR-1/PR-2 deliberately never cache it). H3 (PERF-3): served from a
// hand-written prepared statement (credential_lookup_raw.go) when
// available — see that file's header for why, and
// TestCredentialLookupRaw_MatchesGORM_Fuzz for the proof the two paths
// agree. Falls back to the original GORM query unchanged whenever the raw
// path isn't available (transaction-scoped LocalStorage, or a prepare
// failure) — this method's observable behavior is identical either way.
//
// A request that asked for the read-path fold (PERF-LEVER2) gets the same
// credential from a statement that also reads one secret's node; see
// local_folded_credential.go. Whenever that cannot answer, this runs as before.
func (ls *LocalStorage) GetMachineIdentityCredentialWithIdentityStateByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, string, error) {
	if cred, state, handled := ls.foldedCredentialLookup(ctx, hash); handled {
		return cred, state, nil
	}
	if cred, state, handled, err := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, hash); handled {
		return cred, state, err
	}
	var row credentialWithIdentityState
	err := ls.db.WithContext(ctx).
		Table("machine_identity_credentials AS c").
		Select(modelColumns(ls.db, &models.MachineIdentityCredential{}, "c")+", m.state AS identity_state").
		Joins("JOIN machine_identities AS m ON m.id = c.machine_identity_id").
		Where("c.token_hash = ?", hash).
		First(&row).Error
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &row.MachineIdentityCredential, row.IdentityState, nil
}

func (ls *LocalStorage) GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error) {
	var c models.MachineIdentityCredential
	if err := ls.db.WithContext(ctx).First(&c, id).Error; err != nil {
		// G80: was an unconditional "not found" wrap regardless of the underlying
		// error, so a genuine storage failure (e.g. a closed/unreachable DB) read
		// identically to a real not-found to any caller doing the same string-match
		// server/http/handlers.isNotFoundErr does -- UpdateMachineIdentityCredentialProxy
		// (server/http/handlers/machine_identities_proxy.go), added as part of the
		// same G80 fix that first called this method from that handler, surfaced
		// this as a wrong 404 instead of 500 for a real storage error. Distinguish
		// genuine not-found (gorm.ErrRecordNotFound) from everything else, matching
		// GetUser's (local_users.go) already-established pattern.
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &c, nil
}

func (ls *LocalStorage) ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error) {
	var rows []*models.MachineIdentityCredential
	err := ls.db.WithContext(ctx).
		Where("machine_identity_id = ?", machineID).
		Order(sqlOrderCreatedAtDesc).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// ListActiveMachineIdentityCredentials returns every non-revoked machine credential,
// newest first — the deployment-wide token-hygiene view.
func (ls *LocalStorage) ListActiveMachineIdentityCredentials(ctx context.Context) ([]*models.MachineIdentityCredential, error) {
	var rows []*models.MachineIdentityCredential
	err := ls.db.WithContext(ctx).
		Where("revoked = ?", false).
		Order(sqlOrderCreatedAtDesc).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// SetMachineIdentityCredentialClassification persists ONLY the classification
// column, conditional on the row's current classification still being
// fromClassification — see the storage.Storage interface doc for why the
// full-row UpdateMachineIdentityCredential this replaced (a bare Save) could
// un-revoke a concurrently revoked token (#2696).
//
// COALESCE so a NULL column (a row written before Classification existed) is
// matched by fromClassification "", the value GORM reads it back as — the same
// treatment SetAccountStateIfMatches gives account_state.
//
// There is deliberately no updated_at here: MachineIdentityCredential has no
// such column (only CreatedAt and the separately-stamped LastUsedAt).
func (ls *LocalStorage) SetMachineIdentityCredentialClassification(ctx context.Context, credentialID uint, fromClassification, toClassification string) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.MachineIdentityCredential{}).
		Where("id = ? AND COALESCE(classification, '') = ?", credentialID, fromClassification).
		// A map, not a struct: GORM writes every map entry including a zero
		// value, so clearing the label (level "") actually persists the empty
		// string rather than being skipped as "unset".
		Updates(map[string]any{"classification": toClassification})
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

func (ls *LocalStorage) CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error) {
	return countByClassification(ctx, ls.db, &models.MachineIdentityCredential{})
}

// RevokeMachineIdentityCredential's project_id filter (#1551) is enforced via
// a subquery against machine_identities rather than a join, matching this
// package's existing UpdateColumn-conditional-write idiom (single statement,
// no separate read).
func (ls *LocalStorage) RevokeMachineIdentityCredential(ctx context.Context, projectID, credentialID uint) error {
	result := ls.db.WithContext(ctx).Model(&models.MachineIdentityCredential{}).
		Where("id = ? AND machine_identity_id IN (?)", credentialID,
			ls.db.Model(&models.MachineIdentity{}).Select("id").Where("project_id = ?", projectID)).
		UpdateColumn("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// #1507: this UpdateColumn write bypasses model hooks, so last_used_at is
// whatever Location usedAt itself carries (currently always c.now(), via
// TouchMachineTokenLastUsed) — CountStaleMachineCredentials
// (local_hygiene_counts.go), reachable today from GetHygieneTrends/
// RecordHygieneTrendPoint (server/http/handlers/hygiene_trends.go), already
// range-queries this same column with a bound derived from the SAME k.now()
// accessor. Safe only as long as both stay on that one source. If either
// side ever switches to a differently-sourced time (e.g. a raw
// time.Now().UTC()), normalize explicitly at this call site (there is no
// BeforeSave hook that can reach an UpdateColumn write) before trusting the
// comparison.
func (ls *LocalStorage) TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	cutoff := usedAt.Add(-staleness)
	return ls.db.WithContext(ctx).Model(&models.MachineIdentityCredential{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", id, cutoff).
		UpdateColumn("last_used_at", usedAt).Error
}

// --- Machine role grants ---

func (ls *LocalStorage) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	var existing models.MachineIdentityRole
	err := ls.db.WithContext(ctx).
		Where("machine_identity_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			machineID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
	if err == nil {
		return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	grant := models.MachineIdentityRole{
		MachineIdentityID: machineID,
		RoleID:            roleID,
		ProjectID:         scope.ProjectID,
		EnvironmentID:     scope.EnvironmentID,
	}
	if err := ls.db.WithContext(ctx).Create(&grant).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where("machine_identity_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			machineID, roleID, scope.ProjectID, scope.EnvironmentID).Delete(&models.MachineIdentityRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotAssigned", nil))
	}
	return nil
}

// GetMachineRoleIDsAt returns the role IDs granted to the machine that apply at
// the target scope — a grant applies when its project is global or equal AND its
// environment is global or equal (mirrors GetUserRoleIDsAt).
//
// A scoped (non-zero) project_id/environment_id must ALSO NOT resolve to a
// soft-deleted project/environment row — mirroring the deleted_at join
// GetUserRoleIDsAt/GetUserGroupRoleIDsAt apply for the same reason (#161/#312).
// Without it, a machine role bound directly to a project/environment ID keeps
// authorizing regardless of that project's/environment's own soft-delete state,
// so deletion doesn't work as an access boundary for machine principals either.
// The LEFT JOINs (not INNER) are required because project_id/environment_id 0
// means "global" and has no corresponding row to join against — the "= 0 OR ..."
// clause short-circuits before the joined columns are consulted in that case; a
// scoped project_id/environment_id with no matching row at all (the joined column
// is SQL NULL) is treated as not-deleted, same as every other "unknown" scope ID
// this query already tolerates.
func (ls *LocalStorage) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.MachineIdentityRole{}).
		Joins("LEFT JOIN projects ON projects.id = machine_identity_roles.project_id").
		Joins("LEFT JOIN environments ON environments.id = machine_identity_roles.environment_id").
		Where("machine_identity_roles.machine_identity_id = ?", machineID).
		Where("machine_identity_roles.project_id = 0 OR (machine_identity_roles.project_id = ? AND projects.deleted_at IS NULL)", scope.ProjectID).
		Where("machine_identity_roles.environment_id = 0 OR (machine_identity_roles.environment_id = ? AND environments.deleted_at IS NULL)", scope.EnvironmentID).
		Distinct().Pluck("machine_identity_roles.role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// GetMachineRoles returns every role granted to the machine (any scope), for
// display only (e.g. rendering a machine's role list in an admin UI/CLI).
//
// It is intentionally UNSCOPED — it returns roles across every project/
// environment flattened into one list, with no deleted_at gate on the scope
// project/environment (unlike GetMachineRoleIDsAt). Do NOT reuse this result
// for an authorization decision: a role granted only for a now-soft-deleted or
// entirely different project would wrongly authorize (#308). Use
// GetMachineRoleIDsAt for any authorization path instead.
//
// (#308) As defense in depth, RequireRole (server/middleware) additionally
// refuses to gate on a machine principal at all, so even this method's output
// reaching a machine's userCtx.Roles cannot be paired with an unscoped
// role-name check to bypass scoping — but that guard lives at the consumer,
// not here, so any OTHER future unscoped role-name check written against this
// method's result would reintroduce the same bypass. Do not add one; use
// GetMachineRoleIDsAt / core.Authorize instead.
func (ls *LocalStorage) GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN machine_identity_roles ON roles.id = machine_identity_roles.role_id").
		Where("machine_identity_roles.machine_identity_id = ?", machineID).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetMachineRoleScopes returns the distinct (project, environment) scopes at
// which machineID holds ANY role grant, directly (machine_identity_roles) —
// the machine-identity mirror of GetUserRoleScopes (G33). Machine identities
// have no group-membership concept (unlike users' group_roles), so this is a
// single-source query. See the storage.Storage interface doc for why this
// exists: a scope-DISCOVERY step so a caller can enumerate every scope a
// machine actually holds a grant at, then evaluate GetMachineRoleIDsAt per
// scope, instead of resolving only the global scope as actorRoleIDs (connect.go)
// used to before this fix.
func (ls *LocalStorage) GetMachineRoleScopes(ctx context.Context, machineID uint) ([]storage.Scope, error) {
	type scopeRow struct {
		ProjectID     uint
		EnvironmentID uint
	}
	var rows []scopeRow
	if err := ls.db.WithContext(ctx).Model(&models.MachineIdentityRole{}).
		Select("project_id, environment_id").
		Where("machine_identity_id = ?", machineID).
		Group("project_id, environment_id").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	scopes := make([]storage.Scope, 0, len(rows))
	for _, r := range rows {
		scopes = append(scopes, storage.Scope{ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID})
	}
	return scopes, nil
}

// --- OIDC bindings (ADR-031) ---

func (ls *LocalStorage) CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error) {
	if err := ls.db.WithContext(ctx).Create(b).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return b, nil
}

// GetMachineByOIDCSubject resolves the machine identity bound to (issuer, subject).
func (ls *LocalStorage) GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error) {
	var m models.MachineIdentity
	err := ls.db.WithContext(ctx).
		Table("machine_identities").
		Joins("JOIN machine_identity_oidc_bindings b ON b.machine_identity_id = machine_identities.id").
		Where("b.issuer = ? AND b.subject = ?", issuer, subject).
		First(&m).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &m, nil
}

func (ls *LocalStorage) ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error) {
	var rows []*models.MachineIdentityOIDCBinding
	err := ls.db.WithContext(ctx).
		Where("machine_identity_id = ?", machineID).
		Order(sqlOrderCreatedAtDesc).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// GetOIDCBindingByID used to wrap EVERY error from First (not just a genuine
// gorm.ErrRecordNotFound) with the "not found" i18n string -- surfaced by
// DeleteOIDCBindingProxy's G80 fix, which now reads the binding before
// deleting it (to resolve its owning machine/project): a real connection
// failure got mislabeled as "not found" and the proxy handler's
// isNotFoundErr string match then reported 404 instead of 500 for a genuine
// storage outage. Matches the established gorm.ErrRecordNotFound-vs-
// everything-else pattern this package already uses elsewhere (e.g.
// local_sod.go's GetSoDPolicy, fixed the same way for the identical reason).
func (ls *LocalStorage) GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error) {
	var b models.MachineIdentityOIDCBinding
	err := ls.db.WithContext(ctx).First(&b, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &b, nil
}

func (ls *LocalStorage) DeleteOIDCBinding(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.MachineIdentityOIDCBinding{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}
