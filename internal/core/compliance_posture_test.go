package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

// compliancePostureCore builds a bare KeyorixCore against a real (empty) sqlite DB —
// only models.Project is migrated, since accessGovernancePosture's ListProjects is the
// one call GetCompliancePosture treats as fatal; every other sub-rollup query errors
// (e.g. from a missing table) are expected to soft-fail into Degraded, not abort.
func compliancePostureCore(t *testing.T) *KeyorixCore {
	t.Helper()
	c, _ := compliancePostureCoreDB(t)
	return c
}

// compliancePostureCoreDB is compliancePostureCore but also returns the underlying
// *gorm.DB, so a test can AutoMigrate additional tables to control precisely which
// sub-rollup query fails (a not-migrated table) versus succeeds (migrated, empty).
func compliancePostureCoreDB(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.now = func() time.Time { return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC) }
	return c, db
}

// failingLegalHoldStore wraps LocalStorage and fails GetActiveLegalHold, simulating a DB
// error on that one sub-rollup while every other posture query still runs for real.
func failingLegalHoldStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		GetActiveLegalHold: func(_ storage.Storage, _ context.Context) (*models.LegalHold, error) {
			return nil, errors.New("simulated db failure")
		},
	})
}

// #136: before the fix, a failed legal-hold query left LegalHold.Active=false —
// byte-identical to "queried, no hold in effect". That's the most dangerous instance of
// the fail-open pattern: it's the signal purge jobs would otherwise trust to preserve
// records under hold, and it feeds an HMAC-signed evidence pack an auditor trusts. A query
// failure must surface as Degraded, not as a silently-clean zero value.
func TestGetCompliancePosture_DegradedOnLegalHoldQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t)
	c.storage = failingLegalHoldStore(c.storage.(*store.LocalStorage))

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.False(t, p.LegalHold.Active, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed legal-hold query must flip Degraded — the zero value above is UNKNOWN, not verified-clean")
	assert.True(t, containsSubstring(p.DegradedReasons, "legal_hold"), "expected a legal_hold entry in DegradedReasons, got %v", p.DegradedReasons)

	controls, err := c.GetComplianceControls(context.Background())
	require.NoError(t, err)
	lh := findControl(t, controls.Controls, "legal-hold")
	assert.Equal(t, ControlStatusUnknown, lh.Status, "the legal-hold CONTROL must surface as unknown, not silently pass, when its posture signal is degraded")
}

// #145: trust.DefaultRegistry() only errors when the embedded update/license signing-key
// material itself is malformed (a build/release integrity problem) — distinct from an
// ordinary unsigned/source build, which parses its empty key spec with a nil error. Before
// this fix, a registry-lookup failure left SupplyChain.TrustedUpdateKeys/UpdateSigningTrusted
// at their zero values — byte-identical to the expected "no keys pinned, ordinary dev build"
// state — masking a genuine "couldn't even check" failure as benign not-configured.
func TestGetCompliancePosture_DegradedOnSupplyChainTrustRegistryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t)
	c.SetTrustRegistryFunc(func() (*trust.KeyRegistry, error) {
		return nil, errors.New("simulated malformed embedded key data")
	})

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.False(t, p.SupplyChain.UpdateSigningTrusted, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed trust-registry lookup must flip Degraded — the zero value above is UNKNOWN, not a verified unsigned build")
	assert.True(t, containsSubstring(p.DegradedReasons, "supply_chain"), "expected a supply_chain entry in DegradedReasons, got %v", p.DegradedReasons)

	controls, err := c.GetComplianceControls(context.Background())
	require.NoError(t, err)
	sc := findControl(t, controls.Controls, "supply-chain-integrity")
	assert.Equal(t, ControlStatusUnknown, sc.Status, "the supply-chain-integrity CONTROL must surface as unknown, not silently not-configured, when its trust-registry lookup failed")
}

// failingRiskExceptionsStore wraps LocalStorage and fails ListRiskExceptions, simulating
// a DB error on the risk-exception sub-rollup.
func failingRiskExceptionsStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListRiskExceptions: func(_ storage.Storage, _ context.Context, _ bool) ([]*models.RiskException, error) {
			return nil, errors.New("simulated db failure")
		},
	})
}

// #136: empirically, dropping the risk_exceptions table flipped a real active exception
// from count=1 to count=0 — a query failure must surface as Degraded, not a silently-clean
// zero count.
func TestGetCompliancePosture_DegradedOnRiskExceptionQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t)
	c.storage = failingRiskExceptionsStore(c.storage.(*store.LocalStorage))

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.Equal(t, 0, p.Risk.ActiveExceptions, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed risk-exception query must flip Degraded")
	assert.True(t, containsSubstring(p.DegradedReasons, "risk"), "expected a risk entry in DegradedReasons, got %v", p.DegradedReasons)
}

// failingSoDPoliciesStore wraps LocalStorage and fails ListSoDPolicies, simulating a DB
// error on the SoD sub-rollup.
func failingSoDPoliciesStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSoDPolicies: func(_ storage.Storage, _ context.Context) ([]*models.SoDPolicy, error) {
			return nil, errors.New("simulated db failure")
		},
	})
}

// #136: empirically, dropping the sod_policies table flipped a real toxic-combination
// violation from count>=1 to count=0 — a query failure must surface as Degraded, not a
// silently-clean zero count.
func TestGetCompliancePosture_DegradedOnSoDPoliciesQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t)
	c.storage = failingSoDPoliciesStore(c.storage.(*store.LocalStorage))

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.Equal(t, 0, p.AccessGovernance.SoDViolations, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed SoD-policy query must flip Degraded")
	assert.True(t, containsSubstring(p.DegradedReasons, "sod_violations"), "expected a sod_violations entry in DegradedReasons, got %v", p.DegradedReasons)

	controls, err := c.GetComplianceControls(context.Background())
	require.NoError(t, err)
	sod := findControl(t, controls.Controls, "separation-of-duties")
	assert.Equal(t, ControlStatusUnknown, sod.Status, "the SoD CONTROL must surface as unknown, not silently pass, when its posture signal is degraded")
}

func containsSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// compliancePostureCoreWithProject is compliancePostureCoreDB plus one real project
// row, so accessGovernancePosture's per-project loop (campaigns / break-glass /
// dormant grants) actually runs instead of a no-op over zero projects.
func compliancePostureCoreWithProject(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	c, db := compliancePostureCoreDB(t)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	return c, db
}

// #358: GetRotationStatus's own error (e.g. a rotation-policy listing failure) must
// flip the posture's Rotation sub-rollup to degraded instead of leaving
// CoveredSecrets/Overdue/DueSoon at their zero-value "0 secrets overdue" reading.
func TestGetCompliancePosture_DegradedOnRotationQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t) // models.RotationPolicy deliberately NOT migrated

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.Equal(t, RotationPosture{}, p.Rotation, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed rotation query must flip Degraded — 0 overdue is UNKNOWN, not verified-clean")
	assert.True(t, containsSubstring(p.DegradedReasons, "rotation"), "expected a rotation entry in DegradedReasons, got %v", p.DegradedReasons)
}

// #359: a failed ListAnomalyAlerts query must not read as "no open alerts" — that masks
// active, unreviewed high-severity access anomalies.
func TestGetCompliancePosture_DegradedOnAnomalyQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t) // models.AnomalyAlert deliberately NOT migrated

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, AnomaliesPosture{}, p.Anomalies)
	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "anomalies"), "expected an anomalies entry in DegradedReasons, got %v", p.DegradedReasons)
}

// #360: classificationPosture has three separate Count...ByClassification calls
// (dynamic configs, machine identities, machine credentials) that each independently
// fail-opened to a zero (= "fully classified") count. Migrating SecretNode/Environment
// but NOT the three classification tables isolates exactly those three calls as the
// failure, demonstrating all three degrade independently in one pass.
func TestGetCompliancePosture_DegradedOnClassificationCountQueryErrors(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreDB(t)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}))
	// models.DynamicSecretConfig / MachineIdentity / MachineIdentityCredential deliberately NOT migrated.

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, ClassificationCounts{}, p.Classification.DynamicConfigs)
	assert.Equal(t, ClassificationCounts{}, p.Classification.MachineIdentities)
	assert.Equal(t, ClassificationCounts{}, p.Classification.MachineCredentials)
	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "classification:dynamic_configs"), "got %v", p.DegradedReasons)
	assert.True(t, containsSubstring(p.DegradedReasons, "classification:machine_identities"), "got %v", p.DegradedReasons)
	assert.True(t, containsSubstring(p.DegradedReasons, "classification:machine_credentials"), "got %v", p.DegradedReasons)
}

// #361(a): a project whose ListAccessReviewCampaigns query errors must not be silently
// dropped from ProjectsNeverReviewed/ProjectsWithOpenCampaign/PendingItems/ProjectsOverdue.
func TestGetCompliancePosture_DegradedOnAccessReviewCampaignsQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}, &models.UserRole{}, &models.Group{}, &models.GroupRole{}, &models.AuditEvent{}))
	// models.AccessReviewCampaign deliberately NOT migrated.

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "access_governance:campaigns:project=1"), "got %v", p.DegradedReasons)
}

// #361(b): a project's ListBreakGlassActivations error must not silently omit it from
// EmergencyAccess — the most severe of the three, since it hides CURRENTLY-ACTIVE
// emergency access from the report.
func TestGetCompliancePosture_DegradedOnBreakGlassQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.UserRole{}, &models.Group{}, &models.GroupRole{}, &models.AuditEvent{}))
	// models.BreakGlassActivation deliberately NOT migrated.

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, EmergencyAccessPosture{}, p.EmergencyAccess, "the field itself still reads as its zero value — no visible active break-glass")
	assert.True(t, p.Degraded, "an unqueryable break-glass register must flip Degraded rather than silently read as no emergency access")
	assert.True(t, containsSubstring(p.DegradedReasons, "emergency_access:project=1"), "got %v", p.DegradedReasons)
}

// #361(c): countDormantRoleGrants's two internal queries (ListProjectRoleAssignments,
// LastUserSecretActivity) must each independently degrade rather than silently return 0
// (undercounting stale privileged access) on a storage error.
func TestGetCompliancePosture_DegradedOnDormantRoleGrantsAssignmentsQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.AuditEvent{}))
	// models.UserRole / GroupRole deliberately NOT migrated → ListProjectRoleAssignments fails.

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, p.AccessGovernance.DormantRoleGrants)
	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "dormant_role_grants:assignments:project=1"), "got %v", p.DegradedReasons)
}

func TestGetCompliancePosture_DegradedOnDormantRoleGrantsActivityQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.UserRole{}, &models.GroupRole{}, &models.Group{}))
	// models.AuditEvent deliberately NOT migrated → LastUserSecretReadActivity's raw
	// "audit_events" table query fails (the first of the two plain-tier per-
	// permission activity queries countDormantRoleGrants runs, #487 round 112).

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, p.AccessGovernance.DormantRoleGrants)
	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "dormant_role_grants:read_activity:project=1"), "got %v", p.DegradedReasons)
}

// failingSecretWriteActivityStore wraps LocalStorage and fails
// LastUserSecretWriteActivity, simulating a DB error on the write half of the
// plain-tier per-permission activity split (#487 round 112) while
// LastUserSecretReadActivity itself still succeeds.
func failingSecretWriteActivityStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		LastUserSecretWriteActivity: func(_ storage.Storage, _ context.Context, _ uint, _ time.Time) (map[uint]time.Time, error) {
			return nil, errors.New("simulated db failure")
		},
	})
}

// #487 round 112: countDormantRoleGrants's plain-tier write-activity query must
// independently degrade rather than silently return 0 (undercounting stale
// standing access) on a storage error.
func TestGetCompliancePosture_DegradedOnDormantRoleGrantsWriteActivityQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.UserRole{}, &models.GroupRole{}, &models.AuditEvent{}, &models.Group{}))
	c.storage = failingSecretWriteActivityStore(c.storage.(*store.LocalStorage))

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, p.AccessGovernance.DormantRoleGrants)
	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "dormant_role_grants:write_activity:project=1"), "got %v", p.DegradedReasons)
}

// failingRoleManagementActivityStore wraps LocalStorage and fails
// LastUserRoleManagementActivity, simulating a DB error on one of the two
// admin-tier activity signals (#258/#487) while LastUserSecretActivity and
// LastUserSecretDeletionActivity themselves still succeed.
func failingRoleManagementActivityStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		LastUserRoleManagementActivity: func(_ storage.Storage, _ context.Context, _ uint, _ time.Time) (map[uint]time.Time, error) {
			return nil, errors.New("simulated db failure")
		},
	})
}

// #258/#487: countDormantRoleGrants's role-management activity query must
// independently degrade rather than silently return 0 (undercounting stale
// privileged access) on a storage error.
func TestGetCompliancePosture_DegradedOnDormantRoleGrantsRoleManagementActivityQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.UserRole{}, &models.GroupRole{}, &models.AuditEvent{}, &models.Group{}))
	c.storage = failingRoleManagementActivityStore(c.storage.(*store.LocalStorage))

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, p.AccessGovernance.DormantRoleGrants)
	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "dormant_role_grants:role_management_activity:project=1"), "got %v", p.DegradedReasons)
}

// failingSecretsDeletionActivityStore wraps LocalStorage and fails
// LastUserSecretDeletionActivity, the other admin-tier activity signal (#258/#487).
func failingSecretsDeletionActivityStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		LastUserSecretDeletionActivity: func(_ storage.Storage, _ context.Context, _ uint, _ time.Time) (map[uint]time.Time, error) {
			return nil, errors.New("simulated db failure")
		},
	})
}

func TestGetCompliancePosture_DegradedOnDormantRoleGrantsSecretsDeletionActivityQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.UserRole{}, &models.GroupRole{}, &models.AuditEvent{}, &models.Group{}))
	c.storage = failingSecretsDeletionActivityStore(c.storage.(*store.LocalStorage))

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, p.AccessGovernance.DormantRoleGrants)
	assert.True(t, p.Degraded)
	assert.True(t, containsSubstring(p.DegradedReasons, "dormant_role_grants:secrets_deletion_activity:project=1"), "got %v", p.DegradedReasons)
}
