package contracttest

import "testing"

// TestOpenAPIRegistryPartition is the load-bearing check from ADR-074: every
// operation in openapi.yaml must land in exactly one of enforced,
// pending-with-reason, or out-of-scope-with-reason. Fails the build in
// either direction -- see CheckPartition.
func TestOpenAPIRegistryPartition(t *testing.T) {
	if err := CheckPartition(); err != nil {
		t.Fatal(err)
	}
}

// TestExercisingTestsExist guards registry.go's exercisingTests map, itself
// a hand-maintained list, against naming a test function that has been
// renamed or deleted -- see CheckExercisingTestsExist's doc comment for why
// nothing else in this package would otherwise catch that.
func TestExercisingTestsExist(t *testing.T) {
	if err := CheckExercisingTestsExist(); err != nil {
		t.Fatal(err)
	}
}

// TestSpecLoadsAndValidates guards the harness's own precondition: if
// openapi.yaml stops parsing or fails OpenAPI validation, every test using
// AssertOpenAPIResponse would fail with the same underlying cause. This
// isolates that failure mode to one clearly-named test.
func TestSpecLoadsAndValidates(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	if spec == nil || router == nil {
		t.Fatal("contracttest: loadSpec succeeded but left spec or router nil")
	}
}

// TestEnforcedSetMatchesADR074 pins the exact 10-operation enforced set
// (schema'd minus outOfScopeRegistry's prometheusMetrics -- see ADR-074's
// "honest enforced baseline" section for which of these carry a real
// structured schema vs. a near-content-free `{type: string, format:
// binary}` one) so a future change to openapi.yaml's schema coverage is
// visible here, not just via a silently growing/shrinking set.
//
// getVersion added by ADR-108 PR 0 (docs/cli-split-inventory.md §5):
// GET /api/v1/version carries a real `api_version`/`minimum_cli_version`
// schema from the day it was added, not a later backfill.
//
// The 13 machine/PAT/project operations below were added by ADR-108 PR 2
// (docs/cli-split-inventory.md §7): the thin CLI's generated client needs a
// real response schema to produce typed accessors, so this batch backfilled
// schemas for these previously-schema-less (or brand new, e.g. the OIDC
// binding trio) operations and exercises each via openapi_contract_pr2_test.go.
//
// The 35 secret-core-CRUD-and-metadata operations below were added by
// ADR-108 PR 4 (docs/cli-split-inventory.md §7): 8 (createSecret, getSecret,
// updateSecret, getSecretVersions, grantSecretACL, revokeSecretACL,
// classifySecret, listSecrets) backfilled schemas for previously-schema-less
// existing routes; the other 27 are brand-new routes added in the same PR.
// Each is exercised via openapi_contract_pr4_test.go.
// The 20 rbac/group/invite operations below (plus the brand-new
// getPermissionMatrix, which had no openapi.yaml entry at all before) were
// added by ADR-108 PR 3 (docs/cli-split-inventory.md §7), exercised via
// openapi_contract_pr3_test.go.
//
// The 18 dynamic-secret/rotation-policy/break-glass operations below were
// added by ADR-108 PR 1 (docs/cli-split-inventory.md §7, "dynamic-secret,
// rotation, breakglass -- 9+7+3 = 19 commands"): the thin CLI's generated
// client needs real response schemas to produce typed accessors for these
// routes, most of which existed and were already called by the old CLI's
// remote mode but were entirely undocumented in this spec until now
// (dynamic-secrets, rotation-plan/order) or had only a narrative,
// schema-less description (rotation-policies, break-glass).
// getRotationStatus/deleteRotationPolicy/revokeBreakGlass are deliberately
// NOT in this batch: deleteRotationPolicy is 204 No Content (nothing to
// schema); getRotationStatus and revokeBreakGlass stay in pendingRegistry
// since none of PR 1's 19 commands needed a typed accessor for them beyond
// what the envelope's bare success/message already gives the CLI.
//
// The 6 share operations below were added by ADR-108 PR 9 (docs/cli-split-
// inventory.md §7, "share -- 7 commands"): shareSecret, listSecretShares, and
// updateSharePermission had only a narrative, schema-less description before
// this; listSharedSecrets/listSharedSecretsForUser/listGroupShares needed one
// for the first time. removeSelfFromShare (also new to the spec, a 204) and
// revokeShare (already schema-less-by-design, also 204) are deliberately NOT
// in this batch -- both are 204 No Content, tracked in outOfScopeRegistry
// instead, matching every other 204 route in this package.
func TestEnforcedSetMatchesADR074(t *testing.T) {
	want := map[string]bool{
		"authGetSetupToken":             true,
		"authLogin":                     true,
		"authRefresh":                   true,
		"healthCheck":                   true,
		"getVersion":                    true,
		"listSecretACLs":                true,
		"systemInit":                    true,
		"exportSecretAccessLog":         true,
		"exportAuditLogsCSV":            true,
		"exportAccessReviewCampaignCSV": true,
		"createMachineIdentity":         true,
		"createOIDCBinding":             true,
		"createPAT":                     true,
		"getMachineAuditReport":         true,
		"issueMachineToken":             true,
		"listExpiredPATs":               true,
		"listMachineIdentities":         true,
		"listMachineRoles":              true,
		"listMachineTokens":             true,
		"listOIDCBindings":              true,
		"listPATs":                      true,
		"listProjects":                  true,
		"machineTokenHygiene":           true,
		"patHygiene":                    true,
		"addGroupMember":                true,
		"assignRoleToGroup":             true,
		"assignUserRole":                true,
		"createGroup":                   true,
		"createProjectInvitation":       true,
		"getGroup":                      true,
		"getGroupMembers":               true,
		"getGroupRoles":                 true,
		"getPermissionMatrix":           true,
		"getRolePermissions":            true,
		"getUserRolesForUser":           true,
		"listGroups":                    true,
		"listProjectEnvironments":       true,
		"listProjectInvitations":        true,
		"listRBACAuditLogs":             true,
		"listRoles":                     true,
		"listUsers":                     true,
		"resendProjectInvitation":       true,
		"revokeProjectInvitation":       true,
		"updateGroup":                   true,
		"activateBreakGlass":            true,
		"listBreakGlassActivations":     true,
		"createDynamicSecretConfig":     true,
		"classifyDynamicSecretConfig":   true,
		"getDynamicSecretConfig":        true,
		"issueDynamicSecretLease":       true,
		"listDynamicSecretConfigs":      true,
		"listDynamicSecretLeases":       true,
		"renewDynamicSecretLease":       true,
		"revokeAllDynamicSecretLeases":  true,
		"revokeDynamicSecretLease":      true,
		"createRotationPolicy":          true,
		"evaluateRotationPolicies":      true,
		"getRotationPolicy":             true,
		"listRotationPolicies":          true,
		"getProjectRotationOrder":       true,
		"getProjectRotationPlan":        true,
		"getDeploymentRotationPlan":     true,
		"shareSecret":                   true,
		"listSecretShares":              true,
		"updateSharePermission":         true,
		"listSharedSecrets":             true,
		"listSharedSecretsForUser":      true,
		"listGroupShares":               true,
		// The 18 secret bulk/rotation/hygiene operations below were added by ADR-108
		// PR 5 (docs/cli-split-inventory.md §7): 2 (rotateSecret, getSecretRisk)
		// backfilled schemas for previously-schema-less existing routes; the other 16
		// are brand-new routes added in the same PR. Each is exercised via
		// openapi_contract_pr5_test.go.
		"addSecretDependency":             true,
		"addSecretVersionComment":         true,
		"classifySecret":                  true,
		"copyEnvironmentSecrets":          true,
		"copySecret":                      true,
		"createFolder":                    true,
		"createSecret":                    true,
		"createSecretTemplate":            true,
		"describeSecret":                  true,
		"diffSecretVersions":              true,
		"getSecret":                       true,
		"getSecretAccessLog":              true,
		"getSecretByName":                 true,
		"getSecretImpact":                 true,
		"getSecretSchedule":               true,
		"getSecretTags":                   true,
		"getSecretValueByRef":             true,
		"getSecretVersions":               true,
		"grantSecretACL":                  true,
		"listAccessors":                   true,
		"listDeletedSecrets":              true,
		"listFolders":                     true,
		"listSecretDependencies":          true,
		"listSecretTemplates":             true,
		"listSecretVersionComments":       true,
		"listSecrets":                     true,
		"moveSecret":                      true,
		"restoreSecret":                   true,
		"resumeSecret":                    true,
		"revokeSecretACL":                 true,
		"rollbackSecret":                  true,
		"setSecretSchedule":               true,
		"setSecretTags":                   true,
		"suspendSecret":                   true,
		"updateSecret":                    true,
		"listExpiringSecrets":             true,
		"listOrphanedSecrets":             true,
		"secretNameConformance":           true,
		"deploymentSecretNameConformance": true,
		"reassignSecretOwner":             true,
		"bulkRotateSecrets":               true,
		"bulkRenameSecrets":               true,
		"bulkDeleteSecrets":               true,
		"renderSecretTemplate":            true,
		"rotateSecret":                    true,
		"simulateSecretRotation":          true,
		"setSecretAutoRotate":             true,
		"getSecretAuditTrail":             true,
		"getSecretOwnershipHistory":       true,
		"getSecretCertificate":            true,
		"getSecretBlastRadius":            true,
		"getSecretRisk":                   true,
		"getQuotaReport":                  true,
		// FINISH-SPLIT census-gaps batch (docs/cli-split-inventory-census.md): the last
		// 3 command-census gaps ported to the thin CLI. Each is exercised via
		// openapi_contract_finishsplit_test.go.
		"getUsageReport":       true,
		"getBillingReport":     true,
		"migrateUserToMachine": true,
		// API-hygiene casing campaign, PR C3 (rbac: Roles/Permissions): these
		// 7 backfilled schemas for previously-schema-less (or, for
		// getRoleByName, entirely undocumented) routes whose handlers were
		// sending internal/storage/models.Role/Permission straight to the
		// wire with no json tags at all -- fixed to go through the
		// handler-level roleWire/permissionWire/roleWithPermissionsWire/
		// userRoleAssignmentWire types (rbac_wire.go). Each is exercised via
		// openapi_contract_apihygiene_rbac_test.go.
		"createRole":            true,
		"getRole":               true,
		"getRoleByName":         true,
		"updateRole":            true,
		"listPermissions":       true,
		"getPermission":         true,
		"getUserRoleAssignment": true,
		// API hygiene campaign (catalog_wire.go snake_case wire types) added
		// response schemas for these 6 Projects/Environments operations. Each is
		// exercised via openapi_contract_catalog_test.go.
		"createProject":            true,
		"getProject":               true,
		"updateProject":            true,
		"createProjectEnvironment": true,
		"listEnvironments":         true,
		"cloneEnvironment":         true,
		// QA-2 session: closed a real contract gap found while investigating
		// #2441/#2442 -- the self-service MFA lifecycle (enroll/activate/
		// disable/recovery-codes/regenerate), the mfa_required branch of
		// /auth/login (authLogin was already enforced; this just adds a
		// second response shape to it), /auth/mfa/verify, and
		// /auth/setup/consume had either NO openapi.yaml entry at all (the
		// 5 MFA lifecycle routes, verifyMFALogin) or a prose-only one
		// (authConsumeSetup). Each is exercised via
		// openapi_contract_qa2_mfa_test.go (plus TestConsumeSetup_HappyPath_S11
		// for authConsumeSetup).
		"enrollMFA":                  true,
		"activateMFA":                true,
		"disableMFA":                 true,
		"recoveryCodesStatus":        true,
		"regenerateMFARecoveryCodes": true,
		"verifyMFALogin":             true,
		"authConsumeSetup":           true,

		// #2781 (one definition of project membership): the per-user membership
		// view gained a response schema when it stopped answering from the ADR-022
		// onboarding journal -- users_memberships_2781_test.go.
		"getUserMembershipsForUser": true,

		// #3024: change-password's 200 gained data.reauthentication_required (a
		// setup-only session ends when the password change finishes setup) --
		// openapi_contract_recover1_test.go.
		"changePassword": true,
	}

	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	got := enforcedOperationIDs()

	for opID := range want {
		if !got[opID] {
			t.Errorf("expected %s to be enforced, it is not", opID)
		}
	}
	for opID := range got {
		if !want[opID] {
			t.Errorf("%s is enforced but not in ADR-074's expected set -- "+
				"update this test if that's an intentional new schema", opID)
		}
	}
}
