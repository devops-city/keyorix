package contracttest

const (
	reasonSchemaNotYetWritten = "schema not yet written"
	reason204NoContent        = "204 No Content -- no body to validate"
)

// pendingRegistry lists every operationId that has no 2xx JSON-Schema-bearing
// response in openapi.yaml yet. Every entry needs a reason -- this is a
// record of known gaps, not a dumping ground (ADR-074). Generated from a
// direct parse of openapi.yaml (see .scratch/classify_openapi.go in the PR
// that introduced this file) and verified equal to the spec via
// CheckPartition -- do not hand-edit without re-running that check.
//
// Adding a schema for an operation here does not require touching this map:
// CheckPartition fails the build if a pending entry's operation gains a
// schema, which is the signal to delete the entry -- the registry shrinks
// one operation at a time as ADR-074's Phase 2 handoff batches land.
var pendingRegistry = map[string]string{ // #nosec G101 -- operationId keys, not credentials; some contain "Token"/"PAT" (createPAT, issueMachineToken, ...), values are all the literal reason string "schema not yet written"
	"acknowledgeAnomalyAlert":            reasonSchemaNotYetWritten, // post /api/v1/audit/anomalies/{id}/acknowledge
	"addProjectMember":                   reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/members
	"assignPermissionToRole":             reasonSchemaNotYetWritten, // post /api/v1/roles/{id}/permissions
	"attestProjectAccessReview":          reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/access-review/attest
	"authLogout":                         reasonSchemaNotYetWritten, // post /auth/logout
	"authPasswordReset":                  reasonSchemaNotYetWritten, // post /auth/password-reset
	"closeAccessReviewCampaign":          reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close
	"createAccessRequest":                reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/access-requests
	"createGlobalInvitation":             reasonSchemaNotYetWritten, // post /api/v1/invitations
	"createRiskException":                reasonSchemaNotYetWritten, // post /api/v1/risk-exceptions
	"createSecretAccessRequest":          reasonSchemaNotYetWritten, // post /api/v1/secret-access-requests
	"createSoDPolicy":                    reasonSchemaNotYetWritten, // post /api/v1/sod/policies
	"createUser":                         reasonSchemaNotYetWritten, // post /api/v1/users
	"decideAccessReviewCampaignItem":     reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide
	"deleteEnvironment":                  reasonSchemaNotYetWritten, // delete /api/v1/environments/{id}
	"deleteOIDCBinding":                  reasonSchemaNotYetWritten, // delete /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}
	"deleteProject":                      reasonSchemaNotYetWritten, // delete /api/v1/projects/{id}
	"deleteSoDPolicy":                    reasonSchemaNotYetWritten, // delete /api/v1/sod/policies/{id}
	"endImpersonation":                   reasonSchemaNotYetWritten, // post /api/v1/auth/end-impersonation
	"exportAuditLogs":                    reasonSchemaNotYetWritten, // get /api/v1/audit/export
	"getAccessReviewCampaign":            reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/access-review/campaigns/{campaignId}
	"getAuditRetention":                  reasonSchemaNotYetWritten, // get /api/v1/audit/retention
	"getAuthConfig":                      reasonSchemaNotYetWritten, // get /api/v1/system/auth-config
	"getAuthProfile":                     reasonSchemaNotYetWritten, // get /api/v1/auth/profile
	"getComplianceControls":              reasonSchemaNotYetWritten, // get /api/v1/compliance/controls
	"getComplianceEvidence":              reasonSchemaNotYetWritten, // get /api/v1/compliance/evidence
	"getCompliancePosture":               reasonSchemaNotYetWritten, // get /api/v1/compliance/posture
	"getDashboardActivity":               reasonSchemaNotYetWritten, // get /api/v1/dashboard/activity
	"getDashboardStats":                  reasonSchemaNotYetWritten, // get /api/v1/dashboard/stats
	"getEncryptionConfig":                reasonSchemaNotYetWritten, // get /api/v1/system/encryption-config
	"getLegalHold":                       reasonSchemaNotYetWritten, // get /api/v1/legal-hold
	"getMostAccessedSecrets":             reasonSchemaNotYetWritten, // get /api/v1/secrets/usage/most-accessed
	"getProjectAccessReview":             reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/access-review
	"getProjectDrift":                    reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/drift
	"getProjectHealth":                   reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/health
	"getProjectHygiene":                  reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/hygiene
	"getProjectStats":                    reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/stats
	"getRotationStatus":                  reasonSchemaNotYetWritten, // get /api/v1/rotation-policies/status
	"getSecretAccessRequest":             reasonSchemaNotYetWritten, // get /api/v1/secret-access-requests/{requestId}
	"getSystemInfo":                      reasonSchemaNotYetWritten, // get /api/v1/system/info
	"getSystemMetrics":                   reasonSchemaNotYetWritten, // get /api/v1/system/metrics
	"getUnusedSecrets":                   reasonSchemaNotYetWritten, // get /api/v1/secrets/usage/unused
	"getUser":                            reasonSchemaNotYetWritten, // get /api/v1/users/{id}
	"getUserByEmail":                     reasonSchemaNotYetWritten, // get /api/v1/users/by-email
	"grantMachineRole":                   reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/machine-identities/{machineId}/roles
	"inviteMember":                       reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/memberships
	"liftLegalHold":                      reasonSchemaNotYetWritten, // delete /api/v1/legal-hold
	"listAccessRequests":                 reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/access-requests
	"listAccessReviewCampaigns":          reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/access-review/campaigns
	"listAnomalyAlerts":                  reasonSchemaNotYetWritten, // get /api/v1/audit/anomalies
	"listAuditLogs":                      reasonSchemaNotYetWritten, // get /api/v1/audit/logs
	"listNotifications":                  reasonSchemaNotYetWritten, // get /api/v1/notifications
	"listProjectMembers":                 reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/members
	"listProjectMemberships":             reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/memberships
	"listRiskExceptions":                 reasonSchemaNotYetWritten, // get /api/v1/risk-exceptions
	"listSecretAccessRequests":           reasonSchemaNotYetWritten, // get /api/v1/secret-access-requests
	"listSessions":                       reasonSchemaNotYetWritten, // get /api/v1/auth/sessions
	"listShares":                         reasonSchemaNotYetWritten, // get /api/v1/shares
	"listSoDPolicies":                    reasonSchemaNotYetWritten, // get /api/v1/sod/policies
	"listSoDViolations":                  reasonSchemaNotYetWritten, // get /api/v1/sod/violations
	"listStaleUsers":                     reasonSchemaNotYetWritten, // get /api/v1/users/stale
	"markAllNotificationsRead":           reasonSchemaNotYetWritten, // post /api/v1/notifications/read-all
	"markNotificationRead":               reasonSchemaNotYetWritten, // post /api/v1/notifications/{id}/read
	"mfaStepUp":                          reasonSchemaNotYetWritten, // post /api/v1/auth/mfa/stepup
	"openAccessReviewCampaign":           reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/access-review/campaigns
	"placeLegalHold":                     reasonSchemaNotYetWritten, // post /api/v1/legal-hold
	"reactivateUser":                     reasonSchemaNotYetWritten, // post /api/v1/users/{id}/reactivate
	"removeMachineRole":                  reasonSchemaNotYetWritten, // delete /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}
	"removeProjectMember":                reasonSchemaNotYetWritten, // delete /api/v1/projects/{id}/members/{userId}
	"requirePasswordReset":               reasonSchemaNotYetWritten, // post /api/v1/users/{id}/require-password-reset
	"resendSetupLink":                    reasonSchemaNotYetWritten, // post /api/v1/users/{id}/resend-setup-link
	"resolveAccessRequest":               reasonSchemaNotYetWritten, // put /api/v1/projects/{id}/access-requests/{requestId}
	"resolveSecretAccessRequest":         reasonSchemaNotYetWritten, // put /api/v1/secret-access-requests/{requestId}
	"restoreEnvironment":                 reasonSchemaNotYetWritten, // post /api/v1/projects/{projectId}/environments/{id}/restore
	"restoreProject":                     reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/restore
	"restoreUser":                        reasonSchemaNotYetWritten, // post /api/v1/users/{id}/restore
	"revokeBreakGlass":                   reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/break-glass/{activationId}/revoke
	"revokeMachineToken":                 reasonSchemaNotYetWritten, // delete /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}
	"revokeProjectAccessReview":          reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/access-review/revoke
	"revokeRiskException":                reasonSchemaNotYetWritten, // delete /api/v1/risk-exceptions/{id}
	"revokeUserSessions":                 reasonSchemaNotYetWritten, // post /api/v1/users/{id}/revoke-sessions
	"searchAuditLogs":                    reasonSchemaNotYetWritten, // get /api/v1/audit/search
	"searchUsers":                        reasonSchemaNotYetWritten, // get /api/v1/users/search
	"startImpersonation":                 reasonSchemaNotYetWritten, // post /api/v1/admin/impersonate
	"suspendInactiveUsers":               reasonSchemaNotYetWritten, // post /api/v1/admin/jobs/suspend-inactive-users
	"suspendUser":                        reasonSchemaNotYetWritten, // post /api/v1/users/{id}/suspend
	"transitionMachineIdentity":          reasonSchemaNotYetWritten, // put /api/v1/projects/{id}/machine-identities/{machineId}
	"transitionMembership":               reasonSchemaNotYetWritten, // put /api/v1/projects/{id}/memberships/{membershipId}
	"updateAuthProfile":                  reasonSchemaNotYetWritten, // put /api/v1/auth/profile
	"updateProjectMember":                reasonSchemaNotYetWritten, // put /api/v1/projects/{id}/members/{userId}
	"updateRotationPolicy":               reasonSchemaNotYetWritten, // put /api/v1/rotation-policies/{id}
	"updateUser":                         reasonSchemaNotYetWritten, // put /api/v1/users/{id}
	"updateUserRoles":                    reasonSchemaNotYetWritten, // put /api/v1/users/{id}/roles
	"verifyAuditChain":                   reasonSchemaNotYetWritten, // get /api/v1/audit/verify
	"verifyComplianceEvidence":           reasonSchemaNotYetWritten, // post /api/v1/compliance/evidence/verify
	"withdrawAccessRequest":              reasonSchemaNotYetWritten, // post /api/v1/projects/{id}/access-requests/{requestId}/withdraw
	"withdrawSecretAccessRequest":        reasonSchemaNotYetWritten, // post /api/v1/secret-access-requests/{requestId}/withdraw
	"writeAuditCheckpoint":               reasonSchemaNotYetWritten, // post /api/v1/audit/checkpoint
	"bulkApproveAccessRequests":          reasonSchemaNotYetWritten, // post /api/v1/access-requests/bulk-approve
	"bulkRejectAccessRequests":           reasonSchemaNotYetWritten, // post /api/v1/access-requests/bulk-reject
	"createAlertEscalationPolicy":        reasonSchemaNotYetWritten, // post /api/v1/alert-escalation-policies
	"createNotificationChannel":          reasonSchemaNotYetWritten, // post /api/v1/notification-channels
	"createRejectionReasonTemplate":      reasonSchemaNotYetWritten, // post /api/v1/rejection-reason-templates
	"deleteAlertEscalationPolicy":        reasonSchemaNotYetWritten, // delete /api/v1/alert-escalation-policies/{id}
	"deleteNotificationChannel":          reasonSchemaNotYetWritten, // delete /api/v1/notification-channels/{id}
	"deleteRejectionReasonTemplate":      reasonSchemaNotYetWritten, // delete /api/v1/rejection-reason-templates/{id}
	"getAnomalyConfig":                   reasonSchemaNotYetWritten, // get /api/v1/admin/anomaly-config
	"getNotificationChannel":             reasonSchemaNotYetWritten, // get /api/v1/notification-channels/{id}
	"listAlertEscalationPolicies":        reasonSchemaNotYetWritten, // get /api/v1/alert-escalation-policies
	"listNotificationChannels":           reasonSchemaNotYetWritten, // get /api/v1/notification-channels
	"listRejectionReasonTemplates":       reasonSchemaNotYetWritten, // get /api/v1/rejection-reason-templates
	"migrateAuditChainEncoding":          reasonSchemaNotYetWritten, // post /api/v1/audit/migrate-chain-encoding
	"runAlertEscalation":                 reasonSchemaNotYetWritten, // post /api/v1/admin/jobs/run-alert-escalation
	"runRoleExpiryCheck":                 reasonSchemaNotYetWritten, // post /api/v1/admin/jobs/role-expiry-check
	"runTokenExpiryCheck":                reasonSchemaNotYetWritten, // post /api/v1/admin/jobs/token-expiry-check
	"updateAnomalyConfig":                reasonSchemaNotYetWritten, // put /api/v1/admin/anomaly-config
	"updateNotificationChannel":          reasonSchemaNotYetWritten, // put /api/v1/notification-channels/{id}
	"approveRiskException":               reasonSchemaNotYetWritten, // post /api/v1/risk-exceptions/{id}/approve
	"exportComplianceControlsCSV":        reasonSchemaNotYetWritten, // get /api/v1/compliance/controls.csv
	"getComplianceCredentialTrends":      reasonSchemaNotYetWritten, // get /api/v1/compliance/credential-trends
	"getComplianceDigest":                reasonSchemaNotYetWritten, // get /api/v1/compliance/digest
	"getCompliancePermissionBaseline":    reasonSchemaNotYetWritten, // get /api/v1/compliance/permission-baseline
	"getCompliancePermissionBaselineCSV": reasonSchemaNotYetWritten, // get /api/v1/compliance/permission-baseline.csv
	"getCompliancePermissionChanges":     reasonSchemaNotYetWritten, // get /api/v1/compliance/permission-changes
	"getComplianceRotationByBackend":     reasonSchemaNotYetWritten, // get /api/v1/compliance/rotation-by-backend
	"getDeploymentHygiene":               reasonSchemaNotYetWritten, // get /api/v1/hygiene
	"getProjectSecretsInventoryCSV":      reasonSchemaNotYetWritten, // get /api/v1/projects/{id}/secrets/inventory.csv
	"getSecretsInventoryCSV":             reasonSchemaNotYetWritten, // get /api/v1/secrets/inventory.csv
	"sendComplianceDigest":               reasonSchemaNotYetWritten, // post /api/v1/compliance/digest/send
}

// outOfScopeRegistry lists every operationId that will never be enforced,
// by design, with the reason. Two shapes today:
//
//   - 204 No Content responses: nothing to validate a body against, by
//     definition (ADR-074) -- these are not gaps and don't belong in
//     pendingRegistry.
//   - prometheusMetrics: has a schema (text/plain), but it's promhttp's own
//     third-party handler, not code this repo owns, and no client will ever
//     be generated against Prometheus exposition format.
//
// A reason string here is NOT independently verified against the spec by
// CheckPartition -- it only checks that the entry doesn't ALSO have a real
// 2xx JSON schema, unless the operationId is in schemaExemptOperations
// below. That means the only way to legitimately opt a schema-bearing
// operation out of enforcement is to add it to schemaExemptOperations with
// its own justification, not just write a reason string here -- otherwise
// this map would be a silent, unaudited escape hatch from enforcement.
var outOfScopeRegistry = map[string]string{ // #nosec G101 -- operationId keys, not credentials; some contain "PAT"/"Session" (revokePAT, revokeSession, ...), values are all descriptive reason strings
	"bulkRevokeExpiredPATs":      reason204NoContent, // delete /api/v1/auth/tokens/expired
	"deleteGroup":                reason204NoContent, // delete /api/v1/groups/{id}
	"deleteRole":                 reason204NoContent, // delete /api/v1/roles/{id}
	"deleteRotationPolicy":       reason204NoContent, // delete /api/v1/rotation-policies/{id}
	"deleteSecret":               reason204NoContent, // delete /api/v1/secrets/{id}
	"deleteUser":                 reason204NoContent, // delete /api/v1/users/{id}
	"removeGroupMember":          reason204NoContent, // delete /api/v1/groups/{id}/members/{userId}
	"removePermissionFromRole":   reason204NoContent, // delete /api/v1/roles/{id}/permissions/{permissionId}
	"removeRoleFromGroup":        reason204NoContent, // delete /api/v1/groups/{id}/roles/{roleId}
	"removeSelfFromShare":        reason204NoContent, // delete /api/v1/secrets/{id}/self-share
	"removeUserRole":             reason204NoContent, // delete /api/v1/user-roles
	"revokePAT":                  reason204NoContent, // delete /api/v1/auth/tokens/{id}
	"revokeSession":              reason204NoContent, // delete /api/v1/auth/sessions/{id}
	"revokeShare":                reason204NoContent, // delete /api/v1/shares/{id}
	"deleteFolder":               reason204NoContent, // delete /api/v1/folders/{id}
	"deleteSecretSchedule":       reason204NoContent, // delete /api/v1/secrets/{id}/schedule
	"deleteSecretTemplate":       reason204NoContent, // delete /api/v1/secret-templates/{id}
	"deleteSecretVersionComment": reason204NoContent, // delete /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}
	"removeSecretDependency":     reason204NoContent, // delete /api/v1/secrets/{id}/dependencies/{depId}

	"prometheusMetrics": "promhttp.Handler, third-party code, no generated client will ever read Prometheus exposition format", // get /metrics
}

// schemaExemptOperations is the explicit, narrow allowlist of operationIds
// permitted to be BOTH in outOfScopeRegistry AND have a real 2xx JSON schema
// in openapi.yaml -- today, only prometheusMetrics (see its comment above).
// CheckPartition (checks.go) flags any other outOfScopeRegistry entry that
// also has a schema as a violation: without this allowlist, a reason string
// alone would let any schema-bearing operation be silently opted out of all
// contract enforcement while CI stays green.
var schemaExemptOperations = map[string]bool{
	"prometheusMetrics": true,
}

// exercisingTests maps each enforced operationId to the top-level test
// function name(s) that call AssertOpenAPIResponse for it. This exists
// only so CheckAllEnforcedExercised can stay correct under CI's test
// sharding (server/http/handlers runs as 4 separate `go test -run <regexp>`
// processes, split by test-name hash -- see the CheckAllEnforcedExercised
// doc comment in checks.go for why a process-global check alone isn't
// enough). Keep this in sync with the actual test file: if you move an
// AssertOpenAPIResponse call to a different top-level test function, update
// its entry here too, or the coverage check will report a false failure
// (loud, not silent -- an out-of-date entry here fails closed).
var exercisingTests = map[string][]string{
	"authGetSetupToken":             {"TestGetSetupToken_HappyPath_S11"},
	"authLogin":                     {"TestLogin_HappyPath_S8", "TestContractQA2_Login_MFARequiredBranch"},
	"authConsumeSetup":              {"TestConsumeSetup_HappyPath_S11"},
	"enrollMFA":                     {"TestContractQA2_EnrollMFA"},
	"activateMFA":                   {"TestContractQA2_ActivateMFA"},
	"changePassword":                {"TestContractRecover1_ChangePassword"},
	"disableMFA":                    {"TestContractQA2_DisableMFA"},
	"recoveryCodesStatus":           {"TestContractQA2_RecoveryCodesStatus"},
	"regenerateMFARecoveryCodes":    {"TestContractQA2_RegenerateRecoveryCodes"},
	"verifyMFALogin":                {"TestContractQA2_VerifyMFALogin"},
	"authRefresh":                   {"TestRefreshToken_ValidToken_S7"},
	"healthCheck":                   {"TestHealthCheck"},
	"getVersion":                    {"TestVersionHandler_ExposesOnlySkewFields"},
	"listSecretACLs":                {"TestListSecretACLs_Empty", "TestGrantSecretACL_HappyPath"},
	"systemInit":                    {"TestAuthHandler_InitSystem_Success"},
	"exportSecretAccessLog":         {"TestExportAccessLog_JSONFormat", "TestExportAccessLog_CSVFormat"},
	"exportAuditLogsCSV":            {"TestExportAuditLogsCSV"},
	"exportAccessReviewCampaignCSV": {"TestExportAccessReviewCampaignCSV"},
	// docs/cli-split-inventory.md §7 PR 2 (pat, auth mfa/logout, machine) --
	// openapi_contract_pr2_test.go.
	"createMachineIdentity": {"TestContractPR2_CreateMachineIdentity"},
	"createOIDCBinding":     {"TestContractPR2_CreateOIDCBinding"},
	"createPAT":             {"TestContractPR2_CreatePAT"},
	"getMachineAuditReport": {"TestContractPR2_GetMachineAuditReport"},
	"issueMachineToken":     {"TestContractPR2_IssueMachineToken"},
	"listExpiredPATs":       {"TestContractPR2_ListExpiredPATs"},
	"listMachineIdentities": {"TestContractPR2_ListMachineIdentities"},
	"listMachineRoles":      {"TestContractPR2_ListMachineRoles"},
	"listMachineTokens":     {"TestContractPR2_ListMachineTokens"},
	"listOIDCBindings":      {"TestContractPR2_ListOIDCBindings"},
	"listPATs":              {"TestContractPR2_ListPATs"},
	"listProjects":          {"TestContractPR2_ListProjects"},
	"machineTokenHygiene":   {"TestContractPR2_MachineTokenHygiene"},
	"patHygiene":            {"TestContractPR2_PATHygiene"},
	// docs/cli-split-inventory.md §7 PR 4 (secret core CRUD + metadata) --
	// openapi_contract_pr4_test.go.
	"addSecretDependency":       {"TestContractPR4_AddSecretDependency"},
	"addSecretVersionComment":   {"TestContractPR4_AddSecretVersionComment"},
	"classifySecret":            {"TestContractPR4_ClassifySecret"},
	"copyEnvironmentSecrets":    {"TestContractPR4_CopyEnvironmentSecrets"},
	"copySecret":                {"TestContractPR4_CopySecret"},
	"createFolder":              {"TestContractPR4_CreateFolder"},
	"createSecret":              {"TestContractPR4_CreateSecret"},
	"createSecretTemplate":      {"TestContractPR4_CreateSecretTemplate"},
	"describeSecret":            {"TestContractPR4_DescribeSecret"},
	"diffSecretVersions":        {"TestContractPR4_DiffSecretVersions"},
	"getSecret":                 {"TestContractPR4_GetSecret"},
	"getSecretAccessLog":        {"TestContractPR4_GetSecretAccessLog"},
	"getSecretByName":           {"TestContractPR4_GetSecretByName"},
	"getSecretImpact":           {"TestContractPR4_GetSecretImpact"},
	"getSecretSchedule":         {"TestContractPR4_GetSecretSchedule"},
	"getSecretTags":             {"TestContractPR4_GetSecretTags"},
	"getSecretValueByRef":       {"TestContractPR4_GetSecretValueByRef"},
	"getSecretVersions":         {"TestContractPR4_GetSecretVersions"},
	"grantSecretACL":            {"TestContractPR4_GrantSecretACL"},
	"listAccessors":             {"TestContractPR4_ListAccessors"},
	"listDeletedSecrets":        {"TestContractPR4_ListDeletedSecrets"},
	"listFolders":               {"TestContractPR4_ListFolders"},
	"listSecretDependencies":    {"TestContractPR4_ListSecretDependencies"},
	"listSecretTemplates":       {"TestContractPR4_ListSecretTemplates"},
	"listSecretVersionComments": {"TestContractPR4_ListSecretVersionComments"},
	"listSecrets":               {"TestContractPR4_ListSecrets"},
	"moveSecret":                {"TestContractPR4_MoveSecret"},
	"restoreSecret":             {"TestContractPR4_RestoreSecret"},
	"resumeSecret":              {"TestContractPR4_ResumeSecret"},
	"revokeSecretACL":           {"TestContractPR4_RevokeSecretACL"},
	"rollbackSecret":            {"TestContractPR4_RollbackSecret"},
	"setSecretSchedule":         {"TestContractPR4_SetSecretSchedule"},
	"setSecretTags":             {"TestContractPR4_SetSecretTags"},
	"suspendSecret":             {"TestContractPR4_SuspendSecret"},
	"updateSecret":              {"TestContractPR4_UpdateSecret"},
	// docs/cli-split-inventory.md §7 PR 3 (rbac, group, invite) --
	// openapi_contract_pr3_test.go.
	"addGroupMember":          {"TestContractPR3_AddGroupMember"},
	"assignRoleToGroup":       {"TestContractPR3_AssignRoleToGroup"},
	"assignUserRole":          {"TestContractPR3_AssignUserRole"},
	"createGroup":             {"TestContractPR3_CreateGroup"},
	"createProjectInvitation": {"TestContractPR3_CreateProjectInvitation"},
	"getGroup":                {"TestContractPR3_GetGroup"},
	"getGroupMembers":         {"TestContractPR3_GetGroupMembers"},
	"getGroupRoles":           {"TestContractPR3_GetGroupRoles"},
	"getPermissionMatrix":     {"TestContractPR3_GetPermissionMatrix"},
	"getRolePermissions":      {"TestContractPR3_GetRolePermissions"},
	"getUserRolesForUser":     {"TestContractPR3_GetUserRolesForUser"},
	"listGroups":              {"TestContractPR3_ListGroups"},
	"listProjectEnvironments": {"TestContractPR3_ListProjectEnvironments"},
	"listProjectInvitations":  {"TestContractPR3_ListProjectInvitations"},
	"listRBACAuditLogs":       {"TestContractPR3_ListRBACAuditLogs"},
	"listRoles":               {"TestContractPR3_ListRoles"},
	"listUsers":               {"TestContractPR3_ListUsers"},
	"resendProjectInvitation": {"TestContractPR3_ResendProjectInvitation"},
	"revokeProjectInvitation": {"TestContractPR3_RevokeProjectInvitation"},
	"updateGroup":             {"TestContractPR3_UpdateGroup"},
	// API-hygiene casing campaign, PR C3 (rbac: Roles/Permissions) --
	// openapi_contract_apihygiene_rbac_test.go.
	"createRole":            {"TestContractAPIHygiene_CreateRole"},
	"getRole":               {"TestContractAPIHygiene_GetRole"},
	"getRoleByName":         {"TestContractAPIHygiene_GetRoleByName"},
	"updateRole":            {"TestContractAPIHygiene_UpdateRole"},
	"listPermissions":       {"TestContractAPIHygiene_ListPermissions"},
	"getPermission":         {"TestContractAPIHygiene_GetPermission"},
	"getUserRoleAssignment": {"TestContractAPIHygiene_GetUserRoleAssignment"},
	// docs/cli-split-inventory.md §7 PR 1 (dynamic-secret, rotation, breakglass) --
	// openapi_contract_pr1_test.go.
	"activateBreakGlass":           {"TestContractPR1_ActivateBreakGlass"},
	"listBreakGlassActivations":    {"TestContractPR1_ListBreakGlassActivations"},
	"createDynamicSecretConfig":    {"TestContractPR1_CreateDynamicSecretConfig"},
	"listDynamicSecretConfigs":     {"TestContractPR1_ListDynamicSecretConfigs"},
	"getDynamicSecretConfig":       {"TestContractPR1_GetDynamicSecretConfig"},
	"classifyDynamicSecretConfig":  {"TestContractPR1_ClassifyDynamicSecretConfig"},
	"issueDynamicSecretLease":      {"TestContractPR1_IssueDynamicSecretLease"},
	"listDynamicSecretLeases":      {"TestContractPR1_ListDynamicSecretLeases"},
	"renewDynamicSecretLease":      {"TestContractPR1_RenewDynamicSecretLease"},
	"revokeDynamicSecretLease":     {"TestContractPR1_RevokeDynamicSecretLease"},
	"revokeAllDynamicSecretLeases": {"TestContractPR1_RevokeAllDynamicSecretLeases"},
	"listRotationPolicies":         {"TestContractPR1_ListRotationPolicies"},
	"createRotationPolicy":         {"TestContractPR1_CreateRotationPolicy"},
	"getRotationPolicy":            {"TestContractPR1_GetRotationPolicy"},
	"evaluateRotationPolicies":     {"TestContractPR1_EvaluateRotationPolicies"},
	"getProjectRotationOrder":      {"TestContractPR1_GetProjectRotationOrder"},
	"getProjectRotationPlan":       {"TestContractPR1_GetProjectRotationPlan"},
	"getDeploymentRotationPlan":    {"TestContractPR1_GetDeploymentRotationPlan"},
	// docs/cli-split-inventory.md §7 PR 9 (share) --
	// openapi_contract_pr9_test.go.
	"shareSecret":              {"TestContractPR9_ShareSecret"},
	"listSecretShares":         {"TestContractPR9_ListSecretShares"},
	"updateSharePermission":    {"TestContractPR9_UpdateSharePermission"},
	"listSharedSecrets":        {"TestContractPR9_ListSharedSecrets"},
	"listSharedSecretsForUser": {"TestContractPR9_ListSharedSecretsForUser"},
	"listGroupShares":          {"TestContractPR9_ListGroupShares"},
	// docs/cli-split-inventory.md §7 PR 5 (secret bulk/rotation/export/import/scan/
	// hygiene) -- openapi_contract_pr5_test.go.
	"listExpiringSecrets":             {"TestContractPR5_ListExpiringSecrets"},
	"listOrphanedSecrets":             {"TestContractPR5_ListOrphanedSecrets"},
	"secretNameConformance":           {"TestContractPR5_SecretNameConformance"},
	"deploymentSecretNameConformance": {"TestContractPR5_DeploymentSecretNameConformance"},
	"reassignSecretOwner":             {"TestContractPR5_ReassignSecretOwner"},
	"bulkRotateSecrets":               {"TestContractPR5_BulkRotateSecrets"},
	"bulkRenameSecrets":               {"TestContractPR5_BulkRenameSecrets"},
	"bulkDeleteSecrets":               {"TestContractPR5_BulkDeleteSecrets"},
	"renderSecretTemplate":            {"TestContractPR5_RenderTemplate"},
	"rotateSecret":                    {"TestContractPR5_RotateSecret"},
	"simulateSecretRotation":          {"TestContractPR5_SimulateRotation"},
	"setSecretAutoRotate":             {"TestContractPR5_SetAutoRotate"},
	"getSecretAuditTrail":             {"TestContractPR5_AuditTrail"},
	"getSecretOwnershipHistory":       {"TestContractPR5_OwnershipHistory"},
	"getSecretCertificate":            {"TestContractPR5_GetSecretCertificate"},
	"getSecretBlastRadius":            {"TestContractPR5_GetBlastRadius"},
	"getSecretRisk":                   {"TestContractPR5_GetSecretRisk"},
	"getQuotaReport":                  {"TestContractPR5_GetQuotaReport"},
	// FINISH-SPLIT census-gaps batch (docs/cli-split-inventory-census.md) --
	// openapi_contract_finishsplit_test.go.
	"getUsageReport":       {"TestContractFinishSplit_GetUsageReport"},
	"getBillingReport":     {"TestContractFinishSplit_GetBillingReport"},
	"migrateUserToMachine": {"TestContractFinishSplit_MigrateUserToMachine"},
	// API hygiene campaign (catalog_wire.go snake_case wire types) --
	// openapi_contract_catalog_test.go.
	"createProject":            {"TestContractCatalog_CreateProject"},
	"getProject":               {"TestContractCatalog_GetProject"},
	"updateProject":            {"TestContractCatalog_UpdateProject"},
	"createProjectEnvironment": {"TestContractCatalog_CreateProjectEnvironment"},
	"listEnvironments":         {"TestContractCatalog_ListEnvironments"},
	"cloneEnvironment":         {"TestContractCatalog_CloneEnvironment"},
	// #2781 (one definition of project membership) --
	// users_memberships_2781_test.go.
	"getUserMembershipsForUser": {"TestContract2781_GetUserMembershipsForUser"},
}
