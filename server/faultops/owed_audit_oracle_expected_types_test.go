// owed_audit_oracle_expected_types_test.go -- the owed-audit rule's PINNED per-op table.
//
// The rule learns which audit rows an op owes from a probe (owedAuditProbeFor: refuse
// LogAuditEvent#1..n and read what gets queued). A probe cannot see its own blind spot:
// if a revocation regressed to a plain best-effort audit row, the probe would learn
// "owes nothing" for it, the rule would stop engaging, and every sweep case would stay
// green. This table is written by hand, from what each operation is supposed to owe, and
// TestOwedAuditOracle_SweepEveryScopedOp compares the probe against it exactly (event
// type -> number of rows), so a revocation that stops owing a row, owes a different one,
// or owes one more or fewer, fails here.
//
// Changing an entry is a decision about what a revocation owes the audit log: do it in
// the same change as the code, and say why in the commit.
package faultops

// owedAuditExpectedOwedTypes: scoped op -> owed audit event type -> row count.
var owedAuditExpectedOwedTypes = map[string]map[string]int{
	// SSO / SAML: the shared group and role reconcile (sso.go) removes memberships and
	// roles the IdP no longer grants. The SSO callback does both; the SAML ACS scenario
	// revokes the JIT baseline role only.
	owedAuditSSOCallbackOp: {"group.member_removed": 1, "role.removed": 1},
	owedAuditSAMLACSOp:     {"role.removed": 1},

	"REST DELETE /api/v1/user-roles/":                                                   {"role.removed": 1},
	"REST DELETE /api/v1/environments/{id}":                                             {"environment.deleted": 1},
	"GRPC keyorix.v1.ProjectService.DeleteProject":                                      {"project.deleted": 1},
	"REST DELETE /api/v1/projects/{id}":                                                 {"project.deleted": 1},
	"GRPC keyorix.v1.RoleService.RemoveRole":                                            {"role.removed": 1},
	"REST DELETE /api/v1/groups/{id}/roles/{roleId}":                                    {"role.group_removed": 1},
	"REST DELETE /api/v1/roles/{id}/permissions/{permissionId}":                         {"permission.removed": 1},
	"REST DELETE /api/v1/roles/{id}":                                                    {"role.deleted": 1},
	"GRPC keyorix.v1.RoleService.DeleteRole":                                            {"role.deleted": 1},
	"REST DELETE /api/v1/groups/{id}/members/{userId}":                                  {"group.member_removed": 1},
	"GRPC keyorix.v1.GroupService.RemoveGroupMember":                                    {"group.member_removed": 1},
	"REST DELETE /api/v1/groups/{id}":                                                   {"group.deleted": 1},
	"GRPC keyorix.v1.GroupService.DeleteGroup":                                          {"group.deleted": 1},
	"REST DELETE /api/v1/projects/{id}/members/{userId}":                                {"role.removed": 1},
	"REST DELETE /api/v1/shares/{id}":                                                   {"share_revoked": 1},
	"GRPC keyorix.v1.ShareService.RevokeShare":                                          {"share_revoked": 1},
	"REST DELETE /api/v1/secrets/{id}/acl/{aclId}":                                      {"secret.acl_revoked": 1},
	"GRPC keyorix.v1.SecretService.RevokeSecretACL":                                     {"secret.acl_revoked": 1},
	"REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}": {"machine_identity.token_revoked": 1},
	"GRPC keyorix.v1.MachineIdentityService.RevokeMachineToken":                         {"machine_identity.token_revoked": 1},
	"REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}":   {"machine_identity.role_removed": 1},
	"GRPC keyorix.v1.MachineIdentityService.TransitionMachineIdentity":                  {"machine_identity.suspended": 1},
	"REST DELETE /api/v1/auth/tokens/{id}":                                              {"pat.revoked": 1},
	"REST DELETE /api/v1/auth/sessions/{id}":                                            {"session.revoked": 1},
	"REST POST /api/v1/users/{id}/revoke-sessions":                                      {"account.sessions_revoked": 1},
	"REST POST /api/v1/users/{id}/suspend":                                              {"account.suspended": 1},
	"REST DELETE /api/v1/users/{id}":                                                    {"user.deleted": 1},
	"GRPC keyorix.v1.UserService.DeleteUser":                                            {"user.deleted": 1},
	"REST POST /api/v1/projects/{id}/break-glass/{activationId}/revoke":                 {"break_glass.revoked": 1, "role.removed": 1},
	"GRPC keyorix.v1.BreakGlassService.RevokeBreakGlass":                                {"break_glass.revoked": 1, "role.removed": 1},
	"REST DELETE /api/v1/projects/{id}/invitations/{invitationId}":                      {"invitation.revoked": 1},
	"REST POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw":              {"access_request.withdrawn": 1},
	"REST DELETE /api/v1/risk-exceptions/{id}":                                          {"risk.exception_revoked": 1},
	"REST DELETE /scim/v2/Groups/{id}":                                                  {"scim.group_deprovisioned": 1},
}
