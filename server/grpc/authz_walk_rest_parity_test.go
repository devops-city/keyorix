package grpc_test

// authz_walk_rest_parity_test.go — AUTHZ-WALKS-GRPC-1 item 3
// (INV-GRPC-rest-walk-parity).
//
// The REST authorization walks (server/http: permission_sweep_test.go, the PAT
// read-family sweep, ...) cover every route family. This test keeps the gRPC
// walks (authz_walk_lowpriv_test.go, authz_walk_dead_credential_test.go) aligned
// with them: a route family is either reachable over gRPC, and then walked here
// automatically because the walks enumerate GetServiceInfo, or it is listed as
// REST-only with a reason. Adding an RPC for a family that is listed REST-only,
// or a REST family nobody classified, fails.
//
// DEVIATION from the brief, which asked for the proto's HTTP annotations:
// keyorix.proto carries no google.api.http annotations (ADR-106, the proto-first
// generated surface, is withdrawn — see INV-GRPC-06), so there is nothing to read.
// The two sides are therefore both DERIVED and the join between them is a small
// reasoned table, checked from both ends:
//
//   - gRPC side: the live server's registered methods (GetServiceInfo);
//   - REST side: scripts/e2e/routes.json, the route inventory that
//     server/http TestRouteInventoryIsCurrent regenerates from router.go's AST on
//     every run and fails on drift, so it cannot go stale silently.
//
// The table (grpcToREST) is the only hand-written part. Every entry must name a
// real registered method and a real REST route, every registered method must have
// an entry, and every REST family must be covered by at least one entry or listed
// in restOnlyFamilies.
//
// What this does NOT cover: route-level parity INSIDE a covered family (the
// secrets family has ~58 REST routes and 12 RPCs; ADR-105 says gRPC is a partial
// data-plane API on purpose), and whether the two transports reach the same
// decision for the same principal — that is INV-GRPC-02
// (grpc_rest_authz_parity_fuzz_test.go) for secret reads and the two walks for
// the low-privilege and dead-credential cases.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
)

// grpcToREST maps every registered "service/method" to the REST route that does
// the same job ("METHOD pattern", as in scripts/e2e/routes.json), or to "" with a
// reason in grpcOnlyReason when REST has no counterpart.
var grpcToREST = map[string]string{
	"keyorix.v1.SecretService/CreateSecret":           "POST /api/v1/secrets",
	"keyorix.v1.SecretService/GetSecret":              "GET /api/v1/secrets/{id}",
	"keyorix.v1.SecretService/GetSecretValue":         "GET /api/v1/secrets/value",
	"keyorix.v1.SecretService/UpdateSecret":           "PUT /api/v1/secrets/{id}",
	"keyorix.v1.SecretService/DeleteSecret":           "DELETE /api/v1/secrets/{id}",
	"keyorix.v1.SecretService/ListSecrets":            "GET /api/v1/secrets",
	"keyorix.v1.SecretService/GetSecretVersions":      "GET /api/v1/secrets/{id}/versions",
	"keyorix.v1.SecretService/SetSecretAutoRotate":    "PATCH /api/v1/secrets/{id}/auto-rotate",
	"keyorix.v1.SecretService/ListSecretDependencies": "GET /api/v1/secrets/{id}/dependencies",
	"keyorix.v1.SecretService/GetSecretImpact":        "GET /api/v1/secrets/{id}/impact",
	"keyorix.v1.SecretService/GrantSecretACL":         "POST /api/v1/secrets/{id}/acl",
	"keyorix.v1.SecretService/RevokeSecretACL":        "DELETE /api/v1/secrets/{id}/acl/{aclId}",
	"keyorix.v1.SecretService/ListSecretACLs":         "GET /api/v1/secrets/{id}/acl",

	"keyorix.v1.ShareService/ShareSecret":           "POST /api/v1/secrets/{id}/share",
	"keyorix.v1.ShareService/ListSecretShares":      "GET /api/v1/secrets/{id}/shares",
	"keyorix.v1.ShareService/ListUserShares":        "GET /api/v1/shares/owned",
	"keyorix.v1.ShareService/ListSharedSecrets":     "GET /api/v1/shared-secrets",
	"keyorix.v1.ShareService/UpdateSharePermission": "PUT /api/v1/shares/{id}",
	"keyorix.v1.ShareService/RevokeShare":           "DELETE /api/v1/shares/{id}",

	"keyorix.v1.UserService/CreateUser":             "POST /api/v1/users",
	"keyorix.v1.UserService/GetUser":                "GET /api/v1/users/{id}",
	"keyorix.v1.UserService/UpdateUser":             "PUT /api/v1/users/{id}",
	"keyorix.v1.UserService/DeleteUser":             "DELETE /api/v1/users/{id}",
	"keyorix.v1.UserService/ListUsers":              "GET /api/v1/users",
	"keyorix.v1.UserService/ReissueOneTimePassword": "POST /api/v1/users/{id}/reissue-one-time-password",

	"keyorix.v1.RoleService/CreateRole":   "POST /api/v1/roles",
	"keyorix.v1.RoleService/GetRole":      "GET /api/v1/roles/{id}",
	"keyorix.v1.RoleService/UpdateRole":   "PUT /api/v1/roles/{id}",
	"keyorix.v1.RoleService/DeleteRole":   "DELETE /api/v1/roles/{id}",
	"keyorix.v1.RoleService/ListRoles":    "GET /api/v1/roles",
	"keyorix.v1.RoleService/AssignRole":   "POST /api/v1/user-roles",
	"keyorix.v1.RoleService/RemoveRole":   "DELETE /api/v1/user-roles",
	"keyorix.v1.RoleService/GetUserRoles": "GET /api/v1/user-roles/user/{userId}",

	"keyorix.v1.AuditService/GetAuditLogs":         "GET /api/v1/audit/logs",
	"keyorix.v1.AuditService/GetRBACAuditLogs":     "GET /api/v1/audit/rbac-logs",
	"keyorix.v1.AuditService/StreamAuditLogs":      "",
	"keyorix.v1.AuditService/VerifyAuditChain":     "GET /api/v1/audit/verify",
	"keyorix.v1.AuditService/WriteAuditCheckpoint": "POST /api/v1/audit/checkpoint",
	"keyorix.v1.AuditService/GetAuditRetention":    "GET /api/v1/audit/retention",

	"keyorix.v1.SystemService/HealthCheck":   "GET /health",
	"keyorix.v1.SystemService/GetSystemInfo": "GET /api/v1/system/info",
	"keyorix.v1.SystemService/GetMetrics":    "GET /api/v1/system/metrics",

	"keyorix.v1.BreakGlassService/ActivateBreakGlass":        "POST /api/v1/projects/{id}/break-glass",
	"keyorix.v1.BreakGlassService/ListBreakGlassActivations": "GET /api/v1/projects/{id}/break-glass",
	"keyorix.v1.BreakGlassService/RevokeBreakGlass":          "POST /api/v1/projects/{id}/break-glass/{activationId}/revoke",

	"keyorix.v1.GroupService/ListGroups":        "GET /api/v1/groups",
	"keyorix.v1.GroupService/GetGroup":          "GET /api/v1/groups/{id}",
	"keyorix.v1.GroupService/CreateGroup":       "POST /api/v1/groups",
	"keyorix.v1.GroupService/UpdateGroup":       "PUT /api/v1/groups/{id}",
	"keyorix.v1.GroupService/DeleteGroup":       "DELETE /api/v1/groups/{id}",
	"keyorix.v1.GroupService/RestoreGroup":      "POST /api/v1/groups/{id}/restore",
	"keyorix.v1.GroupService/GetGroupMembers":   "GET /api/v1/groups/{id}/members",
	"keyorix.v1.GroupService/AddGroupMember":    "POST /api/v1/groups/{id}/members",
	"keyorix.v1.GroupService/RemoveGroupMember": "DELETE /api/v1/groups/{id}/members/{userId}",

	"keyorix.v1.ProjectService/ListProjects":              "GET /api/v1/projects",
	"keyorix.v1.ProjectService/GetProject":                "GET /api/v1/projects/{id}",
	"keyorix.v1.ProjectService/CreateProject":             "POST /api/v1/projects",
	"keyorix.v1.ProjectService/UpdateProject":             "PUT /api/v1/projects/{id}",
	"keyorix.v1.ProjectService/DeleteProject":             "DELETE /api/v1/projects/{id}",
	"keyorix.v1.ProjectService/GetProjectRotationOrder":   "GET /api/v1/projects/{id}/rotation-order",
	"keyorix.v1.ProjectService/GetProjectRotationPlan":    "GET /api/v1/projects/{id}/rotation-plan",
	"keyorix.v1.ProjectService/GetDeploymentRotationPlan": "GET /api/v1/rotation-plan",
	"keyorix.v1.ProjectService/ListEnvironments":          "GET /api/v1/projects/{id}/environments",

	"keyorix.v1.MachineIdentityService/ListMachineIdentities":     "GET /api/v1/projects/{id}/machine-identities",
	"keyorix.v1.MachineIdentityService/CreateMachineIdentity":     "POST /api/v1/projects/{id}/machine-identities",
	"keyorix.v1.MachineIdentityService/TransitionMachineIdentity": "PUT /api/v1/projects/{id}/machine-identities/{machineId}",
	"keyorix.v1.MachineIdentityService/ClassifyMachineIdentity":   "PATCH /api/v1/projects/{id}/machine-identities/{machineId}/classification",
	"keyorix.v1.MachineIdentityService/IssueMachineToken":         "POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens",
	"keyorix.v1.MachineIdentityService/ListMachineTokens":         "GET /api/v1/projects/{id}/machine-identities/{machineId}/tokens",
	"keyorix.v1.MachineIdentityService/RevokeMachineToken":        "DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}",
	"keyorix.v1.MachineIdentityService/ClassifyMachineToken":      "PATCH /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification",

	"keyorix.v1.DynamicSecretService/ListConfigs":     "GET /api/v1/dynamic-secrets/configs",
	"keyorix.v1.DynamicSecretService/GetConfig":       "GET /api/v1/dynamic-secrets/configs/{id}",
	"keyorix.v1.DynamicSecretService/CreateConfig":    "POST /api/v1/dynamic-secrets/configs",
	"keyorix.v1.DynamicSecretService/ClassifyConfig":  "PATCH /api/v1/dynamic-secrets/configs/{id}/classification",
	"keyorix.v1.DynamicSecretService/IssueLease":      "POST /api/v1/dynamic-secrets/configs/{id}/issue",
	"keyorix.v1.DynamicSecretService/ListLeases":      "GET /api/v1/dynamic-secrets/configs/{id}/leases",
	"keyorix.v1.DynamicSecretService/RevokeLease":     "POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke",
	"keyorix.v1.DynamicSecretService/RenewLease":      "POST /api/v1/dynamic-secrets/leases/{leaseID}/renew",
	"keyorix.v1.DynamicSecretService/RevokeAllLeases": "POST /api/v1/dynamic-secrets/configs/{id}/revoke-all",

	"keyorix.v1.ComplianceService/GetCompliancePosture":  "GET /api/v1/compliance/posture",
	"keyorix.v1.ComplianceService/GetComplianceControls": "GET /api/v1/compliance/controls",

	"keyorix.v1.ConnectService/ListConnectors": "GET /api/v1/connect/connectors",
	"keyorix.v1.ConnectService/ReadSecret":     "POST /api/v1/connect/{name}/secret:read",
	"keyorix.v1.ConnectService/ListRefGrants":  "GET /api/v1/connect/ref-grants",
	"keyorix.v1.ConnectService/CreateRefGrant": "POST /api/v1/connect/ref-grants",
	"keyorix.v1.ConnectService/DeleteRefGrant": "DELETE /api/v1/connect/ref-grants/{id}",
}

// grpcOnlyReason: registered methods with no REST counterpart, and why.
var grpcOnlyReason = map[string]string{
	"keyorix.v1.AuditService/StreamAuditLogs": "server-streaming live feed; REST has no streaming transport (it offers /audit/export and /audit/export.csv for bulk reads)",
}

// restOnlyFamilies: REST route families (the first path segment after /api/v1/, or
// "root" / "scim" as routeInventoryFeatureGroup in server/http names them) with no
// gRPC method at all, and why. ADR-105: gRPC is a partial data-plane API; HTTP is
// the complete interface. A family leaves this list the moment an RPC maps into it
// (the test enforces that), which is when its low-privilege and dead-credential
// behaviour starts being walked here.
var restOnlyFamilies = map[string]string{
	"access-requests":            "secret access-request workflow (approve/reject); governance flow, HTTP-only per ADR-105",
	"admin":                      "operator endpoints: impersonation, scheduler jobs, usage/billing; deliberately not on the data-plane gRPC surface",
	"alert-escalation-policies":  "alerting configuration; HTTP-only governance surface",
	"auth":                       "login, MFA, WebAuthn, SSO, password and session management; interactive flows with no gRPC counterpart (the interceptor refuses setup-only sessions outright, INV-GRPC-setup-only-session-refused)",
	"dashboard":                  "web UI aggregate; no API consumer on gRPC",
	"environments":               "top-level environment list and DELETE; gRPC ListEnvironments is project-scoped and maps to the projects family, and environment deletion is HTTP-only",
	"folders":                    "secret folder tree; gRPC reaches folders only through CreateSecret.parent_id and ListSecrets.folder_only",
	"hygiene":                    "deployment hygiene report; HTTP-only governance surface",
	"invitations":                "user invitation flow; interactive",
	"legal-hold":                 "retention governance; HTTP-only",
	"license":                    "license status; operator surface",
	"machine-identities":         "machine-identity audit report (/machine-identities/audit[.csv]); the gRPC MachineIdentityService maps to the project-scoped routes in the projects family",
	"machine-token-hygiene":      "hygiene report; HTTP-only governance surface",
	"notification-channels":      "notification configuration; HTTP-only",
	"notifications":              "per-user inbox for the web UI; no gRPC consumer",
	"pat-hygiene":                "hygiene report; HTTP-only governance surface",
	"permissions":                "permission catalogue for the UI",
	"rbac":                       "RBAC summary for the UI",
	"rejection-reason-templates": "workflow templates; HTTP-only governance surface",
	"risk-exceptions":            "risk acceptance workflow; HTTP-only governance surface",
	"rotation-calendar":          "calendar view for the UI",
	"rotation-policies":          "rotation policy configuration; HTTP-only governance surface",
	"scim":                       "SCIM 2.0 provisioning is HTTP by specification",
	"secret-access-requests":     "access-request workflow; HTTP-only governance surface",
	"secret-templates":           "secret template catalogue; HTTP-only",
	"sod":                        "separation-of-duties policy; HTTP-only governance surface",
	"version":                    "build version probe",
}

type routeRow struct {
	Method       string `json:"method"`
	Pattern      string `json:"pattern"`
	FeatureGroup string `json:"feature_group"`
}

// loadRESTRoutes reads the committed REST route inventory.
func loadRESTRoutes(t *testing.T) map[string]routeRow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "e2e", "routes.json"))
	require.NoError(t, err, "scripts/e2e/routes.json is regenerated by server/http TestRouteInventoryIsCurrent")
	var rows []routeRow
	require.NoError(t, json.Unmarshal(b, &rows))
	require.Greater(t, len(rows), 200, "route inventory is implausibly small")
	out := map[string]routeRow{}
	for _, r := range rows {
		out[r.Method+" "+r.Pattern] = r
	}
	return out
}

func TestGRPCMethodsHaveRESTCounterpartOrReason(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	srv, err := keyorixgrpc.NewServer(&config.Config{}, h.CoreService)
	require.NoError(t, err)
	t.Cleanup(srv.Stop)
	registered := registeredMethodKeys(srv)
	routes := loadRESTRoutes(t)

	// 1. Every registered method is classified, exactly once.
	for key := range registered {
		_, mapped := grpcToREST[key]
		_, only := grpcOnlyReason[key]
		if !mapped {
			t.Errorf("%s is registered but not in grpcToREST: map it to its REST route, or give it a grpcOnlyReason (\"\" in grpcToREST)", key)
			continue
		}
		if grpcToREST[key] == "" && !only {
			t.Errorf("%s has no REST route in grpcToREST and no grpcOnlyReason", key)
		}
		if grpcToREST[key] != "" && only {
			t.Errorf("%s is in grpcOnlyReason but also maps to REST route %q", key, grpcToREST[key])
		}
	}
	// 2. No stale entries.
	for key := range grpcToREST {
		require.Truef(t, registered[key], "grpcToREST names %s, which is not a registered method — remove the stale entry", key)
	}
	for key, reason := range grpcOnlyReason {
		require.Truef(t, registered[key], "grpcOnlyReason names %s, which is not a registered method", key)
		require.NotEmptyf(t, strings.TrimSpace(reason), "grpcOnlyReason[%s] needs a reason", key)
	}

	// 3. Every mapped REST route exists in the (drift-checked) inventory.
	coveredFamilies := map[string]bool{}
	for key, route := range grpcToREST {
		if route == "" {
			continue
		}
		row, ok := routes[route]
		if !ok {
			t.Errorf("%s maps to REST route %q, which is not in scripts/e2e/routes.json (renamed or removed?)", key, route)
			continue
		}
		coveredFamilies[row.FeatureGroup] = true
	}

	// 4. Every REST family is covered by a gRPC method or listed REST-only, and a
	//    REST-only entry is dropped as soon as a method maps into it.
	families := map[string]bool{}
	for _, r := range routes {
		families[r.FeatureGroup] = true
	}
	var unclassified []string
	for fam := range families {
		_, restOnly := restOnlyFamilies[fam]
		switch {
		case coveredFamilies[fam] && restOnly:
			t.Errorf("REST family %q is listed in restOnlyFamilies but a gRPC method now maps into it — remove the entry", fam)
		case !coveredFamilies[fam] && !restOnly:
			unclassified = append(unclassified, fam)
		}
	}
	sort.Strings(unclassified)
	for _, fam := range unclassified {
		t.Errorf("REST route family %q has no gRPC method and is not in restOnlyFamilies: add a reasoned entry (or map an RPC to it)", fam)
	}
	for fam, reason := range restOnlyFamilies {
		require.Truef(t, families[fam], "restOnlyFamilies names %q, which is not a REST family in the route inventory — remove the stale entry", fam)
		require.NotEmptyf(t, strings.TrimSpace(reason), "restOnlyFamilies[%s] needs a reason", fam)
	}

	// Not vacuous: the join covers the whole registered surface and many families.
	require.GreaterOrEqual(t, len(registered), 80)
	require.GreaterOrEqual(t, len(coveredFamilies), 12, "implausibly few REST families map to gRPC methods")
}

func registeredMethodKeys(srv *grpc.Server) map[string]bool {
	out := map[string]bool{}
	for svc, info := range srv.GetServiceInfo() {
		for _, m := range info.Methods {
			out[svc+"/"+m.Name] = true
		}
	}
	return out
}
