// Command filterspec produces a narrowed copy of server/http/handlers/openapi.yaml
// containing only the paths the thin CLI's generated client actually needs, per Phase 3 PR
// (docs/cli-split-inventory.md §7). Generating a client for the full ~167-operation spec
// when a given PR wires only a handful of them (PR 0: 4) produces a client dominated by
// dead generated code -- narrowing the INPUT spec keeps the generated OUTPUT proportionate
// to what's actually used, while still being real generation from the canonical API
// definition (ADR-106), not a hand-maintained subset.
//
// `components:` is kept in full rather than reference-chased down to only what the kept
// paths use: openapi.yaml is 400+ $ref-heavy, and a wrong reference-pruning pass silently
// breaking a kept path's schema would be a worse failure mode than a few dozen extra unused
// generated types (server/http/handlers/openapi.yaml's own components section is not large
// enough for that trade to matter).
//
// Run via `make -C cli client` (see cli/Makefile), not directly -- see this repo's root
// Makefile for the analogous `make proto` pattern.
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// keptPaths is the worklist: as each Phase 3 PR (docs/cli-split-inventory.md §7) wires a
// new command group, add the REST paths it needs here and re-run `make -C cli client`.
var keptPaths = []string{
	"/health",
	"/api/v1/version",
	"/auth/login",
	// #2737: the second step of a two-step login. /auth/login answers an
	// MFA-enabled account with a challenge instead of a token (200 +
	// MFAChallengeData, see openapi.yaml's authLogin description), and the
	// challenge is completed here. Without this path the generated client had
	// no way to finish a login at all, which is why `keyorix login` dead-ended
	// on the challenge response.
	"/auth/mfa/verify",
	"/auth/logout",
	"/api/v1/auth/profile",
	// Item 3b (RELEASE-BLOCKERS): `keyorix change-password`, so the J5
	// lost-admin recovery flow (docs/operator/j5-lost-admin.md) needs no raw
	// curl call to finish setting a real password after logging in with the
	// one-time password recover-admin prints.
	"/api/v1/auth/change-password",
	// PR 10 leftovers (docs/cli-split-inventory.md §7) -- system init --server.
	"/system/init",
	// PR 2 (docs/cli-split-inventory.md §7) -- pat, auth (mfa/logout), machine.
	"/api/v1/auth/mfa/stepup",
	// ADR-112 item 1: require_mfa defaults on, so a fresh install's first admin
	// is confined to MFA enrolment until it enrols -- `keyorix mfa enroll` and
	// `keyorix mfa activate` are how the CLI does that.
	"/api/v1/auth/mfa/enroll",
	"/api/v1/auth/mfa/activate",
	"/api/v1/auth/tokens",
	"/api/v1/auth/tokens/{id}",
	"/api/v1/auth/tokens/expired",
	"/api/v1/pat-hygiene",
	"/api/v1/projects/{id}/machine-identities",
	"/api/v1/projects/{id}/machine-identities/{machineId}",
	"/api/v1/projects/{id}/machine-identities/{machineId}/tokens",
	"/api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}",
	"/api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings",
	"/api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}",
	// Item 2 (RELEASE-BLOCKERS): `keyorix machine grant-role`/`revoke-role`/`roles`.
	"/api/v1/projects/{id}/machine-identities/{machineId}/roles",
	"/api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}",
	"/api/v1/machine-token-hygiene",
	"/api/v1/machine-identities/audit",
	"/api/v1/projects",
	// #2562: the per-project read a project-scoped (least-privilege) caller CAN
	// use to resolve --project <id> when the global listing above correctly 403s.
	"/api/v1/projects/{id}",
	// PR 4 (docs/cli-split-inventory.md §7) -- secret core CRUD + metadata.
	"/api/v1/secrets",
	"/api/v1/secrets/{id}",
	"/api/v1/secrets/by-name",
	"/api/v1/secrets/value",
	"/api/v1/secrets/{id}/versions",
	"/api/v1/secrets/{id}/versions/{from}/diff/{to}",
	"/api/v1/secrets/{id}/versions/{versionId}/comments",
	"/api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}",
	"/api/v1/secrets/{id}/acl",
	"/api/v1/secrets/{id}/acl/{aclId}",
	"/api/v1/secrets/{id}/classification",
	"/api/v1/secrets/{id}/tags",
	"/api/v1/secrets/{id}/description",
	"/api/v1/secrets/{id}/move",
	"/api/v1/secrets/{id}/copy",
	"/api/v1/secrets/{id}/dependencies",
	"/api/v1/secrets/{id}/dependencies/{depId}",
	"/api/v1/secrets/{id}/impact",
	"/api/v1/secrets/{id}/access",
	"/api/v1/secrets/{id}/access-log",
	"/api/v1/secrets/{id}/schedule",
	"/api/v1/secrets/{id}/suspend",
	"/api/v1/secrets/{id}/resume",
	"/api/v1/secrets/{id}/rollback",
	"/api/v1/secrets/{id}/restore",
	"/api/v1/projects/{id}/secrets/deleted",
	"/api/v1/projects/{id}/environments/{envId}/copy-secrets",
	"/api/v1/folders",
	"/api/v1/folders/{id}",
	"/api/v1/secret-templates",
	"/api/v1/secret-templates/{id}",
	// PR 7 (docs/cli-split-inventory.md §7) -- audit, anomalies, notification,
	// accessreview, request.
	"/api/v1/audit/verify",
	"/api/v1/audit/export",
	"/api/v1/audit/checkpoint",
	"/api/v1/audit/migrate-chain-encoding",
	"/api/v1/audit/logs",
	"/api/v1/audit/search",
	"/api/v1/audit/anomalies",
	"/api/v1/audit/anomalies/{id}/acknowledge",
	"/api/v1/admin/anomaly-config",
	"/api/v1/alert-escalation-policies",
	"/api/v1/alert-escalation-policies/{id}",
	"/api/v1/admin/jobs/run-alert-escalation",
	"/api/v1/notification-channels",
	"/api/v1/notification-channels/{id}",
	"/api/v1/projects/{id}/access-review",
	"/api/v1/projects/{id}/access-review/revoke",
	"/api/v1/projects/{id}/access-review/attest",
	"/api/v1/projects/{id}/access-review/campaigns",
	"/api/v1/projects/{id}/access-review/campaigns/{campaignId}",
	"/api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide",
	"/api/v1/projects/{id}/access-review/campaigns/{campaignId}/close",
	"/api/v1/projects/{id}/access-requests",
	"/api/v1/projects/{id}/access-requests/{requestId}",
	"/api/v1/projects/{id}/access-requests/{requestId}/withdraw",
	"/api/v1/secret-access-requests",
	"/api/v1/secret-access-requests/{requestId}",
	"/api/v1/access-requests/bulk-approve",
	"/api/v1/access-requests/bulk-reject",
	"/api/v1/rejection-reason-templates",
	"/api/v1/rejection-reason-templates/{id}",
	"/api/v1/projects/{id}/environments",
	"/api/v1/users/{id}",
	// PR 8 (docs/cli-split-inventory.md §7) -- risk, sod, legalhold, compliance,
	// hygiene, trust.
	"/api/v1/risk-exceptions",
	"/api/v1/risk-exceptions/{id}",
	"/api/v1/risk-exceptions/{id}/approve",
	"/api/v1/sod/policies",
	"/api/v1/sod/policies/{id}",
	"/api/v1/sod/violations",
	"/api/v1/legal-hold",
	"/api/v1/hygiene",
	"/api/v1/compliance/posture",
	"/api/v1/compliance/evidence",
	"/api/v1/compliance/evidence/verify",
	"/api/v1/compliance/controls",
	"/api/v1/compliance/controls.csv",
	"/api/v1/compliance/digest",
	"/api/v1/compliance/digest/send",
	"/api/v1/compliance/permission-changes",
	"/api/v1/compliance/permission-baseline",
	"/api/v1/compliance/permission-baseline.csv",
	"/api/v1/compliance/credential-trends",
	"/api/v1/compliance/rotation-by-backend",
	"/api/v1/secrets/inventory.csv",
	"/api/v1/projects/{id}/secrets/inventory.csv",
	// PR 10 (docs/cli-split-inventory.md §7) -- status, system info/role-expiry-check/
	// token-expiry-check.
	"/api/v1/system/info",
	"/api/v1/admin/jobs/role-expiry-check",
	"/api/v1/admin/jobs/token-expiry-check",
	// PR 3 (docs/cli-split-inventory.md §7) -- rbac, group, invite.
	"/api/v1/users",
	// PR 6 (docs/cli-split-inventory.md §7) -- project, user.
	"/api/v1/projects/{id}/stats",
	"/api/v1/projects/{id}/hygiene",
	"/api/v1/projects/{id}/health",
	"/api/v1/projects/{id}/environments/{envId}/clone",
	"/api/v1/environments/{id}",
	"/api/v1/users/by-email",
	"/api/v1/users/{id}/suspend",
	"/api/v1/users/{id}/reactivate",
	"/api/v1/users/{id}/require-password-reset",
	"/api/v1/users/{id}/revoke-sessions",
	"/api/v1/users/{id}/resend-setup-link",
	"/api/v1/users/{id}/reissue-one-time-password",
	"/api/v1/admin/jobs/suspend-inactive-users",
	// PR 3 (docs/cli-split-inventory.md §7) -- rbac, group, invite.
	"/api/v1/users/{id}/roles",
	"/api/v1/roles",
	"/api/v1/roles/{id}/permissions",
	"/api/v1/user-roles",
	"/api/v1/groups",
	"/api/v1/groups/{id}",
	"/api/v1/groups/{id}/members",
	"/api/v1/groups/{id}/members/{userId}",
	"/api/v1/groups/{id}/roles",
	"/api/v1/groups/{id}/roles/{roleId}",
	"/api/v1/audit/rbac-logs",
	"/api/v1/rbac/permission-matrix",
	"/api/v1/projects/{id}/invitations",
	"/api/v1/projects/{id}/invitations/{invitationId}",
	"/api/v1/projects/{id}/invitations/{invitationId}/resend",
	// PR 1 (docs/cli-split-inventory.md §7) -- dynamic-secret, rotation, breakglass.
	"/api/v1/dynamic-secrets/configs",
	"/api/v1/dynamic-secrets/configs/{id}",
	"/api/v1/dynamic-secrets/configs/{id}/classification",
	"/api/v1/dynamic-secrets/configs/{id}/issue",
	"/api/v1/dynamic-secrets/configs/{id}/leases",
	"/api/v1/dynamic-secrets/configs/{id}/revoke-all",
	"/api/v1/dynamic-secrets/leases/{leaseID}/renew",
	"/api/v1/dynamic-secrets/leases/{leaseID}/revoke",
	"/api/v1/rotation-policies",
	"/api/v1/rotation-policies/evaluate",
	"/api/v1/rotation-policies/{id}",
	"/api/v1/projects/{id}/rotation-plan",
	"/api/v1/rotation-plan",
	"/api/v1/projects/{id}/rotation-order",
	"/api/v1/projects/{id}/break-glass",
	"/api/v1/projects/{id}/break-glass/{activationId}/revoke",
	// PR 9 (docs/cli-split-inventory.md §7) -- share.
	"/api/v1/secrets/{id}/share",
	"/api/v1/secrets/{id}/shares",
	"/api/v1/secrets/{id}/self-share",
	"/api/v1/shares/{id}",
	"/api/v1/shared-secrets",
	"/api/v1/users/{id}/shared-secrets",
	"/api/v1/groups/{id}/shares",
	// PR 5 (docs/cli-split-inventory.md §7) -- secret bulk/rotation/export/import/scan/hygiene.
	// /api/v1/secrets and /api/v1/secrets/{id} are kept without a response schema here on
	// purpose -- authoring Secret/SecretGetResult/SecretListEntry is PR 4's job (a sibling,
	// independent PR on its own branch); export/import/bulk-rotate/bulk-rename decode their
	// own local DTOs off the raw (non-...WithResponse) generated methods instead of waiting
	// on that schema to land here.
	"/api/v1/secrets",
	"/api/v1/secrets/{id}",
	"/api/v1/secrets/{id}/rotate",
	"/api/v1/secrets/{id}/rotation/simulate",
	"/api/v1/secrets/{id}/auto-rotate",
	"/api/v1/secrets/{id}/audit",
	"/api/v1/secrets/{id}/ownership-history",
	"/api/v1/secrets/{id}/certificate",
	"/api/v1/secrets/{id}/blast-radius",
	"/api/v1/secrets/{id}/risk",
	"/api/v1/secrets/quota-report",
	"/api/v1/secrets/name-conformance",
	"/api/v1/projects/{id}/secrets/expiring",
	"/api/v1/projects/{id}/secrets/orphaned",
	"/api/v1/projects/{id}/secrets/name-conformance",
	"/api/v1/projects/{id}/secrets/reassign-owner",
	"/api/v1/projects/{id}/secrets/bulk-rotate",
	"/api/v1/projects/{id}/secrets/bulk-rename",
	"/api/v1/projects/{id}/secrets/bulk-delete",
	"/api/v1/projects/{id}/secrets/render",
	// FINISH-SPLIT census-gaps batch (docs/cli-split-inventory-census.md) -- the last 3
	// command-census gaps: billing report, usage show, migrate user-to-machine.
	"/api/v1/admin/usage",
	"/api/v1/admin/billing/report",
	"/api/v1/projects/{id}/machine-identities/migrate-from-user",
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: filterspec <input-openapi.yaml> <output-openapi.yaml>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "filterspec:", err)
		os.Exit(1)
	}
}

func run(inPath, outPath string) error {
	data, err := os.ReadFile(inPath) // #nosec G304 G703 -- inPath/outPath are argv from `make client`, a local dev/CI codegen tool, not user/network input
	if err != nil {
		return fmt.Errorf("read %s: %w", inPath, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", inPath, err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: unexpected document shape", inPath)
	}
	root := doc.Content[0]

	pathsNode, ok := mappingValue(root, "paths")
	if !ok {
		return fmt.Errorf("%s: no top-level 'paths' key", inPath)
	}

	kept := map[string]bool{}
	for _, p := range keptPaths {
		kept[p] = true
	}

	var filteredContent []*yaml.Node
	found := map[string]bool{}
	for i := 0; i+1 < len(pathsNode.Content); i += 2 {
		keyNode, valNode := pathsNode.Content[i], pathsNode.Content[i+1]
		if kept[keyNode.Value] {
			filteredContent = append(filteredContent, keyNode, valNode)
			found[keyNode.Value] = true
		}
	}
	for _, p := range keptPaths {
		if !found[p] {
			return fmt.Errorf("%s: keptPaths entry %q does not exist in the source spec", inPath, p)
		}
	}
	pathsNode.Content = filteredContent

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("marshal filtered spec: %w", err)
	}
	if err := os.WriteFile(outPath, out, 0o600); err != nil { // #nosec G304 G703 -- see the ReadFile call above
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}

func mappingValue(m *yaml.Node, key string) (*yaml.Node, bool) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1], true
		}
	}
	return nil, false
}
