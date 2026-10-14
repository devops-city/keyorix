// opcatalog_test.go is FuzzStorageFaultOperations' operation catalog: real
// dispatch functions driving the actual REST/system/gRPC transports (never
// calling a core.* or storage.* method directly), so a fault only visible to a
// caller that goes through the real handler — F3's replaceRolePermissions, the
// /system proxy Storage()-bypass class — is actually exercised.
//
// Every operation is split into Setup (runs on an UNFAULTED world) and Execute
// (runs on the SAME world after the harness Arms the fault) — the prefix/op
// split STEP 0 called for. Splitting matters for two reasons, both found by
// this harness's own seed corpus before this split existed: (1) NthCall must
// count only Execute's own calls, or a fault meant for the operation under test
// fires during unrelated setup instead; (2) the "error implies unchanged state"
// oracle is only valid relative to POST-setup state — comparing against the
// pristine pre-setup world flags every setup write as a false "state changed"
// violation regardless of whether Execute's own fault handling is correct.
//
// Every key here must exactly match a key in inventory_registry_generated_test.go
// (enforced by TestOperationCatalogKeysAreRegistered below) so StatusFuzzed in
// inventory_overrides_test.go can never silently drift from what the harness
// actually drives.
package faultops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// opResult is transport-agnostic: Success is the ONLY thing oracle (a)/(b) care
// about (2xx / codes.OK vs everything else), Detail is kept for readable tracing.
type opResult struct {
	Success bool
	Detail  string // "HTTP 200: ..." / "codes.OK" / "HTTP 500: <body>" etc.
}

type operation struct {
	// Key must match a "REST <METHOD> <path>" or "GRPC <service>.<method>" key
	// in inventory_registry_generated_test.go.
	Key string
	// Setup runs BEFORE the harness arms any fault — real calls (through the
	// real transport, same as Execute) that put the world in the state Execute
	// needs (e.g. a role to update, a secret to delete). Its return value is
	// passed to Execute untouched. nil Setup means "nothing to do."
	Setup func(ctx context.Context, w *faultWorld) (any, error)
	// Execute performs the ONE call under test, run AFTER the harness arms the
	// fault — this is the only phase whose storage calls count toward NthCall.
	Execute func(ctx context.Context, w *faultWorld, state any) (opResult, error)
}

func httpJSON(ctx context.Context, w *faultWorld, method, path string, body any) (int, []byte, error) {
	return httpJSONAs(ctx, w, w.adminToken, method, path, body)
}

// httpJSONAs is httpJSON with an explicit bearer token, for the rare operation
// whose real caller isn't the bootstrapped admin — e.g. EndImpersonation,
// which authenticates with the impersonation session's own token
// (admin_impersonation.go's End: extractBearerToken(r), never the admin's).
func httpJSONAs(ctx context.Context, w *faultWorld, token, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.httpServer.URL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

// scimJSON is httpJSON for the /scim/v2 route group, which authenticates with
// w.scimToken (SCIMToken middleware's own static bearer token) rather than
// the normal session/PAT bearer w.adminToken every other operation uses.
func scimJSON(ctx context.Context, w *faultWorld, method, path string, body any) (int, []byte, error) {
	return httpJSONAs(ctx, w, w.scimToken, method, path, body)
}

// createSCIMUserForFuzz provisions a user through POST /scim/v2/Users (not
// the ordinary /api/v1/users/ endpoint createUserForFuzz uses) and returns
// its ID -- needed because scim_groups.go's member-add path (#167) only
// accepts a SCIM-MANAGED account (one carrying an externalId set by SCIM
// provisioning); a plain createUserForFuzz user is rejected with
// "SCIM can only add SCIM-managed users to a group". The SCIM response body
// has no {"data": ...} envelope (unlike the ordinary REST API) and encodes
// "id" as a STRING (RFC 7644), not the ordinary API's numeric ID field.
func createSCIMUserForFuzz(ctx context.Context, w *faultWorld, username string) (uint, error) {
	st, body, err := scimJSON(ctx, w, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   username + "@example.com",
		"externalId": username,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup SCIM CreateUser: HTTP %d: %s", st, body)
	}
	var decoded struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.ID == "" {
		return 0, fmt.Errorf("decoding SCIM CreateUser response: %w (body=%s)", err, body)
	}
	id, err := strconv.ParseUint(decoded.ID, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing SCIM CreateUser id %q: %w", decoded.ID, err)
	}
	return uint(id), nil
}

func httpResult(st int, body []byte) opResult {
	return opResult{Success: st/100 == 2, Detail: fmt.Sprintf("HTTP %d: %s", st, body)}
}

// createRoleForFuzz sets up a role with exactly one permission the bootstrapped
// admin holds, returning its ID — setup for the UpdateRole/F3 and gRPC
// AssignRole operations.
func createRoleForFuzz(ctx context.Context, w *faultWorld) (uint, error) {
	status, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
		"name": "fuzz-role", "description": "fuzz role", "permissions": []string{"secrets.read"},
	})
	if err != nil {
		return 0, err
	}
	if status/100 != 2 {
		return 0, fmt.Errorf("setup CreateRole: HTTP %d: %s", status, body)
	}
	var decoded struct {
		Data struct {
			Role struct {
				ID uint `json:"id"`
			} `json:"role"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return 0, fmt.Errorf("decoding CreateRole response: %w (body=%s)", err, body)
	}
	if decoded.Data.Role.ID == 0 {
		return 0, fmt.Errorf("CreateRole response carried no role id (body=%s)", body)
	}
	return decoded.Data.Role.ID, nil
}

// dynamicSecretFuzzAdminDSN is a syntactically valid "postgres" DSN pointed at
// localhost. There is no live external database this in-process harness can
// dial, so wireFakeDynamicSecretEngineForFuzz below replaces the real dial
// with dynamictest.FakeEngine (the same in-memory fake internal/core's own
// unit tests use, e.g. internal/core/dynamic_secrets_test.go) — this DSN
// string is never actually connected to, only stored (encrypted) and passed
// through. "localhost" also requires the private-network-target opt-in below;
// using it deliberately, not working around it.
const dynamicSecretFuzzAdminDSN = "postgres://fake:fake@localhost/fakedb"

// wireFakeDynamicSecretEngineForFuzz swaps this world's dynamic-secrets engine
// factory (newFaultWorld wires the REAL one, dynamic.New, matching production
// exactly — see its own comment: "the actual dynamic.New call... only happens
// if/when a future operation actually calls CreateConfig") for
// dynamictest.FakeEngine, and opts into private-network admin-DSN targets
// (SetDynamicAllowPrivateTargets — its own doc comment: "Set to true only when
// the dynamic-secret backend legitimately lives on a private segment", exactly
// this harness's situation). Each fuzz iteration gets its own fresh
// *core.KeyorixCore (confirmed via opcatalog_smoke_test.go's per-subtest world
// build), so mutating w.core here is scoped to this op's own Setup+Execute,
// not shared with any other op's iteration.
//
// Without this, EVERY dynamic-secrets op that reaches the backend
// (IssueLease/RenewLease/RevokeLease/RevokeAllLeases) would deterministically
// fail even with no fault armed — "localhost" is rejected by the SSRF guard
// before any dial, and even with that allowed, the real dynamic.New("postgres",
// ...) engine has nothing reachable to dial. TestOpCatalog_SucceedsWithNoFaultArmed
// requires every catalog entry to succeed unfaulted, so a deterministically-
// failing op is not an acceptable substitute for real backend reachability —
// the fake engine is what makes these ops genuinely testable in-process.
func wireFakeDynamicSecretEngineForFuzz(w *faultWorld) {
	w.core.SetDynamicAllowPrivateTargets(true)
	w.core.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) {
		return &dynamictest.FakeEngine{NativeExpiry: true}, nil
	})
}

// createDynamicSecretConfigForFuzz wires the fake engine (see
// wireFakeDynamicSecretEngineForFuzz), creates a dynamic-secret config
// (backend "postgres", so SupportsNativeExpiry() is true and IssueLease's
// sweep-disabled guard never short-circuits it) via the real HTTP transport,
// and returns its ID.
func createDynamicSecretConfigForFuzz(ctx context.Context, w *faultWorld, name string) (uint, error) {
	wireFakeDynamicSecretEngineForFuzz(w)
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/dynamic-secrets/configs", map[string]any{
		"name": name, "project_id": 1, "environment_id": 1,
		"backend_type": "postgres", "admin_dsn": dynamicSecretFuzzAdminDSN,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateDynamicSecretConfig: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateDynamicSecretConfig response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// issueDynamicSecretLeaseForFuzz issues a REAL lease (via the real HTTP
// /issue endpoint, now genuinely succeeding thanks to the fake engine wired by
// createDynamicSecretConfigForFuzz) against cfgID, and returns its lease_id —
// setup for RenewLease/RevokeLease/RevokeAllLeases.
func issueDynamicSecretLeaseForFuzz(ctx context.Context, w *faultWorld, cfgID uint) (string, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/issue", cfgID), map[string]any{
		"ttl_seconds": 60,
	})
	if err != nil {
		return "", err
	}
	if st/100 != 2 {
		return "", fmt.Errorf("setup IssueLease: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			LeaseID string `json:"lease_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.LeaseID == "" {
		return "", fmt.Errorf("decoding IssueLease response: %w (body=%s)", err, body)
	}
	return decoded.Data.LeaseID, nil
}

// createSecretForFuzz creates a secret and returns its ID — setup for the
// UpdateSecret/DeleteSecret operations. Same "no json tags, Go default
// capitalized names" shape as Project (models.SecretNode).
func createSecretForFuzz(ctx context.Context, w *faultWorld) (uint, error) {
	return createSecretNamedForFuzz(ctx, w, "fuzz-secret-setup")
}

// createSecretNamedForFuzz is createSecretForFuzz with an explicit name —
// needed whenever a single Setup creates more than one secret in the same
// project/environment (name is unique within that scope, so the second
// createSecretForFuzz call would 409 "Secret with this name already exists").
func createSecretNamedForFuzz(ctx context.Context, w *faultWorld, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
		"name": name, "value": "fuzz-value", "project_id": 1, "environment_id": 1, "type": "generic",
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateSecret: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateSecret response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// addProjectMemberForFuzz adds userID to projectID as a "viewer" (seeded by
// every BootstrapSystem call, see defaultRoles in internal/core/auth_bootstrap.go)
// — setup for operations whose core function requires the target/recipient to
// be a live project member (secret ACL grant, secret share) before it will
// act, distinct from the admin-bypasses-everything path createSecretForFuzz's
// other callers rely on.
func addProjectMemberForFuzz(ctx context.Context, w *faultWorld, projectID, userID uint) error {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/members", projectID), map[string]any{
		"user_id": userID, "role": "viewer",
	})
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("setup AddProjectMember: HTTP %d: %s", st, body)
	}
	return nil
}

// addAdminAsProjectMemberForFuzz adds the world's own bootstrap admin
// ("faultadmin") to projectID as a project member — setup for operations
// whose core function checks the ACTOR's own live project membership, not
// just an owner/permission flag (ShareSecret's requireLiveOwnerAuthority:
// the admin globally holds the admin role via a Scope{} grant, which is NOT
// the same thing as an explicit project_members row, and the owner-share
// gate requires the latter).
func addAdminAsProjectMemberForFuzz(ctx context.Context, w *faultWorld, projectID uint) error {
	admin, err := w.faulty.GetUserByUsername(ctx, "faultadmin")
	if err != nil {
		return fmt.Errorf("setup GetUserByUsername(faultadmin): %w", err)
	}
	return addProjectMemberForFuzz(ctx, w, projectID, admin.ID)
}

// createGroupForFuzz creates a group via the ordinary (non-/system) REST
// endpoint and returns its ID — setup for group-member operations.
func createGroupForFuzz(ctx context.Context, w *faultWorld, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/groups/", map[string]any{
		"name": name, "description": "fuzz group",
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateGroup: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateGroup response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// createUserForFuzz creates a user via the ordinary REST endpoint and returns
// its ID — setup for membership/role-assignment operations.
func createUserForFuzz(ctx context.Context, w *faultWorld, username string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/users/", map[string]any{
		"username": username, "email": username + "@example.com",
		"password": fuzzUserPassword, "display_name": "Fuzz User " + username,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateUser: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateUser response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// startImpersonationForFuzz starts an impersonation session for targetUserID
// via the real REST endpoint and returns the resulting session token (the raw
// kx_session cookie value) — setup for EndImpersonation, which authenticates
// with that token directly as a Bearer header, not the cookie (see
// admin_impersonation.go's End: extractBearerToken(r)). impersonationResponse
// no longer carries the token in its JSON body, so it must be read off the
// Set-Cookie header instead.
func startImpersonationForFuzz(ctx context.Context, w *faultWorld, targetUserID uint) (string, error) {
	b, err := json.Marshal(map[string]any{"user_id": targetUserID})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.httpServer.URL+"/api/v1/admin/impersonate", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+w.adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("setup StartImpersonation: HTTP %d: %s", resp.StatusCode, respBody)
	}
	for _, c := range resp.Cookies() {
		if c.Name == middleware.SessionCookieName {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("StartImpersonation response carried no %s cookie", middleware.SessionCookieName)
}

// assignUserRoleForFuzz assigns roleID to userID at projectID scope
// (environment 0) via the real REST endpoint — setup for access-review
// operations, which need a real, live project-scoped role grant to act on.
func assignUserRoleForFuzz(ctx context.Context, w *faultWorld, userID, roleID, projectID uint) error {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/user-roles", map[string]any{
		"user_id": userID, "role_id": roleID, "project_id": projectID, "environment_id": 0,
	})
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("setup AssignRole: HTTP %d: %s", st, body)
	}
	return nil
}

// openAccessReviewCampaignForFuzz opens a campaign for projectID and returns
// its ID — setup for CloseAccessReviewCampaign and
// DecideAccessReviewCampaignItem.
func openAccessReviewCampaignForFuzz(ctx context.Context, w *faultWorld, projectID uint) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/access-review/campaigns", projectID), map[string]any{
		"name": "fuzz campaign",
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup OpenAccessReviewCampaign: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			Campaign struct {
				ID uint `json:"id"`
			} `json:"campaign"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Campaign.ID == 0 {
		return 0, fmt.Errorf("decoding OpenAccessReviewCampaign response: %w (body=%s)", err, body)
	}
	return decoded.Data.Campaign.ID, nil
}

// accessReviewItemIDForPrincipal fetches campaignID's items and returns the
// one belonging to principalID — setup for DecideAccessReviewCampaignItem,
// which needs a real item ID for the just-created grant, not just the first
// item (which could belong to the reviewer itself and trip the campaign's
// own reviewer-independence check).
func accessReviewItemIDForPrincipal(ctx context.Context, w *faultWorld, projectID, campaignID, principalID uint) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/access-review/campaigns/%d", projectID, campaignID), nil)
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup GetAccessReviewCampaign: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			Items []struct {
				ID          uint `json:"id"`
				PrincipalID uint `json:"principal_id"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return 0, fmt.Errorf("decoding GetAccessReviewCampaign response: %w (body=%s)", err, body)
	}
	for _, item := range decoded.Data.Items {
		if item.PrincipalID == principalID {
			return item.ID, nil
		}
	}
	return 0, fmt.Errorf("no access-review item found for principal %d (body=%s)", principalID, body)
}

// createMachineIdentityForFuzz creates a project-scoped machine identity via
// the real REST endpoint and returns its ID. New identities are created
// active by construction (core.CreateMachineIdentity sets State: MachineActive
// directly — there is no separate "pending" initial state despite
// machineTransitions listing one).
func createMachineIdentityForFuzz(ctx context.Context, w *faultWorld, projectID uint) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID), map[string]any{
		"name": "fuzz-machine", "identity_type": "service",
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateMachineIdentity: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			MachineIdentity struct {
				ID uint `json:"id"`
			} `json:"machine_identity"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.MachineIdentity.ID == 0 {
		return 0, fmt.Errorf("decoding CreateMachineIdentity response: %w (body=%s)", err, body)
	}
	return decoded.Data.MachineIdentity.ID, nil
}

// issueMachineTokenForFuzz issues a token for machineID and returns its
// credential ID — setup for RevokeMachineToken/ClassifyMachineToken.
func issueMachineTokenForFuzz(ctx context.Context, w *faultWorld, projectID, machineID uint) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", projectID, machineID), map[string]any{
		"name": "fuzz-token", "expires_in_days": 90,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup IssueMachineToken: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding IssueMachineToken response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// createProjectForFuzz creates a project via the real REST endpoint and
// returns its ID.
func createProjectForFuzz(ctx context.Context, w *faultWorld, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{
		"name": name,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateProject: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// createEnvironmentForFuzz creates an environment under projectID via the real
// REST endpoint and returns its ID.
func createEnvironmentForFuzz(ctx context.Context, w *faultWorld, projectID uint, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments", projectID), map[string]any{
		"name": name,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateProjectEnvironment: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateProjectEnvironment response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// fuzzUserPassword is the fixed password createUserForFuzz sets on every
// fuzz-created user — shared with loginForFuzz so a caller can authenticate as
// one of these users after creating it.
const fuzzUserPassword = "Xk7#Qm2$Lp9@Vn4!"

// faultAdminPassword is the bootstrapped admin's real password (world_test.go's
// newFaultWorld) — needed by any operation that re-verifies the caller's
// current password (ChangePassword, UpdateProfile).
const faultAdminPassword = "FaultFuzzAdmin123!"

// faultAdminUserID looks up the bootstrapped admin's ID directly (newFaultWorld
// never stores it on faultWorld itself -- every existing op either doesn't need
// a raw ID, or derives one from an HTTP response instead).
func faultAdminUserID(w *faultWorld) (uint, error) {
	var u models.User
	if err := w.db.Where("username = ?", "faultadmin").First(&u).Error; err != nil {
		return 0, err
	}
	return u.ID, nil
}

// enrolMFADirect enrols the bootstrapped admin in TOTP MFA via the real HTTP
// enroll endpoint (so the stored secret is genuinely encrypted by
// BeginMFAEnrollment, identical to every other MFA op's Setup) but then flips
// Activated/MFAEnabled directly via storage instead of spending a TOTP step
// through the real /activate endpoint -- so the FIRST code Execute generates
// for its own op is still a fresh, never-consumed step, exactly as it would be
// for a real account that enabled MFA in a prior, unrelated session. Returns
// the plaintext secret (as `any`, to match every op's Setup return shape).
func enrolMFADirect(ctx context.Context, w *faultWorld) (any, error) {
	if err := w.ensureEncryption(); err != nil {
		return nil, fmt.Errorf("ensureEncryption: %w", err)
	}
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	if err != nil {
		return nil, err
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("EnrollMFA: HTTP %d: %s", st, body)
	}
	var enrolled struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &enrolled); err != nil || enrolled.Data.Secret == "" {
		return nil, fmt.Errorf("decoding EnrollMFA response: %w (body=%s)", err, body)
	}
	userID, err := faultAdminUserID(w)
	if err != nil {
		return nil, fmt.Errorf("faultAdminUserID: %w", err)
	}
	if err := w.db.Model(&models.MFASecret{}).Where("user_id = ?", userID).
		Update("activated", true).Error; err != nil {
		return nil, fmt.Errorf("activating mfa_secrets row directly: %w", err)
	}
	if err := w.db.Model(&models.User{}).Where("id = ?", userID).
		Update("mfa_enabled", true).Error; err != nil {
		return nil, fmt.Errorf("setting users.mfa_enabled directly: %w", err)
	}
	// #2838: seed the recovery codes real activation would have issued. Without
	// them this fixture produced an account with MFA enabled and ZERO recovery
	// codes, which no real account ever has -- and which made a whole class of
	// partial commit structurally UNOBSERVABLE: DeleteMFARecoveryCodes deleted
	// zero rows, so a fault between it and CreateMFARecoveryCodes left the
	// snapshot unchanged. A planted class-A bug (the pre-#G08 shape, the exact
	// "account left with zero recovery codes" state that transaction's comment
	// exists to prevent) SURVIVED against the unseeded fixture; with these rows
	// it is killed. Verified both directions -- see this PR's body.
	//
	// Inserted directly rather than through /activate for the same reason
	// Activated/MFAEnabled are: spending a real TOTP step here would consume the
	// step Execute needs (see this function's own doc comment above).
	// mfaRecoveryCodeCount is not exported from internal/core, so the count is
	// spelled out; the oracle never compares the count, only presence.
	recoveryCodes := make([]*models.MFARecoveryCode, 0, 10)
	for i := range 10 {
		// A fixed, obviously-fake hash per index. Deterministic on purpose: the
		// reference world and the fault world are bootstrapped independently, so
		// anything random here would have to rely on CodeHash's presenceOnlyFields
		// reduction to compare equal. It does carry that reduction (snapshot_test.go),
		// but not depending on it keeps this fixture's rows comparable byte-for-byte.
		recoveryCodes = append(recoveryCodes, &models.MFARecoveryCode{
			UserID:   userID,
			CodeHash: fmt.Sprintf("faultops-seeded-recovery-code-hash-%02d", i),
		})
	}
	if err := w.db.Create(&recoveryCodes).Error; err != nil {
		return nil, fmt.Errorf("seeding mfa_recovery_codes rows directly: %w", err)
	}
	return enrolled.Data.Secret, nil
}

// loginForFuzz logs in as username/password via the real /auth/login endpoint
// and returns the resulting session token (the raw kx_session cookie value) —
// setup for operations whose real caller must be a specific non-admin user
// (e.g. ResolveAccessRequest, which forbids an admin from approving their own
// access request).
func loginForFuzz(ctx context.Context, w *faultWorld, username, password string) (string, error) {
	b, err := json.Marshal(map[string]any{"username": username, "password": password})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.httpServer.URL+"/auth/login", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("setup Login: HTTP %d: %s", resp.StatusCode, respBody)
	}
	for _, c := range resp.Cookies() {
		if c.Name == middleware.SessionCookieName {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("Login response carried no %s cookie", middleware.SessionCookieName)
}

// permissionIDByNameForFuzz looks up a permission's ID by name via the real
// REST endpoint — setup for AssignPermissionToRole, which takes a numeric
// permission_id rather than a name.
func permissionIDByNameForFuzz(ctx context.Context, w *faultWorld, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodGet, "/api/v1/permissions/", nil)
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup ListPermissions: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			Permissions []struct {
				ID   uint   `json:"id"`
				Name string `json:"name"`
			} `json:"permissions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return 0, fmt.Errorf("decoding ListPermissions response: %w (body=%s)", err, body)
	}
	for _, p := range decoded.Data.Permissions {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("permission %q not found (body=%s)", name, body)
}

// firstSecretVersionIDForFuzz fetches secretID's version list and returns the
// first (only, for a freshly created secret) version's ID — setup for the
// version-comment operations, which validate versionId actually belongs to
// secretID (versionBelongsToSecret) rather than accepting any numeric ID.
func firstSecretVersionIDForFuzz(ctx context.Context, w *faultWorld, secretID uint) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions", secretID), nil)
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup GetSecretVersions: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			Versions []struct {
				ID uint `json:"ID"`
			} `json:"versions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Data.Versions) == 0 {
		return 0, fmt.Errorf("decoding GetSecretVersions response: %w (body=%s)", err, body)
	}
	return decoded.Data.Versions[0].ID, nil
}

// createFolderForFuzz creates a folder via the real REST endpoint and returns
// its ID.
func createFolderForFuzz(ctx context.Context, w *faultWorld, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/folders/", map[string]any{
		"name": name, "project_id": 1, "environment_id": 1,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateFolder: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateFolder response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// opCatalog is the closed set of operations FuzzStorageFaultOperations can pick
// from — see the STEP 0 report for the running Fuzzed/Pending/Excluded count
// across the full 309-operation inventory; this is intentionally a starting
// slice covering all three known bug classes plus ordinary CRUD across
// REST/system/gRPC, not the full surface (see TestReportOperationTableCoverage).
var opCatalog = []operation{
	{
		// F3: replaceRolePermissions (server/http/handlers/rbac.go) drops
		// GetRolePermissions/RemovePermissionFromRole errors and always replies
		// 200 — confirmed live on main, see the STEP 0 report.
		Key: "REST PUT /api/v1/roles/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			roleID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", roleID), map[string]any{
				"permissions": []string{"secrets.read"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/secrets/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
				"name": "fuzz-secret", "value": "fuzz-value", "project_id": 1, "environment_id": 1, "type": "generic",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST PUT /api/v1/secrets/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), map[string]any{
				"value": "fuzz-value-updated",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/secrets/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/projects",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-project"})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/users/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/users/", map[string]any{
				"username": "fuzz-user", "email": "fuzz-user@example.com",
				"password": "Xk7#Qm2$Lp9@Vn4!", "display_name": "Fuzz User",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Representative gRPC mutating call, over the REAL grpc.Server (bufconn)
		// including RecoveryInterceptor/AuthInterceptor — proves the harness
		// generalizes across transports, not just REST.
		Key: "GRPC keyorix.v1.RoleService.AssignRole",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			roleID := state.(uint)
			_, err := pb.NewRoleServiceClient(w.grpcConn).AssignRole(w.grpcCtx, &pb.AssignRoleRequest{
				UserId: 1, RoleId: uint32(roleID),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 2: ordinary (non-/system) REST CRUD, one per
		// major resource type not yet covered.
		Key: "REST POST /api/v1/groups/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/groups/", map[string]any{
				"name": "fuzz-group-batch2", "description": "fuzz group",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/groups/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/groups/", map[string]any{
				"name": "fuzz-group-batch2-setup", "description": "fuzz group",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateGroup: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateGroup response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/roles/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
				"name": "fuzz-role-batch2", "description": "fuzz role", "permissions": []string{"secrets.read"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/roles/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 3: gRPC group/role CRUD, over the real grpc.Server
		// (bufconn) with the production interceptor chain.
		Key: "GRPC keyorix.v1.GroupService.CreateGroup",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			_, err := pb.NewGroupServiceClient(w.grpcConn).CreateGroup(w.grpcCtx, &pb.CreateGroupRequest{
				Name: "fuzz-group-grpc-batch3", Description: "fuzz group",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.RoleService.DeleteRole",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			roleID := state.(uint)
			_, err := pb.NewRoleServiceClient(w.grpcConn).DeleteRole(w.grpcCtx, &pb.DeleteRoleRequest{
				Id: uint32(roleID),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 4: group membership.
		Key: "REST POST /api/v1/groups/{id}/members",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-group-batch4")
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-user-batch4")
			if err != nil {
				return nil, err
			}
			return map[string]uint{"groupID": groupID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/members", s["groupID"]), map[string]any{
				"user_id": s["userID"],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/groups/{id}/members/{userId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-group-batch4b")
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-user-batch4b")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/members", groupID), map[string]any{
				"user_id": userID,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup AddGroupMember: HTTP %d: %s", st, body)
			}
			return map[string]uint{"groupID": groupID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete,
				fmt.Sprintf("/api/v1/groups/%d/members/%d", s["groupID"], s["userID"]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 5: rotation policies.
		Key: "REST POST /api/v1/rotation-policies/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/rotation-policies/", map[string]any{
				"name": "fuzz-rotation-policy-batch5", "scope": "project", "project_id": 1, "interval_days": 30,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/rotation-policies/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/rotation-policies/", map[string]any{
				"name": "fuzz-rotation-policy-batch5-setup", "scope": "project", "project_id": 1, "interval_days": 30,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRotationPolicy: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRotationPolicy response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/rotation-policies/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 7 (2026-09-24, fuzz/new-surfaces): RevokeBreakGlass —
		// the ORDINARY, roles.assign-gated self-service revoke path
		// (server/http/handlers/break_glass.go), sibling to
		// RevokeBreakGlassActivationProxy above but reached through
		// core.RevokeBreakGlass directly (no /system proxy hop, no
		// guard+role-removal+conditional-revoke sequence of its own — that
		// logic lives once, in core.RevokeBreakGlass/
		// RevokeBreakGlassActivationAtomic, shared by both callers). Exercises
		// PR #2018's break-glass revoke role-removal + state-update atomicity
		// fix from this OTHER caller path into the same core function. Setup
		// seeds the activation directly through the unfaulted storage wrapper
		// (same shortcut the /system entry above uses), since going through
		// the real self-service ActivateBreakGlass REST route would also
		// require configuring c.breakGlassPolicy's emergency role in this
		// world, which no other opCatalog entry needs.
		Key: "REST POST /api/v1/projects/{id}/break-glass/{activationId}/revoke",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			pStatus, pBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-bg2-project"})
			if err != nil {
				return nil, err
			}
			if pStatus/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", pStatus, pBody)
			}
			var proj struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(pBody, &proj); err != nil || proj.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, pBody)
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-bg2-user")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := w.faulty.AssignRole(ctx, userID, roleID, coreStorage.Scope{ProjectID: proj.Data.ID}); err != nil {
				return nil, fmt.Errorf("setup AssignRole: %w", err)
			}
			activation, err := w.faulty.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
				ProjectID:     proj.Data.ID,
				UserID:        userID,
				RoleID:        roleID,
				RoleName:      "fuzz-role",
				Justification: "fuzz break-glass ordinary path",
				State:         core.BreakGlassActive,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateBreakGlassActivation: %w", err)
			}
			return map[string]uint{"projectID": proj.Data.ID, "activationID": activation.ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost,
				fmt.Sprintf("/api/v1/projects/%d/break-glass/%d/revoke", s["projectID"], s["activationID"]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 8 (2026-09-24, fuzz/new-surfaces): CreateSecretAccessRequest
		// — self-service creation of a secret-scoped access request
		// (internal/core/classification_gate.go's RequestSecretAccess, introduced
		// by #2032), previously entirely absent from this catalog.
		Key: "REST POST /api/v1/secret-access-requests",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			return secretID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			secretID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secret-access-requests", map[string]any{
				"secret_id": secretID, "reason": "fuzz access request",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 8: WithdrawSecretAccessRequest — self-service withdraw of
		// the caller's own pending secret-scoped request (invitations.go's generic
		// WithdrawAccessRequest, unchanged for this SecretID-scoped shape). State
		// is seeded directly through the unfaulted storage wrapper (same shortcut
		// break-glass batch 7 uses) as the world's own bootstrap admin
		// ("faultadmin"), since Execute authenticates as that same admin token and
		// withdraw requires requester == caller.
		Key: "REST POST /api/v1/secret-access-requests/{requestId}/withdraw",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			admin, err := w.faulty.GetUserByUsername(ctx, "faultadmin")
			if err != nil {
				return nil, fmt.Errorf("setup GetUserByUsername(faultadmin): %w", err)
			}
			expires := time.Now().Add(24 * time.Hour)
			created, err := w.faulty.CreateAccessRequest(ctx, &models.AccessRequest{
				ProjectID: 1, UserID: admin.ID, SecretID: &secretID,
				State: core.AccessRequestPending, Reason: "fuzz withdraw setup", ExpiresAt: &expires,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateAccessRequest: %w", err)
			}
			return created.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			reqID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secret-access-requests/%d/withdraw", reqID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 8: ResolveSecretAccessRequest (approve) — the
		// requester-cannot-approve-their-own, admin-authority-ceiling-gated state
		// transition (ApproveSecretAccessRequest), the most state-machine-shaped
		// operation in this family. Requester is a freshly created ordinary user
		// (never the world's own admin), so the real Execute call — as the
		// bootstrap admin, who never made the request — exercises the actual
		// authority/self-approval guards rather than short-circuiting them.
		Key: "REST PUT /api/v1/secret-access-requests/{requestId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			requesterID, err := createUserForFuzz(ctx, w, "fuzz-sar-requester")
			if err != nil {
				return nil, err
			}
			expires := time.Now().Add(24 * time.Hour)
			created, err := w.faulty.CreateAccessRequest(ctx, &models.AccessRequest{
				ProjectID: 1, UserID: requesterID, SecretID: &secretID,
				State: core.AccessRequestPending, Reason: "fuzz approve setup", ExpiresAt: &expires,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateAccessRequest: %w", err)
			}
			return created.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			reqID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secret-access-requests/%d", reqID), map[string]any{
				"action": "approve",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 10 (FAULTOPS-SPEED STEP 2, wiring batch 2, 2026-09-27):
		// gRPC siblings of already-REST-wired core CRUD -- proves the harness
		// generalizes across transports for the same resource families batch 9
		// covered for REST, per this harness's own stated purpose.
		Key: "GRPC keyorix.v1.ProjectService.UpdateProject",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-b10-proj-update"})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewProjectServiceClient(w.grpcConn).UpdateProject(w.grpcCtx, &pb.UpdateProjectRequest{
				Id: uint32(id), Name: "fuzz-b10-proj-updated",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.ProjectService.DeleteProject",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-b10-proj-delete"})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewProjectServiceClient(w.grpcConn).DeleteProject(w.grpcCtx, &pb.DeleteProjectRequest{Id: uint32(id)})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.UserService.UpdateUser",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b10-user-update")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			newName := "Fuzz B10 Updated"
			_, err := pb.NewUserServiceClient(w.grpcConn).UpdateUser(w.grpcCtx, &pb.UpdateUserRequest{
				Id: uint32(id), DisplayName: &newName,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.UserService.DeleteUser",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b10-user-delete")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewUserServiceClient(w.grpcConn).DeleteUser(w.grpcCtx, &pb.DeleteUserRequest{Id: uint32(id)})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.GroupService.UpdateGroup",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createGroupForFuzz(ctx, w, "fuzz-b10-group-update")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewGroupServiceClient(w.grpcConn).UpdateGroup(w.grpcCtx, &pb.UpdateGroupRequest{
				Id: uint32(id), Name: "fuzz-b10-group-updated",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.GroupService.DeleteGroup",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createGroupForFuzz(ctx, w, "fuzz-b10-group-delete")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewGroupServiceClient(w.grpcConn).DeleteGroup(w.grpcCtx, &pb.DeleteGroupRequest{Id: uint32(id)})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Setup soft-deletes the group first (via the same gRPC DeleteGroup this
		// catalog already wires above), then Execute restores it — proving
		// RestoreGroup on a genuinely soft-deleted row, not a no-op on a live one.
		Key: "GRPC keyorix.v1.GroupService.RestoreGroup",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createGroupForFuzz(ctx, w, "fuzz-b10-group-restore")
			if err != nil {
				return nil, err
			}
			if _, err := pb.NewGroupServiceClient(w.grpcConn).DeleteGroup(w.grpcCtx, &pb.DeleteGroupRequest{Id: uint32(id)}); err != nil {
				return nil, fmt.Errorf("setup DeleteGroup (grpc): %w", err)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewGroupServiceClient(w.grpcConn).RestoreGroup(w.grpcCtx, &pb.RestoreGroupRequest{Id: uint32(id)})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.GroupService.AddGroupMember",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-b10-group-addmember")
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-b10-addmember-user")
			if err != nil {
				return nil, err
			}
			return map[string]uint{"groupID": groupID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewGroupServiceClient(w.grpcConn).AddGroupMember(w.grpcCtx, &pb.GroupMemberRequest{
				GroupId: uint32(s["groupID"]), UserId: uint32(s["userID"]),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Setup adds the member first (via the same gRPC AddGroupMember this
		// catalog already wires above), so Execute removes a genuinely-present
		// member, not a no-op.
		Key: "GRPC keyorix.v1.GroupService.RemoveGroupMember",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-b10-group-removemember")
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-b10-removemember-user")
			if err != nil {
				return nil, err
			}
			if _, err := pb.NewGroupServiceClient(w.grpcConn).AddGroupMember(w.grpcCtx, &pb.GroupMemberRequest{
				GroupId: uint32(groupID), UserId: uint32(userID),
			}); err != nil {
				return nil, fmt.Errorf("setup AddGroupMember (grpc): %w", err)
			}
			return map[string]uint{"groupID": groupID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewGroupServiceClient(w.grpcConn).RemoveGroupMember(w.grpcCtx, &pb.GroupMemberRequest{
				GroupId: uint32(s["groupID"]), UserId: uint32(s["userID"]),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.RoleService.UpdateRole",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			desc := "fuzz b10 updated role"
			_, err := pb.NewRoleServiceClient(w.grpcConn).UpdateRole(w.grpcCtx, &pb.UpdateRoleRequest{
				Id: uint32(id), Description: &desc, Permissions: []string{"secrets.read"},
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// RemoveRole is AssignRole's revoke sibling (both already-wired
		// AssignRole above and this entry share the exact same request shape:
		// user+role+optional scope). Setup assigns first so Execute revokes a
		// genuinely-held grant.
		Key: "GRPC keyorix.v1.RoleService.RemoveRole",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-b10-removerole-user")
			if err != nil {
				return nil, err
			}
			if _, err := pb.NewRoleServiceClient(w.grpcConn).AssignRole(w.grpcCtx, &pb.AssignRoleRequest{
				UserId: uint32(userID), RoleId: uint32(roleID),
			}); err != nil {
				return nil, fmt.Errorf("setup AssignRole (grpc): %w", err)
			}
			return map[string]uint{"userID": userID, "roleID": roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewRoleServiceClient(w.grpcConn).RemoveRole(w.grpcCtx, &pb.RemoveRoleRequest{
				UserId: uint32(s["userID"]), RoleId: uint32(s["roleID"]),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.SecretService.CreateSecret",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			_, err := pb.NewSecretServiceClient(w.grpcConn).CreateSecret(w.grpcCtx, &pb.CreateSecretRequest{
				Name: "fuzz-b10-secret-grpc-create", Value: "fuzz-value", ProjectId: 1, EnvironmentId: 1, Type: "generic",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.SecretService.UpdateSecret",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			newVal := "fuzz-b10-secret-grpc-updated"
			_, err := pb.NewSecretServiceClient(w.grpcConn).UpdateSecret(w.grpcCtx, &pb.UpdateSecretRequest{
				Id: uint32(id), Value: &newVal,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.SecretService.DeleteSecret",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewSecretServiceClient(w.grpcConn).DeleteSecret(w.grpcCtx, &pb.DeleteSecretRequest{Id: uint32(id)})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 11 (FAULTOPS-SPEED STEP 2, wiring batch 3, 2026-09-27):
		// ordinary PATCH/PUT variants of the already-wired secret resource --
		// classification, description, retention override, tags, temporal
		// access schedule.
		Key: "REST PATCH /api/v1/secrets/{id}/classification",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/classification", id), map[string]any{
				"classification": "internal",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST PATCH /api/v1/secrets/{id}/description",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/description", id), map[string]any{
				"description": "fuzz b11 description",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST PATCH /api/v1/secrets/{id}/retention",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/retention", id), map[string]any{
				"retention_override_days": 30,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST PUT /api/v1/secrets/{id}/tags",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/tags", id), map[string]any{
				"tags": []string{"fuzz", "b11"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST PUT /api/v1/secrets/{id}/schedule",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/schedule", id), map[string]any{
				"allowed_days": "1,2,3,4,5", "start_hour": 9, "end_hour": 17, "timezone": "UTC",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 11: admin job on-demand triggers (server/http/handlers/
		// admin_jobs.go and its siblings) -- plain no-body POSTs gated on
		// system.write, no precondition beyond the bootstrapped admin (per the
		// STEP 1 report's own characterization of this family).
		Key: "REST POST /api/v1/admin/jobs/anomaly-alerts",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/anomaly-alerts", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/rotation-reminders",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/rotation-reminders", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/expiry-reminders",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/expiry-reminders", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/compliance-digest",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/record-hygiene-snapshot",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/record-hygiene-snapshot", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/role-expiry-check",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/role-expiry-check", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/check-read-quotas",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/check-read-quotas", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/run-alert-escalation",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/run-alert-escalation", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/token-expiry-check",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/token-expiry-check", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/suspend-inactive-users",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/suspend-inactive-users", map[string]any{
				"inactive_days": 90,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/admin/jobs/purge-audit-logs",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/jobs/purge-audit-logs", map[string]any{
				"retention_days": 30,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// admin_impersonation.go's Start: gated by users.impersonate
		// (admin-bypass only); refuses self-impersonation and a nonexistent
		// target — batch 12.
		Key: "REST POST /api/v1/admin/impersonate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b12-impersonate-target")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			userID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/admin/impersonate", map[string]any{
				"user_id": userID,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// admin_impersonation.go's End: authenticates via the impersonation
		// session's OWN token (extractBearerToken), never the admin's —
		// Setup performs a real Start to obtain that token — batch 12.
		Key: "REST POST /api/v1/auth/end-impersonation",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b12-endimp-target")
			if err != nil {
				return nil, err
			}
			return startImpersonationForFuzz(ctx, w, userID)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			token := state.(string)
			st, body, err := httpJSONAs(ctx, w, token, http.MethodPost, "/api/v1/auth/end-impersonation", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// access_review_campaigns.go's OpenAccessReviewCampaign — batch 13.
		Key: "REST POST /api/v1/projects/{id}/access-review/campaigns",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/access-review/campaigns", map[string]any{
				"name": "fuzz campaign",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// access_review_campaigns.go's CloseAccessReviewCampaign, force-closed
		// with zero items pending — batch 13.
		Key: "REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return openAccessReviewCampaignForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			campaignID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/access-review/campaigns/%d/close", campaignID), map[string]any{
				"force": true,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// access_review_campaigns.go's DecideAccessReviewCampaignItem (attest
		// action) — batch 13.
		Key: "REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b13-decide-user")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := assignUserRoleForFuzz(ctx, w, userID, roleID, 1); err != nil {
				return nil, err
			}
			campaignID, err := openAccessReviewCampaignForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			itemID, err := accessReviewItemIDForPrincipal(ctx, w, 1, campaignID, userID)
			if err != nil {
				return nil, err
			}
			return [2]uint{campaignID, itemID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/access-review/campaigns/%d/items/%d/decide", ids[0], ids[1]), map[string]any{
				"action": "attest", "reason": "fuzz",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// project_members.go's AttestProjectAccessReview (standalone
		// endpoint, not the campaign flow) — batch 13.
		Key: "REST POST /api/v1/projects/{id}/access-review/attest",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b13-attest-user")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := assignUserRoleForFuzz(ctx, w, userID, roleID, 1); err != nil {
				return nil, err
			}
			return [2]uint{userID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/access-review/attest", map[string]any{
				"source": "role", "principal_type": "user", "principal_id": ids[0], "role_id": ids[1], "environment_id": 0,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// project_members.go's RevokeProjectAccessReview (standalone
		// endpoint, not the campaign flow) — batch 13.
		Key: "REST POST /api/v1/projects/{id}/access-review/revoke",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b13-revoke-user")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := assignUserRoleForFuzz(ctx, w, userID, roleID, 1); err != nil {
				return nil, err
			}
			return [2]uint{userID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/access-review/revoke", map[string]any{
				"source": "role", "principal_type": "user", "principal_id": ids[0], "role_id": ids[1], "environment_id": 0,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's CreateMachineIdentity — batch 14.
		Key: "REST POST /api/v1/projects/{id}/machine-identities",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/machine-identities", map[string]any{
				"name": "fuzz-machine-create", "identity_type": "service",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's MigrateUserToMachine (ADR-023) — batch 14.
		Key: "REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b14-migrate-user")
		},
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/machine-identities/migrate-from-user", map[string]any{
				"username": "fuzz-b14-migrate-user", "identity_type": "service", "name": "fuzz-migrated",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's TransitionMachineIdentity: a fresh identity
		// is created ACTIVE, so the only legal first move is suspend or
		// revoke (machineTransitions), not "activate" — batch 14.
		Key: "REST PUT /api/v1/projects/{id}/machine-identities/{machineId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createMachineIdentityForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			machineID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d", machineID), map[string]any{
				"action": "suspend",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's IssueMachineToken — batch 14.
		Key: "REST POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createMachineIdentityForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			machineID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/tokens", machineID), map[string]any{
				"name": "fuzz-token-issue", "expires_in_days": 90,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's RevokeMachineToken — batch 14.
		Key: "REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			machineID, err := createMachineIdentityForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			tokenID, err := issueMachineTokenForFuzz(ctx, w, 1, machineID)
			if err != nil {
				return nil, err
			}
			return [2]uint{machineID, tokenID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/tokens/%d", ids[0], ids[1]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's ClassifyMachineIdentity — batch 14.
		Key: "REST PATCH /api/v1/projects/{id}/machine-identities/{machineId}/classification",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createMachineIdentityForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			machineID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/classification", machineID), map[string]any{
				"classification": "internal",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's ClassifyMachineToken — batch 14.
		Key: "REST PATCH /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			machineID, err := createMachineIdentityForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			tokenID, err := issueMachineTokenForFuzz(ctx, w, 1, machineID)
			if err != nil {
				return nil, err
			}
			return [2]uint{machineID, tokenID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/tokens/%d/classification", ids[0], ids[1]), map[string]any{
				"classification": "internal",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's GrantMachineRole — batch 14.
		Key: "REST POST /api/v1/projects/{id}/machine-identities/{machineId}/roles",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			machineID, err := createMachineIdentityForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			return [2]uint{machineID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/roles", ids[0]), map[string]any{
				"role_id": ids[1],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's RemoveMachineRole — batch 14.
		Key: "REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			machineID, err := createMachineIdentityForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/roles", machineID), map[string]any{
				"role_id": roleID,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup GrantMachineRole: HTTP %d: %s", st, body)
			}
			return [2]uint{machineID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/roles/%d", ids[0], ids[1]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's CreateOIDCBinding (ADR-031) — batch 14.
		Key: "REST POST /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createMachineIdentityForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			machineID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/oidc-bindings", machineID), map[string]any{
				"issuer": "https://fuzz.example/issuer", "subject": "fuzz-subject",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// machine_identities.go's DeleteOIDCBinding — batch 14.
		Key: "REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			machineID, err := createMachineIdentityForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/oidc-bindings", machineID), map[string]any{
				"issuer": "https://fuzz.example/issuer", "subject": "fuzz-subject-delete",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateOIDCBinding: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateOIDCBinding response: %w (body=%s)", err, body)
			}
			return [2]uint{machineID, decoded.Data.ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/oidc-bindings/%d", ids[0], ids[1]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "GRPC keyorix.v1.MachineIdentityService.CreateMachineIdentity",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			_, err := pb.NewMachineIdentityServiceClient(w.grpcConn).CreateMachineIdentity(w.grpcCtx, &pb.CreateMachineIdentityRequest{
				ProjectId: 1, Name: "fuzz-b14-machine-grpc-create", IdentityType: "service",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.MachineIdentityService.TransitionMachineIdentity",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createMachineIdentityForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			machineID := state.(uint)
			_, err := pb.NewMachineIdentityServiceClient(w.grpcConn).TransitionMachineIdentity(w.grpcCtx, &pb.TransitionMachineIdentityRequest{
				ProjectId: 1, MachineId: uint32(machineID), Action: "suspend",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.MachineIdentityService.ClassifyMachineIdentity",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createMachineIdentityForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			machineID := state.(uint)
			_, err := pb.NewMachineIdentityServiceClient(w.grpcConn).ClassifyMachineIdentity(w.grpcCtx, &pb.ClassifyMachineIdentityRequest{
				ProjectId: 1, MachineId: uint32(machineID), Classification: "internal",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.MachineIdentityService.IssueMachineToken",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createMachineIdentityForFuzz(ctx, w, 1)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			machineID := state.(uint)
			_, err := pb.NewMachineIdentityServiceClient(w.grpcConn).IssueMachineToken(w.grpcCtx, &pb.IssueMachineTokenRequest{
				ProjectId: 1, MachineId: uint32(machineID), Name: "fuzz-b14-token-grpc", ExpiresInDays: 90,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.MachineIdentityService.RevokeMachineToken",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			machineID, err := createMachineIdentityForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			tokenID, err := issueMachineTokenForFuzz(ctx, w, 1, machineID)
			if err != nil {
				return nil, err
			}
			return [2]uint{machineID, tokenID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			_, err := pb.NewMachineIdentityServiceClient(w.grpcConn).RevokeMachineToken(w.grpcCtx, &pb.RevokeMachineTokenRequest{
				ProjectId: 1, MachineId: uint32(ids[0]), TokenId: uint32(ids[1]),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// invitations.go's CreateInvitation — batch 15.
		Key: "REST POST /api/v1/projects/{id}/invitations",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/invitations", map[string]any{
				"email": "fuzz-b15-invitee@example.com", "role": "viewer",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// invitations.go's RevokeInvitation — batch 15.
		Key: "REST DELETE /api/v1/projects/{id}/invitations/{invitationId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/invitations", map[string]any{
				"email": "fuzz-b15-revoke@example.com", "role": "viewer",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateInvitation: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Invitation struct {
						ID uint `json:"id"`
					} `json:"invitation"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Invitation.ID == 0 {
				return nil, fmt.Errorf("decoding CreateInvitation response: %w (body=%s)", err, body)
			}
			return decoded.Data.Invitation.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			invID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/1/invitations/%d", invID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// invitations.go's CreateGlobalInvitation (ADR-024) — batch 15.
		Key: "REST POST /api/v1/invitations",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/invitations", map[string]any{
				"email": "fuzz-b15-global-invitee@example.com",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// invitations.go's CreateAccessRequest (self-service) — batch 15.
		Key: "REST POST /api/v1/projects/{id}/access-requests",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/access-requests", map[string]any{
				"suggested_role": "viewer", "reason": "fuzz",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// invitations.go's WithdrawAccessRequest (self-service; the withdrawer
		// must be the request's own creator, which the admin caller is here) —
		// batch 15.
		Key: "REST POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/access-requests", map[string]any{
				"suggested_role": "viewer", "reason": "fuzz withdraw",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateAccessRequest: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					AccessRequest struct {
						ID uint `json:"id"`
					} `json:"access_request"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.AccessRequest.ID == 0 {
				return nil, fmt.Errorf("decoding CreateAccessRequest response: %w (body=%s)", err, body)
			}
			return decoded.Data.AccessRequest.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			reqID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/access-requests/%d/withdraw", reqID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// invitations.go's ResolveAccessRequest (approve): the resolver must
		// NOT be the request's own creator ("cannot approve their own"), so
		// Setup logs in as a freshly created, non-admin user to create the
		// request — batch 15.
		Key: "REST PUT /api/v1/projects/{id}/access-requests/{requestId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b15-resolve-requester")
			if err != nil {
				return nil, err
			}
			token, err := loginForFuzz(ctx, w, "fuzz-b15-resolve-requester", fuzzUserPassword)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSONAs(ctx, w, token, http.MethodPost, "/api/v1/projects/1/access-requests", map[string]any{
				"suggested_role": "viewer", "reason": "fuzz resolve",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateAccessRequest (as user %d): HTTP %d: %s", userID, st, body)
			}
			var decoded struct {
				Data struct {
					AccessRequest struct {
						ID uint `json:"id"`
					} `json:"access_request"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.AccessRequest.ID == 0 {
				return nil, fmt.Errorf("decoding CreateAccessRequest response: %w (body=%s)", err, body)
			}
			return decoded.Data.AccessRequest.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			reqID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/projects/1/access-requests/%d", reqID), map[string]any{
				"action": "approve", "granted_role": "viewer",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "GRPC keyorix.v1.ProjectService.CreateProject",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			_, err := pb.NewProjectServiceClient(w.grpcConn).CreateProject(w.grpcCtx, &pb.CreateProjectRequest{
				Name: "fuzz-b15-project-grpc-create",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// catalog.go's DeleteProject on a freshly created, otherwise-unused
		// project (not project 1, which every other op's Setup assumes
		// exists) — batch 15.
		Key: "REST DELETE /api/v1/projects/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createProjectForFuzz(ctx, w, "fuzz-b15-project-delete")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// catalog.go's RestoreProject — batch 15.
		Key: "REST POST /api/v1/projects/{id}/restore",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createProjectForFuzz(ctx, w, "fuzz-b15-project-restore")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d", id), nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup DeleteProject: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/restore", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// catalog.go's CreateProjectEnvironment — batch 15.
		Key: "REST POST /api/v1/projects/{id}/environments",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/environments", map[string]any{
				"name": "fuzz-b15-env-create",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// catalog.go's DeleteEnvironment — batch 15.
		Key: "REST DELETE /api/v1/environments/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createEnvironmentForFuzz(ctx, w, 1, "fuzz-b15-env-delete")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/environments/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// catalog.go's CloneEnvironment: two environments in the same project
		// — batch 15.
		Key: "REST POST /api/v1/projects/{id}/environments/{envId}/clone",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			src, err := createEnvironmentForFuzz(ctx, w, 1, "fuzz-b15-env-clone-src")
			if err != nil {
				return nil, err
			}
			dst, err := createEnvironmentForFuzz(ctx, w, 1, "fuzz-b15-env-clone-dst")
			if err != nil {
				return nil, err
			}
			return [2]uint{src, dst}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/environments/%d/clone", ids[0]), map[string]any{
				"destination_environment_id": ids[1],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// catalog.go's RestoreEnvironment (nested under the project so the
		// permission scope resolves; note the {projectId}/{id} param names,
		// swapped from every other environment route) — batch 15.
		Key: "REST POST /api/v1/projects/{projectId}/environments/{id}/restore",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createEnvironmentForFuzz(ctx, w, 1, "fuzz-b15-env-restore")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/environments/%d", id), nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup DeleteEnvironment: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/environments/%d/restore", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_copy_environment.go's CopyEnvironmentSecrets: two
		// environments in the same project — batch 15.
		Key: "REST POST /api/v1/projects/{id}/environments/{envId}/copy-secrets",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			src, err := createEnvironmentForFuzz(ctx, w, 1, "fuzz-b15-env-copy-src")
			if err != nil {
				return nil, err
			}
			dst, err := createEnvironmentForFuzz(ctx, w, 1, "fuzz-b15-env-copy-dst")
			if err != nil {
				return nil, err
			}
			return [2]uint{src, dst}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/environments/%d/copy-secrets", ids[0]), map[string]any{
				"target_environment_id": ids[1],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "GRPC keyorix.v1.RoleService.CreateRole",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			_, err := pb.NewRoleServiceClient(w.grpcConn).CreateRole(w.grpcCtx, &pb.CreateRoleRequest{
				Name: "fuzz-b15-role-grpc-create", Description: "fuzz role", Permissions: []string{"secrets.read"},
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.UserService.CreateUser",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			pw := fuzzUserPassword
			_, err := pb.NewUserServiceClient(w.grpcConn).CreateUser(w.grpcCtx, &pb.CreateUserRequest{
				Username: "fuzz-b15-user-grpc-create", Email: "fuzz-b15-user-grpc-create@example.com", Password: &pw,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// rbac.go's AssignRoleToGroup — batch 16.
		Key: "REST POST /api/v1/groups/{id}/roles",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-b16-group-role")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			return [2]uint{groupID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/roles", ids[0]), map[string]any{
				"role_id": ids[1], "project_id": 1,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// rbac.go's RemoveRoleFromGroup: scope comes from QUERY params, not
		// body, unlike the grant side — batch 16.
		Key: "REST DELETE /api/v1/groups/{id}/roles/{roleId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-b16-group-removerole")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/roles", groupID), map[string]any{
				"role_id": roleID, "project_id": 1,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup AssignRoleToGroup: HTTP %d: %s", st, body)
			}
			return [2]uint{groupID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d/roles/%d?project_id=1", ids[0], ids[1]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// rbac.go's AssignPermissionToRole — batch 16.
		Key: "REST POST /api/v1/roles/{id}/permissions",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			permID, err := permissionIDByNameForFuzz(ctx, w, "secrets.write")
			if err != nil {
				return nil, err
			}
			return [2]uint{roleID, permID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/roles/%d/permissions", ids[0]), map[string]any{
				"permission_id": ids[1],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// rbac.go's RemovePermissionFromRole — batch 16.
		Key: "REST DELETE /api/v1/roles/{id}/permissions/{permissionId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			permID, err := permissionIDByNameForFuzz(ctx, w, "secrets.write")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/roles/%d/permissions", roleID), map[string]any{
				"permission_id": permID,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup AssignPermissionToRole: HTTP %d: %s", st, body)
			}
			return [2]uint{roleID, permID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d/permissions/%d", ids[0], ids[1]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// groups_handler.go's RestoreGroup — batch 16.
		Key: "REST POST /api/v1/groups/{id}/restore",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-b16-group-restore")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d", groupID), nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup DeleteGroup: HTTP %d: %s", st, body)
			}
			return groupID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			groupID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/restore", groupID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// scim_groups.go's PatchGroup -> core.PatchSCIMGroup (the "add a member"
		// shape, not the "members replace" shape that routes to
		// ReplaceSCIMGroup instead -- see PatchGroup's own replaceAll switch).
		// SESSION-AT AT5: /scim/v2 was never reachable in this harness at all
		// (cfg.SCIM.Enabled was never set) until faultopsSCIMToken wired it in.
		Key: "REST PATCH /scim/v2/Groups/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-at5-scim-patch-group")
			if err != nil {
				return nil, err
			}
			// Must be SCIM-managed (createSCIMUserForFuzz, not
			// createUserForFuzz) -- scim_groups.go's member-add path (#167)
			// rejects a plain, non-SCIM-provisioned account.
			userID, err := createSCIMUserForFuzz(ctx, w, "fuzz-at5-scim-patch-user")
			if err != nil {
				return nil, err
			}
			return [2]uint{groupID, userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := scimJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/scim/v2/Groups/%d", ids[0]), map[string]any{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
				"Operations": []map[string]any{
					{"op": "add", "path": "members", "value": []map[string]any{
						{"value": fmt.Sprintf("%d", ids[1])},
					}},
				},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// scim_groups.go's ReplaceGroup -> core.ReplaceSCIMGroup (full
		// rename + member-set replace). SESSION-AT AT5.
		Key: "REST PUT /scim/v2/Groups/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createGroupForFuzz(ctx, w, "fuzz-at5-scim-replace-group")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			groupID := state.(uint)
			st, body, err := scimJSON(ctx, w, http.MethodPut, fmt.Sprintf("/scim/v2/Groups/%d", groupID), map[string]any{
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
				"displayName": "fuzz-at5-scim-replace-group-renamed",
				"members":     []map[string]any{},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// scim_groups.go's DeleteGroup -> core.DeprovisionSCIMGroup. SESSION-AT AT5.
		Key: "REST DELETE /scim/v2/Groups/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createGroupForFuzz(ctx, w, "fuzz-at5-scim-deprovision-group")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			groupID := state.(uint)
			st, body, err := scimJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/scim/v2/Groups/%d", groupID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's DeleteUser (REST) — batch 16.
		Key: "REST DELETE /api/v1/users/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b16-user-delete")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// project_members.go's RemoveProjectMember — batch 16.
		Key: "REST DELETE /api/v1/projects/{id}/members/{userId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b16-member-remove")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return userID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			userID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/1/members/%d", userID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// project_members.go's UpdateProjectMember — batch 16.
		Key: "REST PUT /api/v1/projects/{id}/members/{userId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b16-member-update")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return userID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			userID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/projects/1/members/%d", userID), map[string]any{
				"role": "viewer",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// project_memberships.go's InviteMember (the state-machine
		// membership flow, distinct from the plain /members endpoint) —
		// batch 16.
		Key: "REST POST /api/v1/projects/{id}/memberships",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b16-membership-invite")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			userID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/memberships", map[string]any{
				"user_id": userID, "role": "viewer",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// project_memberships.go's TransitionMembership: a fresh
		// (non-IDP-resolved) invite starts at "invited", so the only legal
		// first move is "verify" (membershipTransitions) — batch 16.
		Key: "REST PUT /api/v1/projects/{id}/memberships/{membershipId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b16-membership-transition")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/memberships", map[string]any{
				"user_id": userID, "role": "viewer",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup InviteMember: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Membership struct {
						ID uint `json:"id"`
					} `json:"membership"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Membership.ID == 0 {
				return nil, fmt.Errorf("decoding InviteMember response: %w (body=%s)", err, body)
			}
			return decoded.Data.Membership.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			membershipID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/projects/1/memberships/%d", membershipID), map[string]any{
				"action": "verify",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// rbac.go's AssignRole (dedicated opCatalog entry for the registry
		// key itself — assignUserRoleForFuzz already exercises this handler
		// as a setup helper elsewhere, but that isn't a registered opCatalog
		// key) — batch 16.
		Key: "REST POST /api/v1/user-roles/",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b16-userroles-assign")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			return [2]uint{userID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/user-roles/", map[string]any{
				"user_id": ids[0], "role_id": ids[1], "project_id": 1, "environment_id": 0,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// rbac.go's RemoveRole (dedicated opCatalog entry, same reasoning as
		// the AssignRole entry above) — batch 16.
		Key: "REST DELETE /api/v1/user-roles/",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b16-userroles-remove")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := assignUserRoleForFuzz(ctx, w, userID, roleID, 1); err != nil {
				return nil, err
			}
			return [2]uint{userID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, "/api/v1/user-roles/", map[string]any{
				"user_id": ids[0], "role_id": ids[1], "project_id": 1, "environment_id": 0,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_bulk_delete.go's BulkDeleteSecrets — batch 17.
		//
		// SESSION-FI (AT5): this op's Setup requests exactly ONE secret_id, so
		// the single item's outcome IS the operation's outcome for fault-
		// injection purposes -- but BulkDeleteSecrets always replies HTTP 200
		// with a per-item {deleted,failed,total} breakdown in the body (bulk
		// ops report partial results inside a success envelope, by design;
		// there is no non-2xx "some items failed" status). httpResult's plain
		// status-code mapping can't see that, so a fault that correctly,
		// safely denies THIS ONE item (e.g. an authz-resolution read erroring,
		// which the real code already fails closed on — the item lands in
		// "failed", never "deleted") still reported opResult.Success=true,
		// tripping oracle (c) ("a fault on an authz-resolution read produced a
		// SUCCESSFUL result") on a response that never actually deleted
		// anything. Found live by FuzzStorageFaultOperations (fault=
		// GetUserGroupRoleIDsAt#2/error): response body was
		// {"failed":[{"secret_id":1,"error":"secret not found"}],"deleted":[]} —
		// correctly denied, just misread by the harness as a bare HTTP 200
		// success. Parse the body instead of trusting the status code alone.
		Key: "REST POST /api/v1/projects/{id}/secrets/bulk-delete",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/bulk-delete", map[string]any{
				"secret_ids": []uint{id},
			})
			if err != nil {
				return opResult{}, err
			}
			if st/100 == 2 {
				var parsed struct {
					Data struct {
						Deleted []uint `json:"deleted"`
						Failed  []struct {
							SecretID uint   `json:"secret_id"`
							Error    string `json:"error"`
						} `json:"failed"`
					} `json:"data"`
				}
				if jerr := json.Unmarshal(body, &parsed); jerr == nil && len(parsed.Data.Failed) > 0 && len(parsed.Data.Deleted) == 0 {
					return opResult{Success: false, Detail: fmt.Sprintf("HTTP %d (bulk-delete item failed): %s", st, body)}, nil
				}
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_bulk_rename.go's BulkRenameSecrets — batch 17.
		Key: "REST POST /api/v1/projects/{id}/secrets/bulk-rename",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/bulk-rename", map[string]any{
				"renames": []map[string]any{{"id": id, "new_name": "fuzz-b17-renamed"}},
			})
			if err != nil {
				return opResult{}, err
			}
			// SESSION-FI (AT5): same per-item-vs-envelope gap fixed on the
			// bulk-delete sibling above — BulkRenameSecrets always returns
			// HTTP 200 with a renamed/skipped count, so a fault that
			// correctly, safely skips THIS SINGLE requested rename must not
			// be read as Success=true. Fixed proactively (not yet
			// independently fuzzer-triggered) per "check fix siblings."
			if st/100 == 2 {
				var parsed struct {
					Data struct {
						Renamed int `json:"renamed"`
					} `json:"data"`
				}
				if jerr := json.Unmarshal(body, &parsed); jerr == nil && parsed.Data.Renamed == 0 {
					return opResult{Success: false, Detail: fmt.Sprintf("HTTP %d (bulk-rename item not renamed): %s", st, body)}, nil
				}
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_bulk_rotate.go's BulkRotateSecrets: every field optional
		// (omitted secret_ids rotates all matches) — batch 17.
		Key: "REST POST /api/v1/projects/{id}/secrets/bulk-rotate",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate", map[string]any{})
			if err != nil {
				return opResult{}, err
			}
			// SESSION-FI (AT5): same per-item-vs-envelope gap fixed on the
			// bulk-delete sibling above — only flag a failure when something
			// was actually attempted and every attempt failed (Total==0, no
			// matching secrets at all, is a legitimate identical no-op in
			// both the reference and faulted worlds, not a violation).
			if st/100 == 2 {
				var parsed struct {
					Data struct {
						Triggered []uint `json:"triggered"`
						Failed    []struct {
							SecretID uint   `json:"secret_id"`
							Error    string `json:"error"`
						} `json:"failed"`
					} `json:"data"`
				}
				if jerr := json.Unmarshal(body, &parsed); jerr == nil && len(parsed.Data.Failed) > 0 && len(parsed.Data.Triggered) == 0 {
					return opResult{Success: false, Detail: fmt.Sprintf("HTTP %d (bulk-rotate item failed): %s", st, body)}, nil
				}
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_extend_expiring.go's ExtendExpiringSecrets: empty body is
		// valid (defaults apply) — batch 17.
		Key: "REST POST /api/v1/projects/{id}/secrets/extend-expiring",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/extend-expiring", map[string]any{})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_reassign_owner.go's ReassignOwner — batch 17.
		Key: "REST POST /api/v1/projects/{id}/secrets/reassign-owner",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			from, err := createUserForFuzz(ctx, w, "fuzz-b17-reassign-from")
			if err != nil {
				return nil, err
			}
			to, err := createUserForFuzz(ctx, w, "fuzz-b17-reassign-to")
			if err != nil {
				return nil, err
			}
			return [2]uint{from, to}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/reassign-owner", map[string]any{
				"from_owner_id": ids[0], "to_owner_id": ids[1],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_render.go's RenderTemplate: a literal template with no
		// ${secret:...} references resolves trivially — batch 17.
		Key: "REST POST /api/v1/projects/{id}/secrets/render",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/render", map[string]any{
				"template": "fuzz literal template, no references",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// projects_suspend.go's ResumeProjectSecrets — batch 17.
		Key: "REST POST /api/v1/projects/{id}/secrets/resume-all",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/resume-all", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// projects_suspend.go's SuspendProjectSecrets — batch 17.
		Key: "REST POST /api/v1/projects/{id}/secrets/suspend-all",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/secrets/suspend-all", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_copy.go's CopySecret: a second environment in the same
		// project to copy into — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/copy",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			envID, err := createEnvironmentForFuzz(ctx, w, 1, "fuzz-b17-copy-dst-env")
			if err != nil {
				return nil, err
			}
			return [2]uint{secretID, envID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/copy", ids[0]), map[string]any{
				"environment_id": ids[1], "name": "fuzz-b17-secret-copy",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_dependencies.go's AddSecretDependency: a second secret in
		// the same project to depend on — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/dependencies",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			dependsOnID, err := createSecretNamedForFuzz(ctx, w, "fuzz-b17-dependency-target")
			if err != nil {
				return nil, err
			}
			return [2]uint{secretID, dependsOnID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/dependencies", ids[0]), map[string]any{
				"depends_on_id": ids[1], "note": "fuzz dependency",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_dependencies.go's RemoveSecretDependency — batch 17.
		Key: "REST DELETE /api/v1/secrets/{id}/dependencies/{depId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			dependsOnID, err := createSecretNamedForFuzz(ctx, w, "fuzz-b17-dependency-target")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/dependencies", secretID), map[string]any{
				"depends_on_id": dependsOnID, "note": "fuzz dependency",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup AddSecretDependency: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding AddSecretDependency response: %w (body=%s)", err, body)
			}
			return [2]uint{secretID, decoded.Data.ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/dependencies/%d", ids[0], ids[1]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_move.go's MoveSecret: parent_id 0 means root, a no-op move
		// for a secret that already has no parent — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/move",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/move", id), map[string]any{
				"parent_id": 0,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_crud.go's RestoreSecret — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/restore",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup DeleteSecret: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/restore", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_suspend.go's ResumeSecret — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/resume",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/suspend", id), nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup SuspendSecret: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/resume", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// rotation_dryrun.go's SimulateRotation (read-only) — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/rotation/simulate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotation/simulate", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_suspend.go's SuspendSecret — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/suspend",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/suspend", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secrets_ownership.go's TransferOwnership: the new owner must
		// already hold secrets.write (or secrets.manage) at the secret's
		// scope — a plain "viewer" (secrets.read only) fails this ceiling
		// check, so Setup grants a dedicated secrets.write role first —
		// batch 17.
		Key: "REST POST /api/v1/secrets/{id}/transfer-ownership",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			newOwnerID, err := createUserForFuzz(ctx, w, "fuzz-b17-transfer-newowner")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
				"name": "fuzz-b17-writer-role", "description": "fuzz writer role", "permissions": []string{"secrets.write"},
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRole: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Role struct {
						ID uint `json:"id"`
					} `json:"role"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Role.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRole response: %w (body=%s)", err, body)
			}
			if err := assignUserRoleForFuzz(ctx, w, newOwnerID, decoded.Data.Role.ID, 1); err != nil {
				return nil, err
			}
			return [2]uint{secretID, newOwnerID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/transfer-ownership", ids[0]), map[string]any{
				"new_owner_id": ids[1],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_version_comments.go's CreateComment — batch 17.
		Key: "REST POST /api/v1/secrets/{id}/versions/{versionId}/comments",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			versionID, err := firstSecretVersionIDForFuzz(ctx, w, secretID)
			if err != nil {
				return nil, err
			}
			return [2]uint{secretID, versionID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments", ids[0], ids[1]), map[string]any{
				"comment": "fuzz version comment",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_version_comments.go's DeleteComment — batch 17.
		Key: "REST DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			versionID, err := firstSecretVersionIDForFuzz(ctx, w, secretID)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments", secretID, versionID), map[string]any{
				"comment": "fuzz version comment to delete",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateComment: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Comment struct {
						ID uint `json:"id"`
					} `json:"comment"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Comment.ID == 0 {
				return nil, fmt.Errorf("decoding CreateComment response: %w (body=%s)", err, body)
			}
			return [3]uint{secretID, versionID, decoded.Data.Comment.ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([3]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments/%d", ids[0], ids[1], ids[2]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_schedule.go's DeleteSecretSchedule: a plain pass-through
		// delete, no precondition that a schedule was ever set — batch 17.
		Key: "REST DELETE /api/v1/secrets/{id}/schedule",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/schedule", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// folders_handler.go's CreateFolder — batch 18.
		Key: "REST POST /api/v1/folders/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/folders/", map[string]any{
				"name": "fuzz-b18-folder-create", "project_id": 1, "environment_id": 1,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// folders_handler.go's DeleteFolder — batch 18.
		Key: "REST DELETE /api/v1/folders/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createFolderForFuzz(ctx, w, "fuzz-b18-folder-delete")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/folders/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// legal_hold.go's PlaceLegalHold — batch 18.
		Key: "REST POST /api/v1/legal-hold",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/legal-hold", map[string]any{
				"reason": "fuzz legal hold",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// legal_hold.go's LiftLegalHold: only the placing admin may lift —
		// batch 18.
		Key: "REST DELETE /api/v1/legal-hold",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/legal-hold", map[string]any{
				"reason": "fuzz legal hold to lift",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup PlaceLegalHold: HTTP %d: %s", st, body)
			}
			return nil, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodDelete, "/api/v1/legal-hold", map[string]any{
				"reason": "fuzz lift reason",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// notification_channels.go's Create — batch 18.
		Key: "REST POST /api/v1/notification-channels",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/notification-channels", map[string]any{
				"name": "fuzz-b18-channel-create", "type": "email", "email": "fuzz-channel@example.com",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// notification_channels.go's Delete — batch 18.
		Key: "REST DELETE /api/v1/notification-channels/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/notification-channels", map[string]any{
				"name": "fuzz-b18-channel-delete", "type": "email", "email": "fuzz-channel-delete@example.com",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateNotificationChannel: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateNotificationChannel response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/notification-channels/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// notification_channels.go's Update — batch 18.
		Key: "REST PUT /api/v1/notification-channels/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/notification-channels", map[string]any{
				"name": "fuzz-b18-channel-update", "type": "email", "email": "fuzz-channel-update@example.com",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateNotificationChannel: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateNotificationChannel response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/notification-channels/%d", id), map[string]any{
				"name": "fuzz-b18-channel-updated", "type": "email", "email": "fuzz-channel-updated@example.com",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// notification_channels.go's SetRetryPolicy — batch 18.
		Key: "REST PUT /api/v1/notification-channels/{id}/retry-policy",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/notification-channels", map[string]any{
				"name": "fuzz-b18-channel-retry", "type": "email", "email": "fuzz-channel-retry@example.com",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateNotificationChannel: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateNotificationChannel response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/notification-channels/%d/retry-policy", id), map[string]any{
				"max_retries": 5, "retry_backoff_ms": 2000,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// alert_escalation.go's Create — batch 18.
		Key: "REST POST /api/v1/alert-escalation-policies",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/alert-escalation-policies", map[string]any{
				"name": "fuzz-b18-escalation-create", "min_severity": "low", "escalate_after_minutes": 30,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// alert_escalation.go's Update — batch 18.
		Key: "REST PUT /api/v1/alert-escalation-policies/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/alert-escalation-policies", map[string]any{
				"name": "fuzz-b18-escalation-update", "min_severity": "low", "escalate_after_minutes": 30,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateAlertEscalationPolicy: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateAlertEscalationPolicy response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/alert-escalation-policies/%d", id), map[string]any{
				"name": "fuzz-b18-escalation-updated", "min_severity": "high", "escalate_after_minutes": 15,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// bulk_access_requests.go's CreateRejectionReasonTemplate — batch 18.
		Key: "REST POST /api/v1/rejection-reason-templates",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/rejection-reason-templates", map[string]any{
				"name": "fuzz-b18-rejection-create", "reason": "fuzz rejection reason",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// bulk_access_requests.go's DeleteRejectionReasonTemplate — batch 18.
		Key: "REST DELETE /api/v1/rejection-reason-templates/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/rejection-reason-templates", map[string]any{
				"name": "fuzz-b18-rejection-delete", "reason": "fuzz rejection reason",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRejectionReasonTemplate: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Template struct {
						ID uint `json:"id"`
					} `json:"template"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Template.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRejectionReasonTemplate response: %w (body=%s)", err, body)
			}
			return decoded.Data.Template.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/rejection-reason-templates/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// risk_exceptions.go's CreateRiskException — batch 18.
		Key: "REST POST /api/v1/risk-exceptions",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/risk-exceptions", map[string]any{
				"title": "fuzz-b18-risk-exception", "category": "other", "reference": "FUZZ-1",
				"justification": "fuzz justification", "expires_at": time.Now().Add(72 * time.Hour).Format(time.RFC3339),
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// risk_exceptions.go's RevokeRiskException — batch 18.
		Key: "REST DELETE /api/v1/risk-exceptions/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/risk-exceptions", map[string]any{
				"title": "fuzz-b18-risk-exception-revoke", "category": "other", "reference": "FUZZ-2",
				"justification": "fuzz justification", "expires_at": time.Now().Add(72 * time.Hour).Format(time.RFC3339),
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRiskException: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Exception struct {
						ID uint `json:"ID"`
					} `json:"exception"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Exception.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRiskException response: %w (body=%s)", err, body)
			}
			return decoded.Data.Exception.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/risk-exceptions/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// risk_exceptions.go's ApproveRiskException: dual control forbids the
		// CREATOR from approving their own exception, so Setup creates it as
		// admin, then logs in as a second, freshly created user holding a
		// global system.write role to perform the approval — batch 18.
		Key: "REST POST /api/v1/risk-exceptions/{id}/approve",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/risk-exceptions", map[string]any{
				"title": "fuzz-b18-risk-exception-approve", "category": "other", "reference": "FUZZ-3",
				"justification": "fuzz justification", "expires_at": time.Now().Add(72 * time.Hour).Format(time.RFC3339),
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRiskException: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Exception struct {
						ID uint `json:"ID"`
					} `json:"exception"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Exception.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRiskException response: %w (body=%s)", err, body)
			}
			approverID, err := createUserForFuzz(ctx, w, "fuzz-b18-risk-approver")
			if err != nil {
				return nil, err
			}
			st, body, err = httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
				"name": "fuzz-b18-syswrite-role", "description": "fuzz global admin role", "permissions": []string{"system.write"},
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRole: HTTP %d: %s", st, body)
			}
			var roleDecoded struct {
				Data struct {
					Role struct {
						ID uint `json:"id"`
					} `json:"role"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &roleDecoded); err != nil || roleDecoded.Data.Role.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRole response: %w (body=%s)", err, body)
			}
			if err := assignUserRoleForFuzz(ctx, w, approverID, roleDecoded.Data.Role.ID, 0); err != nil {
				return nil, err
			}
			token, err := loginForFuzz(ctx, w, "fuzz-b18-risk-approver", fuzzUserPassword)
			if err != nil {
				return nil, err
			}
			return [2]any{decoded.Data.Exception.ID, token}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			args := state.([2]any)
			id := args[0].(uint)
			token := args[1].(string)
			st, body, err := httpJSONAs(ctx, w, token, http.MethodPost, fmt.Sprintf("/api/v1/risk-exceptions/%d/approve", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// sod.go's CreateSoDPolicy — batch 18.
		Key: "REST POST /api/v1/sod/policies",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/sod/policies", map[string]any{
				"name": "fuzz-b18-sod-policy", "description": "fuzz sod policy",
				"permission_a": "secrets.write", "permission_b": "roles.assign",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// sod.go's DeleteSoDPolicy — batch 18.
		Key: "REST DELETE /api/v1/sod/policies/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/sod/policies", map[string]any{
				"name": "fuzz-b18-sod-policy-delete", "description": "fuzz sod policy",
				"permission_a": "secrets.write", "permission_b": "roles.assign",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateSoDPolicy: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Policy struct {
						ID uint `json:"ID"`
					} `json:"policy"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Policy.ID == 0 {
				return nil, fmt.Errorf("decoding CreateSoDPolicy response: %w (body=%s)", err, body)
			}
			return decoded.Data.Policy.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/sod/policies/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// rotation_policies_handler.go's Create + Update — batch 18.
		Key: "REST PUT /api/v1/rotation-policies/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/rotation-policies/", map[string]any{
				"name": "fuzz-b18-rotation-policy", "scope": "project", "project_id": 1, "interval_days": 30,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRotationPolicy: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRotationPolicy response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/rotation-policies/%d", id), map[string]any{
				"name": "fuzz-b18-rotation-policy-updated", "interval_days": 60,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_templates.go's Create — batch 18.
		Key: "REST POST /api/v1/secret-templates/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secret-templates/", map[string]any{
				"name": "fuzz-b18-template-create", "description": "fuzz template",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_templates.go's Update — batch 18.
		Key: "REST PUT /api/v1/secret-templates/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secret-templates/", map[string]any{
				"name": "fuzz-b18-template-update", "description": "fuzz template",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateSecretTemplate: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateSecretTemplate response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secret-templates/%d", id), map[string]any{
				"name": "fuzz-b18-template-updated", "description": "fuzz template updated",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_templates.go's Delete — batch 18.
		Key: "REST DELETE /api/v1/secret-templates/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secret-templates/", map[string]any{
				"name": "fuzz-b18-template-delete", "description": "fuzz template",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateSecretTemplate: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateSecretTemplate response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secret-templates/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// secret_templates.go's Apply (dry-run preview, read-only) — batch 18.
		Key: "REST POST /api/v1/secret-templates/{id}/apply",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secret-templates/", map[string]any{
				"name": "fuzz-b18-template-apply", "description": "fuzz template", "default_classification": "internal",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateSecretTemplate: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateSecretTemplate response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secret-templates/%d/apply", id), map[string]any{
				"description": "fuzz applied description",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// anomaly_config.go's UpdateAnomalyConfig: empty body is valid (only
		// ceiling checks, no floor checks) — batch 18.
		Key: "REST PUT /api/v1/admin/anomaly-config/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPut, "/api/v1/admin/anomaly-config/", map[string]any{})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// bulk_access_requests.go's BulkApproveAccessRequests — batch 18.
		//
		// SESSION-FI (AT5): ResolveAccessRequest's own "cannot approve their
		// own" guard (see batch 15's op above) applies here too -- Setup must
		// create the request as a non-admin user, not the admin that Execute
		// approves as, or every approval attempt fails every time (confirmed:
		// TestOpCatalog_SucceedsWithNoFaultArmed only caught this once the
		// bulk-op per-item result fix below started actually checking the
		// per-item outcome instead of trusting the HTTP envelope's
		// unconditional 200).
		Key: "REST POST /api/v1/access-requests/bulk-approve",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			if _, err := createUserForFuzz(ctx, w, "fuzz-b18-bulk-approve-requester"); err != nil {
				return nil, err
			}
			token, err := loginForFuzz(ctx, w, "fuzz-b18-bulk-approve-requester", fuzzUserPassword)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSONAs(ctx, w, token, http.MethodPost, "/api/v1/projects/1/access-requests", map[string]any{
				"suggested_role": "viewer", "reason": "fuzz bulk approve",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateAccessRequest: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					AccessRequest struct {
						ID uint `json:"id"`
					} `json:"access_request"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.AccessRequest.ID == 0 {
				return nil, fmt.Errorf("decoding CreateAccessRequest response: %w (body=%s)", err, body)
			}
			return decoded.Data.AccessRequest.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/access-requests/bulk-approve", map[string]any{
				"request_ids": []uint{id},
			})
			if err != nil {
				return opResult{}, err
			}
			// SESSION-FI (AT5): same per-item-vs-envelope gap fixed on the
			// bulk-reject sibling above — BulkApproveAccessRequests always
			// returns HTTP 200 with an {approved,failed} breakdown, so a fault
			// that correctly, safely denies THIS SINGLE requested item (lands
			// in "failed", never "approved") must not be read as Success=true.
			// Fixed proactively here (not yet independently fuzzer-triggered)
			// per "check fix siblings, not just original site."
			if st/100 == 2 {
				var parsed struct {
					Data struct {
						Result struct {
							Approved []uint `json:"approved"`
							Failed   []struct {
								RequestID uint   `json:"request_id"`
								Error     string `json:"error"`
							} `json:"failed"`
						} `json:"result"`
					} `json:"data"`
				}
				if jerr := json.Unmarshal(body, &parsed); jerr == nil && len(parsed.Data.Result.Failed) > 0 && len(parsed.Data.Result.Approved) == 0 {
					return opResult{Success: false, Detail: fmt.Sprintf("HTTP %d (bulk-approve item failed): %s", st, body)}, nil
				}
			}
			return httpResult(st, body), nil
		},
	},
	{
		// bulk_access_requests.go's BulkRejectAccessRequests — batch 18.
		Key: "REST POST /api/v1/access-requests/bulk-reject",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/access-requests", map[string]any{
				"suggested_role": "viewer", "reason": "fuzz bulk reject",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateAccessRequest: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					AccessRequest struct {
						ID uint `json:"id"`
					} `json:"access_request"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.AccessRequest.ID == 0 {
				return nil, fmt.Errorf("decoding CreateAccessRequest response: %w (body=%s)", err, body)
			}
			return decoded.Data.AccessRequest.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/access-requests/bulk-reject", map[string]any{
				"request_ids": []uint{id}, "reason": "fuzz bulk reject reason",
			})
			if err != nil {
				return opResult{}, err
			}
			// SESSION-FI (AT5): same per-item-vs-envelope gap as the
			// bulk-delete-secrets op above — BulkRejectAccessRequests always
			// returns HTTP 200 with a {rejected,failed} breakdown, even when
			// THIS SINGLE requested item correctly, safely failed (an authz-
			// resolution fault inside RejectAccessRequest denies it, landing
			// in "failed", never "rejected"). Found live by
			// FuzzStorageFaultOperations (fault=GetAccessRequest#1/error):
			// AccessRequest staying pending / no notification sent / the
			// bulk_reject_attempted audit message saying "0 rejected" are all
			// the correct, honest consequences of that one denial, not a
			// partial commit — but httpResult's status-code-only mapping read
			// the 200 envelope as Success=true regardless.
			if st/100 == 2 {
				var parsed struct {
					Data struct {
						Result struct {
							Rejected []uint `json:"rejected"`
							Failed   []struct {
								RequestID uint   `json:"request_id"`
								Error     string `json:"error"`
							} `json:"failed"`
						} `json:"result"`
					} `json:"data"`
				}
				if jerr := json.Unmarshal(body, &parsed); jerr == nil && len(parsed.Data.Result.Failed) > 0 && len(parsed.Data.Result.Rejected) == 0 {
					return opResult{Success: false, Detail: fmt.Sprintf("HTTP %d (bulk-reject item failed): %s", st, body)}, nil
				}
			}
			return httpResult(st, body), nil
		},
	},
	{
		// project_members.go's AddProjectMember (dedicated opCatalog entry —
		// addProjectMemberForFuzz already exercises this handler as a setup
		// helper elsewhere, but that isn't a registered opCatalog key) —
		// batch 19.
		Key: "REST POST /api/v1/projects/{id}/members",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b19-addmember")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			userID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/members", map[string]any{
				"user_id": userID, "role": "viewer",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's UpdateUser — batch 19.
		Key: "REST PUT /api/v1/users/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b19-update-user")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", id), map[string]any{
				"display_name": "Fuzz Updated Name",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's RestoreUser — batch 19.
		Key: "REST POST /api/v1/users/{id}/restore",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createUserForFuzz(ctx, w, "fuzz-b19-restore-user")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", id), nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup DeleteUser: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/restore", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's UnlockUser: a plain lockout-clear, no precondition
		// that the target was actually locked — batch 19.
		Key: "REST POST /api/v1/users/{id}/unlock",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b19-unlock-user")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/unlock", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's SuspendUser — batch 19.
		Key: "REST POST /api/v1/users/{id}/suspend",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b19-suspend-user")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/suspend", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's ReactivateUser: needs a suspended target — batch 19.
		Key: "REST POST /api/v1/users/{id}/reactivate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createUserForFuzz(ctx, w, "fuzz-b19-reactivate-user")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/suspend", id), nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup SuspendUser: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reactivate", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's RequirePasswordReset — batch 19.
		Key: "REST POST /api/v1/users/{id}/require-password-reset",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b19-pwreset-user")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/require-password-reset", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_crud.go's RevokeSessions — batch 19.
		Key: "REST POST /api/v1/users/{id}/revoke-sessions",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createUserForFuzz(ctx, w, "fuzz-b19-revokesess-user")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/revoke-sessions", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// groups_handler.go's UpdateGroup — batch 19.
		Key: "REST PUT /api/v1/groups/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createGroupForFuzz(ctx, w, "fuzz-b19-update-group")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/groups/%d", id), map[string]any{
				"description": "fuzz updated description",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// catalog.go's UpdateProject (REST) — batch 19.
		Key: "REST PUT /api/v1/projects/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createProjectForFuzz(ctx, w, "fuzz-b19-update-project")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/projects/%d", id), map[string]any{
				"name": "fuzz-b19-project-updated", "description": "fuzz updated",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// users_roles.go's UpdateUserRoles — batch 19.
		Key: "REST PUT /api/v1/users/{id}/roles",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			userID, err := createUserForFuzz(ctx, w, "fuzz-b19-userroles-update")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			return [2]uint{userID, roleID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/users/%d/roles", ids[0]), map[string]any{
				"role_ids": []uint{ids[1]}, "project_id": 1, "environment_id": 0,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// auth.go's Login — batch 20.
		Key: "REST POST /auth/login",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/login", map[string]any{
				"username": "faultadmin", "password": faultAdminPassword,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// auth.go's Logout — batch 20.
		Key: "REST POST /auth/logout",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/logout", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// auth.go's RefreshToken — batch 20.
		Key: "REST POST /auth/refresh",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/refresh", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// auth.go's ChangePassword — batch 20.
		Key: "REST POST /api/v1/auth/change-password",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/change-password", map[string]any{
				"current_password": faultAdminPassword, "new_password": "FuzzB20NewPassw0rd!",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// auth.go's UpdateProfile — batch 20.
		Key: "REST PUT /api/v1/auth/profile",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPut, "/api/v1/auth/profile", map[string]any{
				"display_name": "Fuzz Admin Updated", "email": "faultadmin@example.com", "current_password": faultAdminPassword,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// auth.go's RevokeSession (self-service) — batch 20.
		Key: "REST DELETE /api/v1/auth/sessions/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodGet, "/api/v1/auth/sessions", nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup ListSessions: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data []struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Data) == 0 {
				return nil, fmt.Errorf("decoding ListSessions response: %w (body=%s)", err, body)
			}
			return decoded.Data[0].ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/auth/sessions/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// pat_handler.go's CreatePAT — batch 20.
		Key: "REST POST /api/v1/auth/tokens",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/tokens", map[string]any{
				"name": "fuzz-b20-pat-create",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// pat_handler.go's RevokePAT — batch 20.
		Key: "REST DELETE /api/v1/auth/tokens/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/tokens", map[string]any{
				"name": "fuzz-b20-pat-delete",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreatePAT: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					PAT struct {
						ID uint `json:"id"`
					} `json:"pat"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.PAT.ID == 0 {
				return nil, fmt.Errorf("decoding CreatePAT response: %w (body=%s)", err, body)
			}
			return decoded.Data.PAT.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/auth/tokens/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// pat_expiry_handler.go's BulkRevokeExpiredPATs: zero expired tokens
		// is a valid, successful no-op — batch 20.
		Key: "REST DELETE /api/v1/auth/tokens/expired",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodDelete, "/api/v1/auth/tokens/expired", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// dashboard.go's SendComplianceDigest: sent=false when no channel is
		// wired is a valid, successful response, not an error — batch 21.
		Key: "REST POST /api/v1/compliance/digest/send",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/compliance/digest/send", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// dashboard.go's VerifyComplianceEvidence: always 200, the
		// verification RESULT (valid/invalid) is data, not an HTTP error —
		// batch 21.
		Key: "REST POST /api/v1/compliance/evidence/verify",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/compliance/evidence/verify", map[string]any{
				"data_b64": "ZnV6eg==", "signature": "fuzz-invalid-signature", "filename": "keyorix-evidence-20260101T000000Z.json",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// compliance_snapshots_handler.go's TakeComplianceSnapshot — batch 21.
		Key: "REST POST /api/v1/compliance/snapshots",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/compliance/snapshots", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// audit.go's MigrateAuditChainEncoding: defaults to dry_run=true, no
		// body required — batch 21.
		Key: "REST POST /api/v1/audit/migrate-chain-encoding",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/audit/migrate-chain-encoding", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// auth.go's PasswordReset: always returns success unconditionally
		// (email-enumeration protection — RequestPasswordReset's own error is
		// discarded) — batch 22.
		Key: "REST POST /auth/password-reset",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/password-reset", map[string]any{
				"email": "fuzz-b22-nonexistent@example.com",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// notifications_handler.go's MarkAllRead: a no-op batch update
		// succeeds even with zero notifications — batch 22.
		Key: "REST POST /api/v1/notifications/read-all",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/notifications/read-all", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// notifications_handler.go's MarkRead: Setup transfers a secret's
		// ownership to a fresh user, which unconditionally notifies the new
		// owner (notifySecretOwnershipTransferred) — a more reliable trigger
		// than notifyAccessRequested, which requires the recipient to be an
		// approver-role ListProjectMembers row, not just any project-scoped
		// role grant — batch 22.
		Key: "REST POST /api/v1/notifications/{id}/read",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			newOwnerID, err := createUserForFuzz(ctx, w, "fuzz-b22-notify-newowner")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
				"name": "fuzz-b22-writer-role", "description": "fuzz writer role", "permissions": []string{"secrets.write"},
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRole: HTTP %d: %s", st, body)
			}
			var roleDecoded struct {
				Data struct {
					Role struct {
						ID uint `json:"id"`
					} `json:"role"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &roleDecoded); err != nil || roleDecoded.Data.Role.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRole response: %w (body=%s)", err, body)
			}
			if err := assignUserRoleForFuzz(ctx, w, newOwnerID, roleDecoded.Data.Role.ID, 1); err != nil {
				return nil, err
			}
			st, body, err = httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/transfer-ownership", secretID), map[string]any{
				"new_owner_id": newOwnerID,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup TransferOwnership: HTTP %d: %s", st, body)
			}
			token, err := loginForFuzz(ctx, w, "fuzz-b22-notify-newowner", fuzzUserPassword)
			if err != nil {
				return nil, err
			}
			st, body, err = httpJSONAs(ctx, w, token, http.MethodGet, "/api/v1/notifications", nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup ListNotifications: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					Notifications []struct {
						ID uint `json:"id"`
					} `json:"notifications"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Data.Notifications) == 0 {
				return nil, fmt.Errorf("no notification produced by TransferOwnership (body=%s)", body)
			}
			return [2]any{decoded.Data.Notifications[0].ID, token}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			args := state.([2]any)
			id := args[0].(uint)
			token := args[1].(string)
			st, body, err := httpJSONAs(ctx, w, token, http.MethodPost, fmt.Sprintf("/api/v1/notifications/%d/read", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// alert_escalation.go's Delete — batch 23.
		Key: "REST DELETE /api/v1/alert-escalation-policies/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/alert-escalation-policies", map[string]any{
				"name": "fuzz-b23-escalation-delete", "min_severity": "low", "escalate_after_minutes": 30,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateAlertEscalationPolicy: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateAlertEscalationPolicy response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/alert-escalation-policies/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "GRPC keyorix.v1.MachineIdentityService.ClassifyMachineToken",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			machineID, err := createMachineIdentityForFuzz(ctx, w, 1)
			if err != nil {
				return nil, err
			}
			tokenID, err := issueMachineTokenForFuzz(ctx, w, 1, machineID)
			if err != nil {
				return nil, err
			}
			return [2]uint{machineID, tokenID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			ids := state.([2]uint)
			_, err := pb.NewMachineIdentityServiceClient(w.grpcConn).ClassifyMachineToken(w.grpcCtx, &pb.ClassifyMachineTokenRequest{
				ProjectId: 1, MachineId: uint32(ids[0]), TokenId: uint32(ids[1]), Classification: "internal",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9 (FAULTOPS-SPEED STEP 2, secret ACL/share/rotation
		// family — highest security value per the STEP 1 plan): secret ACL
		// grant (RBAC Phase 3, secrets.manage-gated).
		Key: "REST POST /api/v1/secrets/{id}/acl",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", s["secretID"]), map[string]any{
				"user_id": s["userID"], "permissions": []string{"secrets.read"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: secret ACL revoke. Setup grants the ACL first
		// (through the real POST), then reads it back via ListSecretACLs
		// (the grant response itself carries no ACL id — {"granted":true} —
		// so the id must come from a follow-up list call).
		Key: "REST DELETE /api/v1/secrets/{id}/acl/{aclId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-revoke-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", secretID), map[string]any{
				"user_id": userID, "permissions": []string{"secrets.read"},
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup GrantSecretACL: HTTP %d: %s", st, body)
			}
			gst, gbody, err := httpJSON(ctx, w, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", secretID), nil)
			if err != nil {
				return nil, err
			}
			if gst/100 != 2 {
				return nil, fmt.Errorf("setup ListSecretACLs: HTTP %d: %s", gst, gbody)
			}
			var decoded struct {
				Data []struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(gbody, &decoded); err != nil || len(decoded.Data) == 0 {
				return nil, fmt.Errorf("decoding ListSecretACLs response: %w (body=%s)", err, gbody)
			}
			return map[string]uint{"secretID": secretID, "aclID": decoded.Data[0].ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/acl/%d", s["secretID"], s["aclID"]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of secret ACL grant — proves the RBAC
		// Phase 3 ACL family generalizes across transports too.
		Key: "GRPC keyorix.v1.SecretService.GrantSecretACL",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-grpc-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewSecretServiceClient(w.grpcConn).GrantSecretACL(w.grpcCtx, &pb.GrantSecretACLRequest{
				SecretId: uint64(s["secretID"]), UserId: uint64(s["userID"]), Permissions: []string{"secrets.read"},
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of secret ACL revoke. Setup grants
		// via the gRPC path itself (GrantSecretACLRequest's response DOES
		// carry the new entry's id, unlike the REST grant response).
		Key: "GRPC keyorix.v1.SecretService.RevokeSecretACL",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-grpc-revoke-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			entry, err := pb.NewSecretServiceClient(w.grpcConn).GrantSecretACL(w.grpcCtx, &pb.GrantSecretACLRequest{
				SecretId: uint64(secretID), UserId: uint64(userID), Permissions: []string{"secrets.read"},
			})
			if err != nil {
				return nil, fmt.Errorf("setup GrantSecretACL (grpc): %w", err)
			}
			return map[string]uint64{"secretID": uint64(secretID), "aclID": entry.GetId()}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint64)
			_, err := pb.NewSecretServiceClient(w.grpcConn).RevokeSecretACL(w.grpcCtx, &pb.RevokeSecretACLRequest{
				SecretId: s["secretID"], AclId: s["aclID"],
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: auto-rotate toggle — enables Keyorix-managed
		// rotation (backend="" = regenerate in Keyorix only, ADR-047), no
		// external rotation backend config needed.
		Key: "REST PATCH /api/v1/secrets/{id}/auto-rotate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/auto-rotate", id), map[string]any{
				"enabled": true,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of auto-rotate toggle.
		Key: "GRPC keyorix.v1.SecretService.SetSecretAutoRotate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewSecretServiceClient(w.grpcConn).SetSecretAutoRotate(w.grpcCtx, &pb.SetSecretAutoRotateRequest{
				Id: uint32(id), Enabled: true,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: secret rotate-on-demand — RotateSecretOnDemand
		// (#193), which also rotates any bound upstream credential.
		Key: "REST POST /api/v1/secrets/{id}/rotate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), map[string]any{
				"new_value": "fuzz-rotated-value",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: secret rollback. Setup rotates once first (a
		// fresh secret's only version IS its current one — RollbackSecret
		// rejects "already the current version" — so a second version must
		// exist before Execute can roll back to version 1).
		Key: "REST POST /api/v1/secrets/{id}/rollback",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), map[string]any{
				"new_value": "fuzz-rollback-setup-rotated",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup RotateSecret: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rollback", id), map[string]any{
				"version": 1,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: share a secret with another project member. The
		// admin (bootstrap creator) is the secret's owner, so ShareSecret's
		// owner gate passes; the recipient must independently be a live
		// project member (a distinct check from the owner gate).
		Key: "REST POST /api/v1/secrets/{id}/share",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", s["secretID"]), map[string]any{
				"recipient_id": s["userID"], "permission": "read",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: update an existing share's permission/expiry.
		// Setup creates the share first through the real POST, then decodes
		// its id from the response (shareRecordWire.ID, "id").
		Key: "REST PUT /api/v1/shares/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-update-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secretID), map[string]any{
				"recipient_id": userID, "permission": "read",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup ShareSecret: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding ShareSecret response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/shares/%d", id), map[string]any{
				"permission": "write",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: revoke a share. Same setup shape as the update
		// path above, distinct share so the two operations never race a
		// shared row within one iteration.
		Key: "REST DELETE /api/v1/shares/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-revoke-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secretID), map[string]any{
				"recipient_id": userID, "permission": "read",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup ShareSecret: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding ShareSecret response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of secret share. ShareSecretRequest's
		// response (ShareRecord) carries its own id directly, unlike the ACL
		// grant's REST response.
		Key: "GRPC keyorix.v1.ShareService.ShareSecret",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-grpc-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewShareServiceClient(w.grpcConn).ShareSecret(w.grpcCtx, &pb.ShareSecretRequest{
				SecretId: uint32(s["secretID"]), RecipientId: uint32(s["userID"]), Permission: "read",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of share update. Setup shares via
		// the gRPC path itself so the returned ShareRecord.Id is used
		// directly (no REST decode needed).
		Key: "GRPC keyorix.v1.ShareService.UpdateSharePermission",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-grpc-update-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			rec, err := pb.NewShareServiceClient(w.grpcConn).ShareSecret(w.grpcCtx, &pb.ShareSecretRequest{
				SecretId: uint32(secretID), RecipientId: uint32(userID), Permission: "read",
			})
			if err != nil {
				return nil, fmt.Errorf("setup ShareSecret (grpc): %w", err)
			}
			return rec.GetId(), nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			shareID := state.(uint32)
			_, err := pb.NewShareServiceClient(w.grpcConn).UpdateSharePermission(w.grpcCtx, &pb.UpdateSharePermissionRequest{
				ShareId: shareID, Permission: "write",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of share revoke.
		Key: "GRPC keyorix.v1.ShareService.RevokeShare",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-grpc-revoke-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			rec, err := pb.NewShareServiceClient(w.grpcConn).ShareSecret(w.grpcCtx, &pb.ShareSecretRequest{
				SecretId: uint32(secretID), RecipientId: uint32(userID), Permission: "read",
			})
			if err != nil {
				return nil, fmt.Errorf("setup ShareSecret (grpc): %w", err)
			}
			return rec.GetId(), nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			shareID := state.(uint32)
			_, err := pb.NewShareServiceClient(w.grpcConn).RevokeShare(w.grpcCtx, &pb.RevokeShareRequest{
				ShareId: shareID,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 24 (Session C item C2, FAULTOPS-SPEED STEP 3 PR B):
		// self-service break-glass activation, the REST route + its 2 gRPC
		// siblings — the "break-glass policy" fixture PR A (#2196) wired
		// (SetBreakGlassPolicy, world_test.go) left these 3 unreachable until
		// something actually called ActivateBreakGlass; the REST revoke sibling
		// was already wired (batch 7). core.ActivateBreakGlass requires the
		// caller to be an existing project member (IsProjectMember, any role,
		// this project scope) — Setup grants the admin (userID 1, the bearer
		// this world's REST/gRPC calls authenticate as) exactly that, mirroring
		// world_fixture_test.go's own TestWorldFixture_BreakGlass proof that this
		// exact shape satisfies ActivateBreakGlass end-to-end.
		Key: "REST POST /api/v1/projects/{id}/break-glass",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			pStatus, pBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-bg-activate-project"})
			if err != nil {
				return nil, err
			}
			if pStatus/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", pStatus, pBody)
			}
			var proj struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(pBody, &proj); err != nil || proj.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, pBody)
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := w.faulty.AssignRole(ctx, 1, roleID, coreStorage.Scope{ProjectID: proj.Data.ID}); err != nil {
				return nil, fmt.Errorf("setup AssignRole (admin membership): %w", err)
			}
			return proj.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			projID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/break-glass", projID), map[string]any{
				"justification": "fuzz break-glass activation — batch 24",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "GRPC keyorix.v1.BreakGlassService.ActivateBreakGlass",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			pStatus, pBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-bg-activate-grpc-project"})
			if err != nil {
				return nil, err
			}
			if pStatus/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", pStatus, pBody)
			}
			var proj struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(pBody, &proj); err != nil || proj.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, pBody)
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := w.faulty.AssignRole(ctx, 1, roleID, coreStorage.Scope{ProjectID: proj.Data.ID}); err != nil {
				return nil, fmt.Errorf("setup AssignRole (admin membership): %w", err)
			}
			return proj.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			projID := state.(uint)
			_, err := pb.NewBreakGlassServiceClient(w.grpcConn).ActivateBreakGlass(w.grpcCtx, &pb.ActivateBreakGlassRequest{
				ProjectId: uint32(projID), Justification: "fuzz break-glass activation grpc — batch 24",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// gRPC RevokeBreakGlass sibling of the already-wired REST revoke
		// (batch 7) — identical Setup shape (a real, pre-existing activation
		// via the storage-level w.faulty helper, matching batch 7's own
		// precedent for this exact operation family), driven over gRPC instead
		// of REST to prove the harness generalizes across transports here too.
		Key: "GRPC keyorix.v1.BreakGlassService.RevokeBreakGlass",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			pStatus, pBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-bg-revoke-grpc-project"})
			if err != nil {
				return nil, err
			}
			if pStatus/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", pStatus, pBody)
			}
			var proj struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(pBody, &proj); err != nil || proj.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, pBody)
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-bg-revoke-grpc-user")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := w.faulty.AssignRole(ctx, userID, roleID, coreStorage.Scope{ProjectID: proj.Data.ID}); err != nil {
				return nil, fmt.Errorf("setup AssignRole: %w", err)
			}
			activation, err := w.faulty.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
				ProjectID:     proj.Data.ID,
				UserID:        userID,
				RoleID:        roleID,
				RoleName:      "fuzz-role",
				Justification: "fuzz break-glass grpc revoke path — batch 24",
				State:         core.BreakGlassActive,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateBreakGlassActivation: %w", err)
			}
			return map[string]uint{"projectID": proj.Data.ID, "activationID": activation.ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewBreakGlassServiceClient(w.grpcConn).RevokeBreakGlass(w.grpcCtx, &pb.RevokeBreakGlassRequest{
				ProjectId: uint32(s["projectID"]), ActivationId: uint32(s["activationID"]),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 25 (Session C item C2, FAULTOPS-SPEED STEP 3 PR B):
		// self-service TOTP MFA lifecycle, unblocked by PR A's (#2196) lazy
		// encryption fixture — BeginMFAEnrollment fails closed with
		// "MFA enrolment requires at-rest encryption" whenever
		// authEncryptor is nil/disabled (internal/core/mfa.go), which every
		// world was before ensureEncryption() existed to turn it on.
		Key: "REST POST /api/v1/auth/mfa/enroll",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			if err := w.ensureEncryption(); err != nil {
				return nil, fmt.Errorf("setup ensureEncryption: %w", err)
			}
			return nil, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/auth/mfa/activate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			if err := w.ensureEncryption(); err != nil {
				return nil, fmt.Errorf("setup ensureEncryption: %w", err)
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup EnrollMFA: HTTP %d: %s", st, body)
			}
			var enrolled struct {
				Data struct {
					Secret string `json:"secret"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &enrolled); err != nil || enrolled.Data.Secret == "" {
				return nil, fmt.Errorf("decoding EnrollMFA response: %w (body=%s)", err, body)
			}
			return enrolled.Data.Secret, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			secret := state.(string)
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				return opResult{}, fmt.Errorf("totp.GenerateCode: %w", err)
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/mfa/activate", map[string]any{
				"code": code, "password": faultAdminPassword,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 26 (Session FI, AT5): disable/recovery-regenerate/stepup/
		// verify were left StatusPending after batch 25 found requireReauth's
		// MarkTOTPStepUsed watermark makes a SECOND TOTP proof impossible within
		// one iteration if the first was spent going through the real HTTP
		// enroll+activate round trip (activate's own code consumes step 0).
		// Unblocked here by NOT calling /activate at all: enrolMFADirect enrols
		// via the real HTTP endpoint (so the secret is genuinely encrypted by
		// BeginMFAEnrollment, same as every other MFA op) but flips
		// Activated/MFAEnabled directly in storage instead of spending a TOTP
		// step through /activate — so step 0 is still completely unspent when
		// Execute generates its own code for THIS op, exactly mirroring how a
		// real account that enabled MFA in a previous, unrelated session would
		// present to any of these four routes.
		Key: "REST POST /api/v1/auth/mfa/disable",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return enrolMFADirect(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			secret := state.(string)
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				return opResult{}, fmt.Errorf("totp.GenerateCode: %w", err)
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/mfa/disable", map[string]any{"code": code})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/auth/mfa/recovery-codes/regenerate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return enrolMFADirect(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			secret := state.(string)
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				return opResult{}, fmt.Errorf("totp.GenerateCode: %w", err)
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate", map[string]any{"code": code})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/auth/mfa/stepup",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return enrolMFADirect(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			secret := state.(string)
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				return opResult{}, fmt.Errorf("totp.GenerateCode: %w", err)
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/mfa/stepup", map[string]any{"code": code})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// REST POST /auth/mfa/verify is the LOGIN-time second factor (distinct
		// from the three reauth routes above): it needs a live MFAChallenge, not
		// an authenticated bearer token, so Setup mints one directly via the core
		// API (an exported call, same trust level as Setup's other direct-storage
		// shortcuts -- this is prerequisite state, not the operation under test).
		Key: "REST POST /auth/mfa/verify",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secret, err := enrolMFADirect(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := faultAdminUserID(w)
			if err != nil {
				return nil, fmt.Errorf("setup faultAdminUserID: %w", err)
			}
			challenge, err := w.core.CreateMFAChallenge(ctx, userID)
			if err != nil {
				return nil, fmt.Errorf("setup CreateMFAChallenge: %w", err)
			}
			return [2]string{secret.(string), challenge}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			st2 := state.([2]string)
			code, err := totp.GenerateCode(st2[0], time.Now())
			if err != nil {
				return opResult{}, fmt.Errorf("totp.GenerateCode: %w", err)
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/mfa/verify", map[string]any{
				"mfa_challenge": st2[1], "code": code,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// E3 dynamic-secrets batch: register a new target (ADR-035). Backend
		// "postgres" + dynamicSecretFuzzAdminDSN — see that constant's doc
		// comment for why (no live external DB in this in-process harness).
		Key: "REST POST /api/v1/dynamic-secrets/configs",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			wireFakeDynamicSecretEngineForFuzz(w)
			return nil, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/dynamic-secrets/configs", map[string]any{
				"name": "fuzz-dynsec-create", "project_id": 1, "environment_id": 1,
				"backend_type": "postgres", "admin_dsn": dynamicSecretFuzzAdminDSN,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST PATCH /api/v1/dynamic-secrets/configs/{id}/classification",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-classify")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			cfgID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/classification", cfgID), map[string]any{
				"classification": "confidential",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// #369: manual enable/disable, independent of DeleteProject's cascade.
		Key: "REST PATCH /api/v1/dynamic-secrets/configs/{id}/enabled",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-enabled")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			cfgID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/enabled", cfgID), map[string]any{
				"enabled": false,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Always fails at the dial (dynamicSecretFuzzAdminDSN, unreachable by
		// design) — still real coverage: exercises the real transport, the
		// real config lookup/disabled/live-project checks, and the real
		// active-lease-ceiling check, all of which run BEFORE the dial and are
		// all real fault-injection surface.
		Key: "REST POST /api/v1/dynamic-secrets/configs/{id}/issue",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-issue")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			cfgID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/issue", cfgID), map[string]any{
				"ttl_seconds": 60,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Incident kill switch (RevokeLeasesForConfig): one active lease,
		// issued for real (see issueDynamicSecretLeaseForFuzz).
		Key: "REST POST /api/v1/dynamic-secrets/configs/{id}/revoke-all",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			cfgID, err := createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-revokeall")
			if err != nil {
				return nil, err
			}
			if _, err := issueDynamicSecretLeaseForFuzz(ctx, w, cfgID); err != nil {
				return nil, fmt.Errorf("setup issueDynamicSecretLeaseForFuzz: %w", err)
			}
			return cfgID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			cfgID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/revoke-all", cfgID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/dynamic-secrets/leases/{leaseID}/renew",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			cfgID, err := createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-renew")
			if err != nil {
				return nil, err
			}
			leaseID, err := issueDynamicSecretLeaseForFuzz(ctx, w, cfgID)
			if err != nil {
				return nil, fmt.Errorf("setup issueDynamicSecretLeaseForFuzz: %w", err)
			}
			return leaseID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			leaseID := state.(string)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/dynamic-secrets/leases/%s/renew", leaseID), map[string]any{
				"ttl_seconds": 60,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			cfgID, err := createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-revoke")
			if err != nil {
				return nil, err
			}
			leaseID, err := issueDynamicSecretLeaseForFuzz(ctx, w, cfgID)
			if err != nil {
				return nil, fmt.Errorf("setup issueDynamicSecretLeaseForFuzz: %w", err)
			}
			return leaseID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			leaseID := state.(string)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/dynamic-secrets/leases/%s/revoke", leaseID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// gRPC sibling of REST CreateConfig — proves the dynamic-secrets
		// family generalizes across transports too, matching this file's
		// convention (e.g. batch 9/10's ACL and CRUD gRPC siblings).
		Key: "GRPC keyorix.v1.DynamicSecretService.CreateConfig",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			wireFakeDynamicSecretEngineForFuzz(w)
			return nil, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			_, err := pb.NewDynamicSecretServiceClient(w.grpcConn).CreateConfig(w.grpcCtx, &pb.CreateDynamicConfigRequest{
				Name: "fuzz-dynsec-create-grpc", ProjectId: 1, EnvironmentId: 1,
				BackendType: "postgres", AdminDsn: dynamicSecretFuzzAdminDSN,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.DynamicSecretService.ClassifyConfig",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-classify-grpc")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			cfgID := state.(uint)
			_, err := pb.NewDynamicSecretServiceClient(w.grpcConn).ClassifyConfig(w.grpcCtx, &pb.ClassifyDynamicConfigRequest{
				Id: uint32(cfgID), Classification: "confidential",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.DynamicSecretService.IssueLease",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-issue-grpc")
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			cfgID := state.(uint)
			_, err := pb.NewDynamicSecretServiceClient(w.grpcConn).IssueLease(w.grpcCtx, &pb.IssueLeaseRequest{
				ConfigId: uint32(cfgID), TtlSeconds: 60,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.DynamicSecretService.RenewLease",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			cfgID, err := createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-renew-grpc")
			if err != nil {
				return nil, err
			}
			leaseID, err := issueDynamicSecretLeaseForFuzz(ctx, w, cfgID)
			if err != nil {
				return nil, fmt.Errorf("setup issueDynamicSecretLeaseForFuzz: %w", err)
			}
			return leaseID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			leaseID := state.(string)
			_, err := pb.NewDynamicSecretServiceClient(w.grpcConn).RenewLease(w.grpcCtx, &pb.RenewLeaseRequest{
				LeaseId: leaseID, TtlSeconds: 60,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.DynamicSecretService.RevokeLease",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			cfgID, err := createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-revoke-grpc")
			if err != nil {
				return nil, err
			}
			leaseID, err := issueDynamicSecretLeaseForFuzz(ctx, w, cfgID)
			if err != nil {
				return nil, fmt.Errorf("setup issueDynamicSecretLeaseForFuzz: %w", err)
			}
			return leaseID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			leaseID := state.(string)
			_, err := pb.NewDynamicSecretServiceClient(w.grpcConn).RevokeLease(w.grpcCtx, &pb.RevokeLeaseRequest{
				LeaseId: leaseID,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.DynamicSecretService.RevokeAllLeases",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			cfgID, err := createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-revokeall-grpc")
			if err != nil {
				return nil, err
			}
			if _, err := issueDynamicSecretLeaseForFuzz(ctx, w, cfgID); err != nil {
				return nil, fmt.Errorf("setup issueDynamicSecretLeaseForFuzz: %w", err)
			}
			return cfgID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			cfgID := state.(uint)
			_, err := pb.NewDynamicSecretServiceClient(w.grpcConn).RevokeAllLeases(w.grpcCtx, &pb.RevokeAllLeasesRequest{
				ConfigId: uint32(cfgID),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
}

// runOp runs op.Setup (if any) then op.Execute against w, with no fault
// arming of its own — used by the fault-free smoke test, and as the shape the
// fuzz harness's own two-phase (Setup unfaulted / Execute faulted) run mirrors.
func runOp(ctx context.Context, w *faultWorld, op operation) (opResult, error) {
	var state any
	if op.Setup != nil {
		var err error
		state, err = op.Setup(ctx, w)
		if err != nil {
			return opResult{}, fmt.Errorf("setup: %w", err)
		}
	}
	return op.Execute(ctx, w, state)
}

// TestOperationCatalogKeysAreRegistered fails if opCatalog references a key the
// live route/method inventory no longer has — a rename or removal upstream
// would otherwise leave a Setup/Execute pair silently dispatching to a dead route.
func TestOperationCatalogKeysAreRegistered(t *testing.T) {
	inCatalog := make(map[string]bool, len(opCatalog))
	for _, op := range opCatalog {
		inCatalog[op.Key] = true
		if !knownOperations[op.Key] {
			t.Errorf("opCatalog references %q, which is not in the live operation inventory (rename/removal upstream?)", op.Key)
		}
		if statusOf(op.Key).Status != StatusFuzzed {
			t.Errorf("opCatalog references %q, but inventory_overrides_test.go does not mark it StatusFuzzed", op.Key)
		}
	}
	// The reverse direction: a key marked StatusFuzzed with no matching
	// opCatalog entry would claim coverage the harness doesn't actually drive.
	for key, e := range operationOverrides {
		if e.Status == StatusFuzzed && !inCatalog[key] {
			t.Errorf("inventory_overrides_test.go marks %q StatusFuzzed, but opCatalog has no entry for it", key)
		}
	}
}
