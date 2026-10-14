// mixed_principal_authority_fuzz_test.go -- FUZZ-MECH M1: random (principal,
// operation, target-project) triples against the LIVE (non-/system) REST
// surface, checked against an independent reference authorization model.
//
// The model is built from THREE documented-policy sources, never by calling
// core.Authorize or reading its branches (a model that calls the code under
// test proves nothing):
//  1. server/http/router.go's own declarative permission gates --
//     RequirePermission/RequireScopedPermission/BlockWhenImpersonating wired
//     directly onto each route. This is the access-control CONFIGURATION, not
//     the implementation logic that enforces it -- reading it is exactly as
//     legitimate as reading an RBAC policy file would be.
//  2. internal/core/auth_bootstrap.go's canonical permission/role catalog
//     (defaultPermissions, editorPermissions/viewerPermissions, and
//     adminRoleNames' 4 magic admin-tier role names that bypass every
//     permission check unconditionally).
//  3. RequireGranterHoldsRolePermissions's and the last-global-admin guard's
//     own documented contracts (cited by name, not by tracing their bodies):
//     a granter must already hold every permission a role it assigns
//     bundles, and no action may leave the system with zero admin-tier users.
//
// v1 scope, stated honestly (same "partial, tracked" shape as opCatalog's own
// 19-of-309, not a claim of full coverage over the live surface's ~250
// routes): 6 principal classes x 12 operations, each (principal, op,
// targetProject) triple independently classified DENY / not-asserted by
// modelVerdict. This harness only ever asserts the DENY direction
// (EFFECT-WITHOUT-AUTHORITY) -- "not asserted" covers both a genuine ALLOW
// and any case this v1 model isn't confident about, per "assert only the
// direction that cannot false-positive."
//
// Explicitly out of v1 scope, and why:
//   - PAT scope-restriction (ADR-042): a narrowed (non-empty) PAT's
//     scope-string grammar wasn't independently confirmed from docs alone
//     within this session; modeling it wrong risks exactly the
//     false-positive failure mode this rule exists to prevent.
//   - Break-glass activation: requires project-level policy configuration
//     this fuzz world doesn't set up (see opCatalog's own comment on why its
//     break-glass Setup uses a storage shortcut rather than the real route).
//   - The ~230 live routes not in the 12-op set below: tracked by
//     TestMixedPrincipalAuthorityCoverage as pending, not silently claimed.
//
// Gate: PR #2171 (ADR-108 Phase 6 step 14c-1) deleted the /system proxy tier;
// this harness targets ONLY the live, human-facing routes that survive that
// deletion -- nothing here depends on the deleted /system fixtures.
package faultops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

// ---- principal classes ----

type principalKind int

const (
	principalGlobalAdmin principalKind = iota
	principalUsersWriteOnly
	principalRolesAssignOnly
	principalProjectEditorA
	principalMachineEditorA
	principalImpersonatedUsersWriteOnly
	numPrincipalKinds
)

func (k principalKind) String() string {
	switch k {
	case principalGlobalAdmin:
		return "globalAdmin"
	case principalUsersWriteOnly:
		return "usersWriteOnly(custom,global)"
	case principalRolesAssignOnly:
		return "rolesAssignOnly(custom,global)"
	case principalProjectEditorA:
		return "editor@projectA"
	case principalMachineEditorA:
		return "machine-editor@projectA"
	case principalImpersonatedUsersWriteOnly:
		return "impersonated(usersWriteOnly)"
	default:
		return "unknown"
	}
}

// grant is one (permission, scope) pair the model treats as held by a
// principal -- ground truth because THIS HARNESS configured it via a real
// CreateRole+AssignRole/GrantMachineRole call, not derived by asking the
// server what it thinks the principal holds.
type grant struct {
	permission string
	scope      core.Scope // {0,0} = global
}

// principalFixture is one fuzzed-in principal for this iteration.
type principalFixture struct {
	kind            principalKind
	token           string
	grants          []grant
	isAdminTier     bool // one of authz.go's 4 admin-tier role names (unconditional bypass)
	isImpersonation bool
}

// holds reports whether p's ground-truth grants satisfy permission at scope,
// applying the same "global grant covers everything, project grant covers
// every environment under it" widening storage.Scope's own doc comment
// describes.
func (p principalFixture) holds(permission string, scope core.Scope) bool {
	if p.isAdminTier {
		return true
	}
	for _, g := range p.grants {
		if g.permission != permission {
			continue
		}
		if g.scope.ProjectID == 0 {
			return true
		}
		if g.scope.ProjectID == scope.ProjectID && (g.scope.EnvironmentID == 0 || g.scope.EnvironmentID == scope.EnvironmentID) {
			return true
		}
	}
	return false
}

// ---- shared world scaffolding ----

// m1World holds the admin-created scaffolding every op's Setup/Execute uses:
// two real projects (so "the principal's own project" vs "a DIFFERENT
// project" is a genuine, meaningful fuzzed choice), the seeded viewer role's
// id+permissions (used as "the role being granted" for the granter-ceiling
// op), and a disposable target user role-grant ops act on.
type m1World struct {
	adminUserID           uint
	projectA, projectB    uint
	envA, envB            uint
	viewerRoleID          uint
	viewerRolePermissions []string
	throwawayUserID       uint
}

func m1ProjectID(mw *m1World, targetProject uint) uint {
	if targetProject == 0 {
		return mw.projectA
	}
	return mw.projectB
}

func m1EnvID(mw *m1World, targetProject uint) uint {
	if targetProject == 0 {
		return mw.envA
	}
	return mw.envB
}

// m1HTTPJSONAs mirrors opcatalog_test.go's httpJSON exactly, except the
// bearer token is an explicit parameter instead of hardcoded to
// w.adminToken -- httpJSON itself is FAULTOPS-SPEED-owned (opcatalog_test.go)
// and always authenticates as the world's bootstrap admin, so this file adds
// its own helper rather than editing that one.
func m1HTTPJSONAs(ctx context.Context, w *faultWorld, token, method, path string, body any) (int, []byte, error) {
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

func m1CreateProjectAndEnv(ctx context.Context, w *faultWorld, name string) (uint, uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": name})
	if err != nil {
		return 0, 0, err
	}
	if st/100 != 2 {
		return 0, 0, fmt.Errorf("CreateProject(%s): HTTP %d: %s", name, st, body)
	}
	var proj struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &proj); err != nil || proj.Data.ID == 0 {
		return 0, 0, fmt.Errorf("decoding CreateProject(%s): %w (body=%s)", name, err, body)
	}
	st, body, err = httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments", proj.Data.ID),
		map[string]any{"name": name + "-env"})
	if err != nil {
		return 0, 0, err
	}
	if st/100 != 2 {
		return 0, 0, fmt.Errorf("CreateProjectEnvironment(%s): HTTP %d: %s", name, st, body)
	}
	var env struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Data.ID == 0 {
		return 0, 0, fmt.Errorf("decoding CreateProjectEnvironment(%s): %w (body=%s)", name, err, body)
	}
	return proj.Data.ID, env.Data.ID, nil
}

// m1CreateRoleWithPermissions creates a role with an exact, caller-chosen
// permission set -- createRoleForFuzz (opcatalog_test.go) hardcodes
// ["secrets.read"] and isn't reusable for this file's custom-permission
// principals -- and returns its id.
func m1CreateRoleWithPermissions(ctx context.Context, w *faultWorld, name string, perms []string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
		"name": name, "description": "fuzz m1 role " + name, "permissions": perms,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("CreateRole(%s): HTTP %d: %s", name, st, body)
	}
	var decoded struct {
		Data struct {
			Role struct {
				ID uint `json:"id"`
			} `json:"role"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Role.ID == 0 {
		return 0, fmt.Errorf("decoding CreateRole(%s): %w (body=%s)", name, err, body)
	}
	return decoded.Data.Role.ID, nil
}

func m1AssignRole(ctx context.Context, w *faultWorld, userID, roleID, projectID, envID uint) error {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/user-roles/", map[string]any{
		"user_id": userID, "role_id": roleID, "project_id": projectID, "environment_id": envID,
	})
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("AssignRole(user=%d,role=%d,proj=%d,env=%d): HTTP %d: %s", userID, roleID, projectID, envID, st, body)
	}
	return nil
}

func m1LoginAs(ctx context.Context, w *faultWorld, username string) (string, error) {
	session, _, err := w.core.Login(ctx, &core.LoginRequest{Username: username, Password: fuzzUserPassword})
	if err != nil {
		return "", fmt.Errorf("Login(%s): %w", username, err)
	}
	return session.SessionToken, nil
}

// buildM1World seeds the two projects, fetches the seeded viewer role, and
// creates one disposable target user -- shared scaffolding every principal
// and op below reuses.
func buildM1World(ctx context.Context, w *faultWorld) (*m1World, error) {
	admin, err := w.faulty.GetUserByUsername(ctx, "faultadmin")
	if err != nil {
		return nil, fmt.Errorf("GetUserByUsername(faultadmin): %w", err)
	}
	pA, eA, err := m1CreateProjectAndEnv(ctx, w, "fuzz-m1-a")
	if err != nil {
		return nil, err
	}
	pB, eB, err := m1CreateProjectAndEnv(ctx, w, "fuzz-m1-b")
	if err != nil {
		return nil, err
	}
	viewerRole, err := w.faulty.GetRoleByName(ctx, "viewer")
	if err != nil {
		return nil, fmt.Errorf("GetRoleByName(viewer): %w", err)
	}
	perms, err := w.faulty.GetRolePermissions(ctx, viewerRole.ID)
	if err != nil {
		return nil, fmt.Errorf("GetRolePermissions(viewer): %w", err)
	}
	var permNames []string
	for _, p := range perms {
		permNames = append(permNames, p.Name)
	}
	targetUserID, err := createUserForFuzz(ctx, w, "fuzz-m1-throwaway")
	if err != nil {
		return nil, err
	}
	return &m1World{
		adminUserID: admin.ID, projectA: pA, projectB: pB, envA: eA, envB: eB,
		viewerRoleID: viewerRole.ID, viewerRolePermissions: permNames,
		throwawayUserID: targetUserID,
	}, nil
}

// buildM1Principals creates and authenticates every principal class this
// harness fuzzes over, in the SAME world buildM1World just scaffolded.
func buildM1Principals(ctx context.Context, w *faultWorld, mw *m1World) ([]principalFixture, error) {
	admin := principalFixture{kind: principalGlobalAdmin, token: w.adminToken, isAdminTier: true}

	uwoUserID, err := createUserForFuzz(ctx, w, "fuzz-m1-uwo")
	if err != nil {
		return nil, err
	}
	uwoRoleID, err := m1CreateRoleWithPermissions(ctx, w, "fuzz-m1-role-uwo", []string{"users.write", "users.read"})
	if err != nil {
		return nil, err
	}
	if err := m1AssignRole(ctx, w, uwoUserID, uwoRoleID, 0, 0); err != nil {
		return nil, err
	}
	uwoToken, err := m1LoginAs(ctx, w, "fuzz-m1-uwo")
	if err != nil {
		return nil, err
	}
	uwoGrants := []grant{{"users.write", core.Scope{}}, {"users.read", core.Scope{}}}
	usersWriteOnly := principalFixture{kind: principalUsersWriteOnly, token: uwoToken, grants: uwoGrants}

	raoUserID, err := createUserForFuzz(ctx, w, "fuzz-m1-rao")
	if err != nil {
		return nil, err
	}
	raoRoleID, err := m1CreateRoleWithPermissions(ctx, w, "fuzz-m1-role-rao", []string{"roles.assign", "roles.read"})
	if err != nil {
		return nil, err
	}
	if err := m1AssignRole(ctx, w, raoUserID, raoRoleID, 0, 0); err != nil {
		return nil, err
	}
	raoToken, err := m1LoginAs(ctx, w, "fuzz-m1-rao")
	if err != nil {
		return nil, err
	}
	rolesAssignOnly := principalFixture{kind: principalRolesAssignOnly, token: raoToken,
		grants: []grant{{"roles.assign", core.Scope{}}, {"roles.read", core.Scope{}}}}

	edUserID, err := createUserForFuzz(ctx, w, "fuzz-m1-edA")
	if err != nil {
		return nil, err
	}
	editorRole, err := w.faulty.GetRoleByName(ctx, "editor")
	if err != nil {
		return nil, fmt.Errorf("GetRoleByName(editor): %w", err)
	}
	if err := m1AssignRole(ctx, w, edUserID, editorRole.ID, mw.projectA, 0); err != nil {
		return nil, err
	}
	edToken, err := m1LoginAs(ctx, w, "fuzz-m1-edA")
	if err != nil {
		return nil, err
	}
	editorPerms, err := w.faulty.GetRolePermissions(ctx, editorRole.ID)
	if err != nil {
		return nil, fmt.Errorf("GetRolePermissions(editor): %w", err)
	}
	var edGrants []grant
	for _, p := range editorPerms {
		edGrants = append(edGrants, grant{p.Name, core.Scope{ProjectID: mw.projectA}})
	}
	projectEditorA := principalFixture{kind: principalProjectEditorA, token: edToken, grants: edGrants}

	machineID, err := m1CreateMachineIdentity(ctx, w, mw.projectA, "fuzz-m1-machine-editor")
	if err != nil {
		return nil, err
	}
	if err := m1GrantMachineRole(ctx, w, mw.projectA, machineID, editorRole.ID); err != nil {
		return nil, err
	}
	machineToken, err := m1IssueMachineToken(ctx, w, mw.projectA, machineID, "fuzz-m1-machine-tok")
	if err != nil {
		return nil, err
	}
	machineEditorA := principalFixture{kind: principalMachineEditorA, token: machineToken, grants: edGrants}

	impSession, _, err := w.core.StartImpersonation(ctx, mw.adminUserID, uwoUserID, "127.0.0.1")
	if err != nil {
		return nil, fmt.Errorf("StartImpersonation: %w", err)
	}
	impersonated := principalFixture{
		kind: principalImpersonatedUsersWriteOnly, token: impSession.SessionToken,
		grants: uwoGrants, isImpersonation: true,
	}

	return []principalFixture{admin, usersWriteOnly, rolesAssignOnly, projectEditorA, machineEditorA, impersonated}, nil
}

func m1CreateMachineIdentity(ctx context.Context, w *faultWorld, projectID uint, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID),
		map[string]any{"name": name, "identity_type": "service"})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("CreateMachineIdentity(%s): HTTP %d: %s", name, st, body)
	}
	var decoded struct {
		Data struct {
			MachineIdentity struct {
				ID uint `json:"id"`
			} `json:"machine_identity"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.MachineIdentity.ID == 0 {
		return 0, fmt.Errorf("decoding CreateMachineIdentity(%s): %w (body=%s)", name, err, body)
	}
	return decoded.Data.MachineIdentity.ID, nil
}

func m1GrantMachineRole(ctx context.Context, w *faultWorld, projectID, machineID, roleID uint) error {
	st, body, err := httpJSON(ctx, w, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/roles", projectID, machineID),
		map[string]any{"role_id": roleID})
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("GrantMachineRole: HTTP %d: %s", st, body)
	}
	return nil
}

func m1IssueMachineToken(ctx context.Context, w *faultWorld, projectID, machineID uint, name string) (string, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", projectID, machineID),
		map[string]any{"name": name})
	if err != nil {
		return "", err
	}
	if st/100 != 2 {
		return "", fmt.Errorf("IssueMachineToken: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.Token == "" {
		return "", fmt.Errorf("decoding IssueMachineToken: %w (body=%s)", err, body)
	}
	return decoded.Data.Token, nil
}

// ---- operation catalog ----

type m1Op struct {
	key                      string
	permission               string // "" = self-service, no permission gate at all
	blockedWhenImpersonating bool
	targetsSoleGlobalAdmin   bool // Suspend/DeleteUser acting on the world's one admin-tier user
	// grantedRolePermissionsFn is non-nil for a role-grant op (the
	// granter-ceiling check): it returns the permission set of the role
	// being granted. A func, not a []string, because the granted role
	// (mw.viewerRoleID's permissions) only exists once the world is built,
	// after m1Ops (a package var) is constructed.
	grantedRolePermissionsFn func(mw *m1World) []string
	modelScope               func(mw *m1World, tp uint) core.Scope
	setup                    func(ctx context.Context, w *faultWorld, mw *m1World, tp uint) (any, error)
	execute                  func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, state any) (opResult, error)
}

func (op m1Op) grantedRolePermissionsOf(mw *m1World) []string {
	if op.grantedRolePermissionsFn == nil {
		return nil
	}
	return op.grantedRolePermissionsFn(mw)
}

func m1ScopeForProject(mw *m1World, tp uint) core.Scope {
	return core.Scope{ProjectID: m1ProjectID(mw, tp)}
}
func m1ScopeGlobal(_ *m1World, _ uint) core.Scope { return core.Scope{} }

var m1Ops = []m1Op{
	{
		key: "REST POST /api/v1/secrets/", permission: "secrets.write", modelScope: m1ScopeForProject,
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost, "/api/v1/secrets/", map[string]any{
				"name": "m1-fuzz-secret", "value": "v", "project_id": m1ProjectID(mw, tp), "environment_id": m1EnvID(mw, tp), "type": "generic",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST PUT /api/v1/secrets/{id}", permission: "secrets.write", modelScope: m1ScopeForProject,
		setup: func(ctx context.Context, w *faultWorld, mw *m1World, tp uint) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
				"name": "m1-fuzz-secret-upd", "value": "v", "project_id": m1ProjectID(mw, tp), "environment_id": m1EnvID(mw, tp), "type": "generic",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateSecret: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateSecret: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), map[string]any{"value": "v2"})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST DELETE /api/v1/secrets/{id}", permission: "secrets.delete", modelScope: m1ScopeForProject,
		setup: func(ctx context.Context, w *faultWorld, mw *m1World, tp uint) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
				"name": "m1-fuzz-secret-del", "value": "v", "project_id": m1ProjectID(mw, tp), "environment_id": m1EnvID(mw, tp), "type": "generic",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateSecret: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateSecret: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST POST /api/v1/roles/", permission: "roles.write", modelScope: m1ScopeGlobal,
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost, "/api/v1/roles/", map[string]any{
				"name": "m1-fuzz-role", "description": "d", "permissions": []string{"secrets.read"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST POST /api/v1/user-roles/ (assign viewer)", permission: "roles.assign", modelScope: m1ScopeGlobal,
		grantedRolePermissionsFn: func(mw *m1World) []string { return mw.viewerRolePermissions },
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost, "/api/v1/user-roles/", map[string]any{
				"user_id": mw.throwawayUserID, "role_id": mw.viewerRoleID, "project_id": 0, "environment_id": 0,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST DELETE /api/v1/user-roles/ (remove viewer)", permission: "roles.assign", modelScope: m1ScopeGlobal,
		setup: func(ctx context.Context, w *faultWorld, mw *m1World, tp uint) (any, error) {
			return nil, m1AssignRole(ctx, w, mw.throwawayUserID, mw.viewerRoleID, 0, 0)
		},
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			var reader io.Reader
			b, _ := json.Marshal(map[string]any{"user_id": mw.throwawayUserID, "role_id": mw.viewerRoleID, "project_id": 0, "environment_id": 0})
			reader = bytes.NewReader(b)
			req, err := http.NewRequestWithContext(ctx, http.MethodDelete, w.httpServer.URL+"/api/v1/user-roles/", reader)
			if err != nil {
				return opResult{}, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := w.httpClient.Do(req)
			if err != nil {
				return opResult{}, err
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			return httpResult(resp.StatusCode, body), nil
		},
	},
	{
		key: "REST POST /api/v1/users/{id}/suspend", permission: "users.write", targetsSoleGlobalAdmin: true,
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/suspend", mw.adminUserID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST DELETE /api/v1/users/{id}", permission: "users.delete", targetsSoleGlobalAdmin: true,
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", mw.adminUserID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST POST /api/v1/groups/", permission: "users.write", modelScope: m1ScopeGlobal,
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost, "/api/v1/groups/", map[string]any{
				"name": "m1-fuzz-group", "description": "d",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST POST /api/v1/groups/{id}/members", permission: "roles.assign", modelScope: m1ScopeGlobal,
		setup: func(ctx context.Context, w *faultWorld, mw *m1World, tp uint) (any, error) {
			return createGroupForFuzz(ctx, w, "m1-fuzz-group-members")
		},
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, state any) (opResult, error) {
			groupID := state.(uint)
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/members", groupID), map[string]any{
				"user_id": mw.throwawayUserID,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST POST /auth/tokens", permission: "", blockedWhenImpersonating: true,
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, _ any) (opResult, error) {
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost, "/api/v1/auth/tokens", map[string]any{"name": "m1-fuzz-pat"})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		key: "REST POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens", permission: "roles.assign",
		modelScope: m1ScopeForProject, blockedWhenImpersonating: true,
		setup: func(ctx context.Context, w *faultWorld, mw *m1World, tp uint) (any, error) {
			return m1CreateMachineIdentity(ctx, w, m1ProjectID(mw, tp), "m1-fuzz-target-machine")
		},
		execute: func(ctx context.Context, w *faultWorld, mw *m1World, token string, tp uint, state any) (opResult, error) {
			machineID := state.(uint)
			st, body, err := m1HTTPJSONAs(ctx, w, token, http.MethodPost,
				fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", m1ProjectID(mw, tp), machineID),
				map[string]any{"name": "m1-fuzz-issued-tok"})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
}

// ---- reference model ----

// modelVerdict independently computes whether p may cause ANY state change
// via op at target project tp -- the oracle this harness checks observed
// reality against. ok=false means this v1 model has no confident,
// non-false-positive-prone answer for this triple; the fuzzer never asserts
// on those.
func modelVerdict(p principalFixture, op m1Op, mw *m1World, tp uint) (deny bool, ok bool) {
	if op.blockedWhenImpersonating && p.isImpersonation {
		return true, true // R8
	}
	if op.permission == "" {
		return false, true // self-service, nothing else to deny
	}
	if op.targetsSoleGlobalAdmin && !p.isAdminTier {
		return true, true // R9: last-global-admin guard
	}
	needScope := core.Scope{}
	if op.modelScope != nil {
		needScope = op.modelScope(mw, tp)
	}
	if !p.holds(op.permission, needScope) {
		return true, true // R1: plain permission-gate denial
	}
	if grantedPerms := op.grantedRolePermissionsOf(mw); len(grantedPerms) > 0 && !p.isAdminTier {
		for _, perm := range grantedPerms {
			if !p.holds(perm, core.Scope{}) && !p.holds(perm, needScope) {
				return true, true // R2: granter-ceiling denial
			}
		}
	}
	return false, false // model has no reason to deny -- not asserted either way
}

// ---- fuzz entry point ----

// decodeMixedPrincipalFuzzInput picks a principal, an operation, and a target
// project (A or B) from the fuzz input's first three bytes -- the whole
// input space this harness explores; everything else about the iteration
// (which permissions each principal class holds, the two projects, the
// throwaway target user) is fixed scaffolding built fresh every iteration by
// buildM1World/buildM1Principals, per newFaultWorld's own reproducibility
// contract (nothing carries over between iterations).
func decodeMixedPrincipalFuzzInput(data []byte) (pIdx, opIdx int, tp uint, ok bool) {
	if len(data) < 3 {
		return 0, 0, 0, false
	}
	pIdx = int(data[0]) % int(numPrincipalKinds)
	opIdx = int(data[1]) % len(m1Ops)
	tp = uint(data[2] & 1)
	return pIdx, opIdx, tp, true
}

// FuzzMixedPrincipalAuthority is FUZZ-MECH M1. See the package doc comment
// above for the model's sources, v1 scope, and what is deliberately not
// covered yet.
func FuzzMixedPrincipalAuthority(f *testing.F) {
	for p := range int(numPrincipalKinds) {
		for o := range m1Ops {
			f.Add([]byte{byte(p), byte(o), 0})
			f.Add([]byte{byte(p), byte(o), 1})
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		pIdx, opIdx, tp, ok := decodeMixedPrincipalFuzzInput(data)
		if !ok {
			t.Skip("input too short")
		}
		ctx := context.Background()

		w := newFaultWorld(t, nil)
		mw, err := buildM1World(ctx, w)
		if err != nil {
			t.Skipf("setup buildM1World itself errored — not an authority finding: %v", err)
		}
		principals, err := buildM1Principals(ctx, w, mw)
		if err != nil {
			t.Skipf("setup buildM1Principals itself errored — not an authority finding: %v", err)
		}

		p := principals[pIdx]
		op := m1Ops[opIdx]

		deny, ok := modelVerdict(p, op, mw, tp)
		if !ok || !deny {
			return // not asserted: either a genuine ALLOW, or this v1 model isn't confident here
		}

		var state any
		if op.setup != nil {
			state, err = op.setup(ctx, w, mw, tp)
			if err != nil {
				t.Skipf("op setup itself errored — not an authority finding: %v", err)
			}
		}

		drainAllBackgroundGoroutines()
		before, err := snapshotDB(w.db)
		if err != nil {
			t.Fatalf("snapshotting pre-execute world: %v", err)
		}

		var result opResult
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic escaped the transport layer entirely for %s as %s (proj=%d): %v — the real "+
						"Recovery middleware should have converted this to a 500, not let it unwind past the handler",
						op.key, p.kind, tp, r)
				}
			}()
			result, err = op.execute(ctx, w, mw, p.token, tp, state)
		}()
		if err != nil {
			t.Skipf("execute returned a transport error (not an application error) for %s as %s: %v", op.key, p.kind, err)
		}

		drainAllBackgroundGoroutines()
		after, err := snapshotDB(w.db)
		if err != nil {
			t.Fatalf("snapshotting post-execute world: %v", err)
		}

		if hashExcluding(before, "AuditEvent") != hashExcluding(after, "AuditEvent") {
			t.Errorf("EFFECT-WITHOUT-AUTHORITY — %s as %s (targetProject=%d) changed non-audit state "+
				"(result=%+v) but the reference model requires denial here. Differing tables: %v",
				op.key, p.kind, tp, result, diffTables(before, after))
		}
	})
}

// TestMixedPrincipalAuthorityCoverage is the shrink-tripwire (same shape as
// minRoleGrantAuthorityPopulation / opCatalog's own pending-count ratchet):
// it never claims this v1 operation set is complete, only reports what
// fraction of the live mutating REST surface it covers and fails if the set
// silently shrinks below its current size.
func TestMixedPrincipalAuthorityCoverage(t *testing.T) {
	const minM1Ops = 12
	if len(m1Ops) < minM1Ops {
		t.Fatalf("m1Ops shrank to %d entries (floor %d) — an operation was silently removed", len(m1Ops), minM1Ops)
	}
	live := liveOperationKeys(t)
	var restCount int
	for _, k := range live {
		if len(k) >= 4 && k[:4] == "REST" {
			restCount++
		}
	}
	t.Logf("FuzzMixedPrincipalAuthority covers %d of %d live mutating REST operations (informational, not a completeness claim)",
		len(m1Ops), restCount)
}

// TestMixedPrincipalAuthority_PositiveControls proves this harness is not
// vacuously green (e.g. every call 403ing for an unrelated plumbing reason,
// which would make every DENY assertion trivially true and every finding
// this harness could ever catch invisible). Each case here is a combo
// modelVerdict returns deny=false for, and asserts it ACTUALLY succeeds with
// a real, observable state change -- the FuzzXxx loop itself never asserts
// this direction (over-allow is not this harness's concern), so it lives
// here as a plain test instead.
func TestMixedPrincipalAuthority_PositiveControls(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		pKind principalKind
		opKey string
		tp    uint
	}{
		{"globalAdmin creates a secret in project A", principalGlobalAdmin, "REST POST /api/v1/secrets/", 0},
		{"editor@projectA creates a secret in ITS OWN project", principalProjectEditorA, "REST POST /api/v1/secrets/", 0},
		{"machine-editor@projectA creates a secret in ITS OWN project (parity with the human editor)", principalMachineEditorA, "REST POST /api/v1/secrets/", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newFaultWorld(t, nil)
			mw, err := buildM1World(ctx, w)
			if err != nil {
				t.Fatalf("buildM1World: %v", err)
			}
			principals, err := buildM1Principals(ctx, w, mw)
			if err != nil {
				t.Fatalf("buildM1Principals: %v", err)
			}
			var p principalFixture
			for _, cand := range principals {
				if cand.kind == c.pKind {
					p = cand
				}
			}
			var op m1Op
			for _, cand := range m1Ops {
				if cand.key == c.opKey {
					op = cand
				}
			}
			deny, ok := modelVerdict(p, op, mw, c.tp)
			if ok && deny {
				t.Fatalf("test setup bug: modelVerdict says this positive control should be DENIED")
			}

			var state any
			if op.setup != nil {
				state, err = op.setup(ctx, w, mw, c.tp)
				if err != nil {
					t.Fatalf("op setup: %v", err)
				}
			}
			drainAllBackgroundGoroutines()
			before, err := snapshotDB(w.db)
			if err != nil {
				t.Fatalf("snapshot before: %v", err)
			}
			result, err := op.execute(ctx, w, mw, p.token, c.tp, state)
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if !result.Success {
				t.Fatalf("expected success, got %+v", result)
			}
			drainAllBackgroundGoroutines()
			after, err := snapshotDB(w.db)
			if err != nil {
				t.Fatalf("snapshot after: %v", err)
			}
			if hashExcluding(before, "AuditEvent") == hashExcluding(after, "AuditEvent") {
				t.Fatalf("expected a real state change for a successful create, got none — the harness's own diff plumbing is broken")
			}
		})
	}
}
