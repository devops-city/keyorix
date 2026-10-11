// pat_restriction_write_family_test.go — PAT-GUARD-3: a restricted PAT is refused
// on every ungated write, deny-by-default, except an explicit allowlist (Andrei's
// decision of 2026-10-11, ADR-042 addendum "ungated writes, deny-by-default").
//
// # The guard: TestEveryUngatedWriteDeclaresRestrictedPATPolicy
//
//   - The route set is derived, not listed: scanRouter (permission_sweep_test.go)
//     parses router.go and returns every route with no permission gate. Every
//     non-GET one must have an entry in core's restrictedPATUngatedWrites table,
//     "refused" or "allowed" with a reason, and every HTTP entry must still be an
//     ungated non-GET route. A new ungated write fails here until someone decides.
//   - Every refused entry is called by every restricted persona of #3062's fixture
//     (two owners x five restrictions) and must answer 403 with the entry's
//     sentinel text; the same owners' unrestricted PATs must NOT get that text, so
//     the refusal is the restriction and not the route. Three refusals also check
//     the effect is absent: the profile is unchanged, the old password still logs
//     in, no project access request was created.
//   - Every allowed entry has a case in restrictedPATAllowedCases that a restricted
//     PAT really succeeds on: it revokes its owner's own token/session, bulk-revokes
//     the owner's expired tokens, or creates a secret/folder/rotation policy/
//     dynamic config inside its own restriction (and is refused outside it). The
//     pre-authentication routes are not PAT-authenticated: login with a restricted
//     PAT as the bearer really succeeds, and every other one answers a restricted
//     PAT exactly as it answers an unrestricted one.
//
// What it does NOT cover: GET routes (TestEveryGETRouteHonoursPATRestriction);
// permission-gated writes, whose restriction is Authorize's (core authz tests and
// the protoreflect fuzzer's AUTHZ oracle); a refused route's handler on its own,
// since the middleware answers first (the PAT-GUARD-1/2 core refusals for PAT mint
// and break-glass stay as defence in depth and keep their own tests). The gRPC half
// is server/grpc/pat_restriction_write_family_test.go.
package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
)

// patGuardAllRestricted is every restricted persona of both owners.
func patGuardAllRestricted() []string {
	var out []string
	for _, o := range patGuardOwners {
		for _, p := range patGuardRestrictedPersonas {
			out = append(out, o.prefix+p)
		}
	}
	return out
}

// routeKeyMethodPath splits "POST /api/v1/x/{id}" into its method and path.
func routeKeyMethodPath(key string) (string, string) {
	method, path, _ := strings.Cut(key, " ")
	return method, path
}

// requestMethod is the HTTP method to call a route key with: HANDLE and MOUNT
// accept any method, so they are called with a write.
func requestMethod(method string) string {
	if method == "HANDLE" || method == "MOUNT" {
		return http.MethodPost
	}
	return method
}

// isHTTPWriteKey reports whether an ungated route key is a write (anything but GET).
func isHTTPWriteKey(key string) bool {
	method, _ := routeKeyMethodPath(key)
	return method != http.MethodGet
}

// restrictedPATAllowedCase proves a restricted PAT really succeeds on one allowed
// write.
type restrictedPATAllowedCase func(t *testing.T, w *patGuardWorld)

var restrictedPATAllowedCases = map[string]restrictedPATAllowedCase{
	"DELETE /api/v1/auth/tokens/{id}":      allowedRevokeOwnPAT,
	"DELETE /api/v1/auth/sessions/{id}":    allowedRevokeOwnSession,
	"DELETE /api/v1/auth/tokens/expired":   allowedBulkRevokeOwnExpiredPATs,
	"POST /api/v1/secrets":                 allowedInScopeCreate("/api/v1/secrets", `{"name":"%s","value":"v","type":"password","project_id":%d,"environment_id":%d}`),
	"POST /api/v1/folders":                 allowedInScopeCreate("/api/v1/folders", `{"name":"%s","project_id":%d,"environment_id":%d}`),
	"POST /api/v1/rotation-policies":       allowedInScopeCreate("/api/v1/rotation-policies", `{"name":"%s","scope":"environment","project_id":%d,"environment_id":%d,"interval_days":30}`),
	"POST /api/v1/dynamic-secrets/configs": allowedInScopeCreate("/api/v1/dynamic-secrets/configs", `{"name":"%s","project_id":%d,"environment_id":%d,"backend_type":"postgres","admin_dsn":"postgres://localhost/test"}`),
	"POST /auth/login":                     allowedLoginWithRestrictedBearer,

	"PUT /api/v1/secret-access-requests/{requestId}": allowedResolveSecretAccessRequest,
}

// TestEveryUngatedWriteDeclaresRestrictedPATPolicy is the family-wide guard (see
// the file header).
func TestEveryUngatedWriteDeclaresRestrictedPATPolicy(t *testing.T) {
	found, _ := scanRouter(t, filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go"))
	table := core.RestrictedPATUngatedWrites()

	var writes []string
	for key := range found {
		if isHTTPWriteKey(key) {
			writes = append(writes, key)
		}
	}
	sort.Strings(writes)
	require.Greater(t, len(writes), 30, "sanity: the scan should find the whole ungated write surface")
	for _, key := range writes {
		_, ok := table[key]
		assert.True(t, ok, "%s is an ungated write with no restricted-PAT declaration: add it to "+
			"core.restrictedPATUngatedWrites (internal/core/pat_restriction_writes.go) as refused, or allowed "+
			"with a reason (deny-by-default, ADR-042 PAT-GUARD-3)", key)
	}
	for key, p := range table {
		if strings.HasPrefix(key, "/") { // a gRPC full method name
			continue
		}
		u, ok := found[key]
		assert.True(t, ok && isHTTPWriteKey(key), "restricted-PAT table entry %q is not an ungated write in router.go any more: remove it (%+v)", key, u)
		if p.Allowed {
			assert.NotEmpty(t, strings.TrimSpace(p.Reason), "allowed entry %q needs a reason", key)
		}
	}

	w := newPATGuardWorld(t)
	// The dynamic-config case: a real engine (as server/main.go wires it) and a
	// localhost DSN; creating a config does not dial it.
	w.core.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, false, false) })
	w.core.SetDynamicAllowPrivateTargets(true)
	restricted := patGuardAllRestricted()
	ip := 0
	for _, key := range writes {
		p, ok := table[key]
		if !ok {
			continue
		}
		method, route := routeKeyMethodPath(key)
		path := patGuardParamRe.ReplaceAllString(route, fmt.Sprint(w.canaryPID))
		switch {
		case !p.Allowed:
			t.Run("refused "+key, func(t *testing.T) {
				want := p.RefusalError().Error()
				for _, persona := range restricted {
					code, body := w.do(t, method, w.tokens[persona], path, []byte(`{}`))
					assert.Equal(t, http.StatusForbidden, code, "%s: %s", persona, body)
					assert.Contains(t, body, want, persona)
				}
				for _, o := range patGuardOwners {
					_, body := w.do(t, method, w.tokens[o.prefix+"pat_unrestricted"], path, []byte(`{}`))
					assert.NotContains(t, body, want, "control: an unrestricted PAT must not be refused as restricted")
				}
			})
		case !strings.HasPrefix(route, "/api/v1/"):
			// Pre-authentication / infrastructure: the PAT is not the credential.
			ip++
			addr := fmt.Sprintf("198.51.100.%d:4000", ip) // own login-throttle budget per route
			t.Run("allowed not PAT-authenticated "+key, func(t *testing.T) {
				for _, o := range patGuardOwners {
					rc, rb := w.serve(t, requestMethod(method), w.tokens[o.prefix+"pat_decoy_project"], path, addr)
					uc, _ := w.serve(t, requestMethod(method), w.tokens[o.prefix+"pat_unrestricted"], path, addr)
					assert.Equal(t, uc, rc, "a restricted PAT must be answered exactly as an unrestricted one: %s", rb)
					for _, s := range []error{core.ErrRestrictedPATSelfServiceWrite, core.ErrRestrictedPATCannotMintPAT, core.ErrRestrictedPATCannotBreakGlass} {
						assert.NotContains(t, rb, s.Error())
					}
				}
			})
			if c, ok := restrictedPATAllowedCases[key]; ok {
				t.Run("allowed succeeds "+key, func(t *testing.T) { c(t, w) })
			}
		default:
			c, ok := restrictedPATAllowedCases[key]
			if !assert.True(t, ok, "allowed entry %s has no behavioural case in restrictedPATAllowedCases", key) {
				continue
			}
			t.Run("allowed succeeds "+key, func(t *testing.T) { c(t, w) })
		}
	}
	for key := range restrictedPATAllowedCases {
		assert.True(t, table[key].Allowed, "restrictedPATAllowedCases has a case for %s, which is not an allowed entry", key)
	}
}

// serve calls the router in-process with a chosen client address, so the
// pre-authentication routes' per-IP login throttle cannot make two calls differ.
func (w *patGuardWorld) serve(t *testing.T, method, token, path, remoteAddr string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func (w *patGuardWorld) userID(t *testing.T, username string) uint {
	t.Helper()
	u, err := w.core.GetUserByEmail(context.Background(), username+"@example.com")
	require.NoError(t, err)
	return u.ID
}

// alive reports whether a credential still authenticates.
func (w *patGuardWorld) alive(t *testing.T, token string) bool {
	t.Helper()
	code, _ := w.get(t, token, "/api/v1/auth/tokens")
	return code == http.StatusOK
}

func allowedRevokeOwnPAT(t *testing.T, w *patGuardWorld) {
	for _, o := range patGuardOwners {
		for _, persona := range patGuardRestrictedPersonas {
			p, err := w.core.CreateOwnPAT(context.Background(), w.userID(t, o.username), "g3-own-"+persona, nil, nil, 0, 0, nil)
			require.NoError(t, err)
			code, body := w.do(t, http.MethodDelete, w.tokens[o.prefix+persona], fmt.Sprintf("/api/v1/auth/tokens/%d", p.Token.ID), nil)
			assert.Equal(t, http.StatusNoContent, code, "%s: %s", persona, body)
			assert.False(t, w.alive(t, p.PlainToken), "%s: the revoked PAT must stop authenticating", persona)
		}
	}
}

func allowedRevokeOwnSession(t *testing.T, w *patGuardWorld) {
	passwords := map[string]string{"pgowner": membershipsGatePassword, "testadmin": "TestPassword123!"}
	for _, o := range patGuardOwners {
		for _, persona := range patGuardRestrictedPersonas {
			s, _, err := w.core.Login(context.Background(), &core.LoginRequest{Username: o.username, Password: passwords[o.username]})
			require.NoError(t, err)
			code, body := w.do(t, http.MethodDelete, w.tokens[o.prefix+persona], fmt.Sprintf("/api/v1/auth/sessions/%d", s.ID), nil)
			assert.Equal(t, http.StatusNoContent, code, "%s: %s", persona, body)
			assert.False(t, w.alive(t, s.SessionToken), "%s: the revoked session must stop authenticating", persona)
		}
	}
}

func allowedBulkRevokeOwnExpiredPATs(t *testing.T, w *patGuardWorld) {
	ctx := context.Background()
	past := time.Now().Add(-24 * time.Hour)
	for _, o := range patGuardOwners {
		uid := w.userID(t, o.username)
		for _, persona := range patGuardRestrictedPersonas {
			_, err := w.core.CreateOwnPAT(ctx, uid, "g3-expired-"+persona, &past, nil, 0, 0, nil)
			require.NoError(t, err)
			expired, err := w.core.ListExpiredOwnPATs(ctx, uid)
			require.NoError(t, err)
			require.NotEmpty(t, expired, "fixture: an expired PAT to revoke")
			code, body := w.do(t, http.MethodDelete, w.tokens[o.prefix+persona], "/api/v1/auth/tokens/expired", nil)
			assert.Equal(t, http.StatusNoContent, code, "%s: %s", persona, body)
			expired, err = w.core.ListExpiredOwnPATs(ctx, uid)
			require.NoError(t, err)
			assert.Empty(t, expired, "%s: the owner's expired PATs must be revoked", persona)
		}
	}
}

// allowedInScopeCreate: a token confined to the decoy project (and one confined to
// the decoy environment) creates inside the decoy scope, and is refused (by
// Authorize, not by the restricted-PAT table) at the canary scope.
func allowedInScopeCreate(path, bodyFmt string) restrictedPATAllowedCase {
	return func(t *testing.T, w *patGuardWorld) {
		for _, o := range patGuardOwners {
			for _, persona := range []string{"pat_decoy_project", "pat_decoy_env"} {
				name := fmt.Sprintf("g3-%s%s-%d", o.prefix, persona, time.Now().UnixNano())
				code, body := w.do(t, http.MethodPost, w.tokens[o.prefix+persona], path, []byte(fmt.Sprintf(bodyFmt, name, w.decoyPID, w.decoyEID)))
				assert.True(t, code == http.StatusOK || code == http.StatusCreated, "%s in its own scope: %d %s", persona, code, body)
				assert.Contains(t, body, name, persona)

				code, body = w.do(t, http.MethodPost, w.tokens[o.prefix+persona], path, []byte(fmt.Sprintf(bodyFmt, name+"-x", w.canaryPID, w.canaryEID)))
				assert.Equal(t, http.StatusForbidden, code, "%s outside its scope: %s", persona, body)
				assert.NotContains(t, body, core.ErrRestrictedPATSelfServiceWrite.Error(), "refused by Authorize, not by the table")
			}
		}
	}
}

// allowedResolveSecretAccessRequest: the request's approver is the owner (a
// project_admin at the canary project). A restricted PAT WITHOUT roles.assign at
// that project is refused by core (not by the restricted-PAT table) and the request
// stays pending; one WITH roles.assign there succeeds. Core's own authority check is
// unchanged for the unrestricted owner.
func allowedResolveSecretAccessRequest(t *testing.T, w *patGuardWorld) {
	ctx := context.Background()
	for _, o := range patGuardOwners {
		owner := w.userID(t, o.username)
		res, err := w.core.CreateOwnPAT(ctx, owner, "g3-roles-assign-"+o.prefix, nil, []string{"roles.assign"}, w.canaryPID, 0, nil)
		require.NoError(t, err)

		// The fixture's pending request: the peer's, for this owner's canary secret.
		req, err := w.core.GetSecretAccessRequest(ctx, w.accessRequests[o.prefix+"pending"], owner)
		require.NoError(t, err)
		require.Equal(t, core.AccessRequestPending, req.State, "fixture: a pending request to decide")
		path := fmt.Sprintf("/api/v1/secret-access-requests/%d", req.ID)
		body := []byte(`{"action":"approve"}`)

		for _, persona := range patGuardRestrictedPersonas {
			code, resp := w.do(t, http.MethodPut, w.tokens[o.prefix+persona], path, body)
			assert.Equal(t, http.StatusForbidden, code, "%s: %s", persona, resp)
			assert.NotContains(t, resp, core.ErrRestrictedPATSelfServiceWrite.Error(), "%s: refused by core, not by the table", persona)
			got, gerr := w.core.GetSecretAccessRequest(ctx, req.ID, owner)
			require.NoError(t, gerr)
			assert.Equal(t, core.AccessRequestPending, got.State, "%s: a refused approval must leave the request pending", persona)
		}

		code, resp := w.do(t, http.MethodPut, res.PlainToken, path, body)
		assert.Equal(t, http.StatusOK, code, "%s: restricted PAT with roles.assign at the request's project: %s", o.username, resp)
		got, err := w.core.GetSecretAccessRequest(ctx, req.ID, owner)
		require.NoError(t, err)
		assert.Equal(t, core.AccessRequestApproved, got.State)
	}
}

func allowedLoginWithRestrictedBearer(t *testing.T, w *patGuardWorld) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"testadmin","password":"TestPassword123!"}`))
	req.RemoteAddr = "198.51.100.250:4000"
	req.Header.Set("Authorization", "Bearer "+w.tokens["admin_pat_decoy_project"])
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// TestPATRestriction_RefusedSelfServiceWritesHaveNoEffect checks the effect is
// absent, not just the status, for three refusals the family guard only checks by
// status, and that the same request succeeds for the unrestricted owner. The
// project-only owner's personas; the admin's are refused by the same table entry.
func TestPATRestriction_RefusedSelfServiceWritesHaveNoEffect(t *testing.T) {
	w := newPATGuardWorld(t)
	ctx := context.Background()

	t.Run("profile", func(t *testing.T) {
		body := []byte(`{"display_name":"g3-renamed","email":"pgowner@example.com"}`)
		for _, persona := range patGuardRestrictedPersonas {
			code, resp := w.do(t, http.MethodPut, w.tokens[persona], "/api/v1/auth/profile", body)
			assert.Equal(t, http.StatusForbidden, code, "%s: %s", persona, resp)
		}
		_, resp := w.get(t, w.tokens["session"], "/api/v1/auth/profile")
		assert.NotContains(t, resp, "g3-renamed", "a refused profile update must not change the profile")
		code, resp := w.do(t, http.MethodPut, w.tokens["pat_unrestricted"], "/api/v1/auth/profile", body)
		require.Equal(t, http.StatusOK, code, "control: %s", resp)
		_, resp = w.get(t, w.tokens["session"], "/api/v1/auth/profile")
		assert.Contains(t, resp, "g3-renamed")
	})

	t.Run("project_access_request", func(t *testing.T) {
		p, err := w.core.CreateProject(ctx, "g3-noaccess", "a project neither owner belongs to")
		require.NoError(t, err)
		path := fmt.Sprintf("/api/v1/projects/%d/access-requests", p.ID)
		body := []byte(`{"suggested_role":"project_viewer","reason":"g3"}`)
		for _, persona := range patGuardRestrictedPersonas {
			code, resp := w.do(t, http.MethodPost, w.tokens[persona], path, body)
			assert.Equal(t, http.StatusForbidden, code, "%s: %s", persona, resp)
		}
		// A request a restricted token had created would make this a 409.
		code, resp := w.do(t, http.MethodPost, w.tokens["pat_unrestricted"], path, body)
		assert.Equal(t, http.StatusCreated, code, "control: no request may exist yet: %s", resp)
	})

	// Last: a password change ends the owner's other credentials.
	t.Run("change_password", func(t *testing.T) {
		body := []byte(fmt.Sprintf(`{"current_password":%q,"new_password":"Zx9#Wv4$Tq8@Pm3!"}`, membershipsGatePassword))
		for _, persona := range patGuardRestrictedPersonas {
			code, resp := w.do(t, http.MethodPost, w.tokens[persona], "/api/v1/auth/change-password", body)
			assert.Equal(t, http.StatusForbidden, code, "%s: %s", persona, resp)
		}
		_, _, err := w.core.Login(ctx, &core.LoginRequest{Username: "pgowner", Password: membershipsGatePassword})
		require.NoError(t, err, "a refused password change must leave the old password working")
		code, resp := w.do(t, http.MethodPost, w.tokens["pat_unrestricted"], "/api/v1/auth/change-password", body)
		require.Equal(t, http.StatusOK, code, "control: %s", resp)
	})
}
