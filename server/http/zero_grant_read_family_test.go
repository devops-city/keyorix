// zero_grant_read_family_test.go — MACHINE-IDENT-DENY-1: a credential with no role
// grant reads no tenant data, on any GET route.
//
// # Why this exists
//
// The SDK contract suites (keyorix-sdks, all four languages) assert that a freshly
// created machine identity, holding no role, gets a 403 from GET /api/v1/projects,
// and that case fails on main: the server answers 200. Nobody had established
// whether that 200 discloses projects the identity has no grant on, or is the
// deliberate empty list #2780 introduced (ListProjects' doc comment: "a caller with
// no grants gets 200 with an empty array instead of a 403"). This file settles it
// for the whole GET surface rather than for that one route.
//
// # The guard: TestEveryGETRouteWithholdsDataFromZeroGrantCredentials
//
// Behavioural, over the real router, built on pat_restriction_read_family_test.go's
// canary world (newPATGuardWorld): every object in the canary project — project,
// environment, secrets, shares, secret access requests, the notifications those
// produce — carries patGuardCanary in its name. zeroGrantSeedExtras adds the
// tenant objects that world does not create, all canary-named: a folder, a group, a
// custom role, a secret dependency, a project access request (and its requester),
// and an expired PAT of the admin who creates the machine identities.
//
//   - The route set is derived, not listed: chi.Walk over NewRouter, every GET route
//     (patGuardGETRoutes). A GET route is covered the moment it is registered.
//   - Path parameters: every {param} of a route is bound to each canary object's id
//     in turn, with and without ?project_id/&environment_id naming the canary scope
//     (patGuardPaths). Recognised shapes: any GET route; any number of {params}.
//   - Oracle: a 2xx body containing patGuardCanary is a violation. None of the
//     zero-grant personas holds a grant on any canary object, and none of their own
//     names (machine identity, user, token) contains the canary, so a self-service
//     route answering about the caller itself cannot trip it.
//   - Personas (zeroGrantPersonas): a machine identity created IN the canary project
//     with no role (the SDK contract's exact shape), and one created in the decoy
//     project.
//   - Non-vacuity: every persona authenticates (200 on GET /projects), and the admin
//     session must see the canary on at least patGuardMinControlHits routes.
//
// What it does NOT cover, said plainly: non-GET routes; query parameters other than
// project_id/environment_id; ids other than the seeded canary objects'; data the
// fixture does not create (a dynamic-secret config or lease, a break-glass
// activation, a rotation policy, an alert-escalation policy, a notification
// channel, an OIDC binding, an audit-verify job); disclosure that does not repeat
// an object's name (a bare count or id, e.g. a dashboard aggregate). The status
// code is not asserted: 403 and an empty 200 both disclose nothing — which of the
// two a zero-grant caller gets is TestZeroGrantMachine_ProjectListIsEmpty200's
// subject. gRPC is not walked here.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
)

// zeroGrantPersonas are the credentials that hold no role grant on anything in the
// canary world. Each must read no canary object through any GET route.
var zeroGrantPersonas = []string{
	"machine_in_canary_project", // the SDK contract's shape: created in the project, no role
	"machine_in_decoy_project",
}

// zeroGrantReadExempt maps a GET route to the reason a zero-grant credential may
// legitimately see canary data through it. Empty: the walk found none. A reason
// must say why the data is not tenant data the caller lacks a grant on.
var zeroGrantReadExempt = map[string]string{}

// zeroGrantSeedExtras creates the canary-named tenant objects newPATGuardWorld does
// not, and appends their ids to w.ids for path-parameter binding.
func zeroGrantSeedExtras(t *testing.T, w *patGuardWorld) {
	t.Helper()
	ctx := context.Background()
	cs := w.core
	admin, err := cs.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	folder, err := cs.CreateFolder(ctx, admin.ID, patGuardCanary+"-folder", w.canaryPID, w.canaryEID, nil)
	require.NoError(t, err)
	group, err := cs.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: patGuardCanary + "-group", Description: patGuardCanary})
	require.NoError(t, err)
	role, _, err := cs.CreateRole(ctx, admin.ID, patGuardCanary+"-role", patGuardCanary+" role", nil)
	require.NoError(t, err)
	dep, err := cs.AddSecretDependency(ctx, core.ActorTypeUser, admin.ID, w.ownedSecret["admin_"], w.ownedSecret[""], patGuardCanary+" dependency", 0)
	require.NoError(t, err)
	requesterID, _ := mkUserWithGlobalRole(t, cs, patGuardCanary+"requester", "")
	ar, err := cs.RequestProjectAccess(ctx, w.canaryPID, requesterID, "project_viewer", patGuardCanary+" project access reason")
	require.NoError(t, err)
	// The machine identities below are created by the admin, so a regression that
	// resolved a machine credential to its creator's user id (machine contexts carry
	// UserID 0 today, which ListOwnPATs/ListOwnSessions reject) would answer the
	// self-service routes with the admin's own rows. A canary-named, already-expired
	// admin PAT makes GET /auth/tokens and /auth/tokens/expired trip the oracle then.
	past := time.Now().Add(-time.Hour)
	_, err = cs.CreateOwnPAT(ctx, admin.ID, patGuardCanary+"-admin-pat", &past, nil, 0, 0, nil)
	require.NoError(t, err)
	w.ids = append(w.ids, folder.ID, group.ID, role.ID, dep.ID, requesterID, ar.ID)
}

// zeroGrantMachine creates a machine identity in projectID over the real API (the
// SDK contract's path: POST .../machine-identities then .../tokens, as the admin)
// and returns its id and plaintext token.
func zeroGrantMachine(t *testing.T, w *patGuardWorld, projectID uint, name string) (uint, string) {
	t.Helper()
	admin := w.tokens["admin_session"]
	code, body := w.do(t, http.MethodPost, admin, fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID),
		[]byte(fmt.Sprintf(`{"name":%q,"identity_type":"service"}`, name)))
	require.Equal(t, http.StatusCreated, code, body)
	var mi struct {
		Data struct {
			MachineIdentity struct {
				ID uint `json:"id"`
			} `json:"machine_identity"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &mi), body)
	require.NotZero(t, mi.Data.MachineIdentity.ID, body)

	code, body = w.do(t, http.MethodPost, admin,
		fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", projectID, mi.Data.MachineIdentity.ID),
		[]byte(`{"name":"zero-grant-token"}`))
	require.Equal(t, http.StatusCreated, code, body)
	var tok struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &tok), body)
	require.NotEmpty(t, tok.Data.Token, body)
	return mi.Data.MachineIdentity.ID, tok.Data.Token
}

// zeroGrantBackends are the storage backends every test here runs on. Postgres
// skips without KEYORIX_TEST_PG_DSN (rrStorageConfig).
var zeroGrantBackends = []string{"sqlite", "postgres"}

func newZeroGrantWorld(t *testing.T, backend string) *patGuardWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg, _ := rrStorageConfig(t, backend)
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	w := newPATGuardWorldOn(t, core.NewKeyorixCore(st))
	zeroGrantSeedExtras(t, w)
	_, w.tokens["machine_in_canary_project"] = zeroGrantMachine(t, w, w.canaryPID, "zg-machine-a")
	_, w.tokens["machine_in_decoy_project"] = zeroGrantMachine(t, w, w.decoyPID, "zg-machine-b")
	// Non-vacuity: every persona authenticates. A walk where every request is a 401
	// would pass the leak oracle trivially.
	for _, persona := range zeroGrantPersonas {
		code, body := w.get(t, w.tokens[persona], "/api/v1/projects")
		require.Equal(t, http.StatusOK, code, "fixture: %s must authenticate: %s", persona, body)
	}
	return w
}

// zeroGrantWalk calls every GET route as each persona and returns, per route, the
// requests that disclosed canary data. It logs, per persona, how many routes
// answered each status on their unparameterised/first binding (the 403-versus-
// empty-200 picture, for the record; not asserted).
func zeroGrantWalk(t *testing.T, w *patGuardWorld, routes, personas []string) map[string][]string {
	t.Helper()
	violations := map[string][]string{}
	statuses := map[string]map[int][]string{}
	for _, route := range routes {
		if _, exempt := zeroGrantReadExempt[route]; exempt {
			continue
		}
		for i, p := range w.patGuardPaths(route) {
			for _, persona := range personas {
				code, body := w.get(t, w.tokens[persona], p)
				if i == 0 {
					if statuses[persona] == nil {
						statuses[persona] = map[int][]string{}
					}
					statuses[persona][code] = append(statuses[persona][code], route)
				}
				if leaks(code, body) {
					violations[route] = append(violations[route], fmt.Sprintf("%s via %s -> %d %s", persona, p, code, truncateForLog(body)))
				}
			}
		}
	}
	for _, persona := range personas {
		for code, rs := range statuses[persona] {
			if code == http.StatusForbidden {
				t.Logf("zero-grant walk: %s: %d routes -> 403", persona, len(rs))
				continue
			}
			t.Logf("zero-grant walk: %s: %d routes -> %d: %s", persona, len(rs), code, strings.Join(rs, " "))
		}
	}
	return violations
}

func truncateForLog(s string) string {
	const limit = 400
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

func reportZeroGrantViolations(t *testing.T, violations map[string][]string) {
	t.Helper()
	routes := make([]string, 0, len(violations))
	for r := range violations {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, route := range routes {
		t.Errorf("GET %s disclosed canary data to a credential with no grant on it:\n  %s\n"+
			"Filter the rows by the caller's authorization (see core.VisibleProjects / "+
			"ListReadableSecrets), or add a reasoned entry to zeroGrantReadExempt.",
			route, strings.Join(violations[route], "\n  "))
	}
}

// TestEveryGETRouteWithholdsDataFromZeroGrantCredentials is the family-wide guard
// (see the file header).
func TestEveryGETRouteWithholdsDataFromZeroGrantCredentials(t *testing.T) {
	for _, backend := range zeroGrantBackends {
		t.Run(backend, func(t *testing.T) { testEveryGETRouteWithholdsDataFromZeroGrant(t, backend) })
	}
}

func testEveryGETRouteWithholdsDataFromZeroGrant(t *testing.T, backend string) {
	w := newZeroGrantWorld(t, backend)
	routes := patGuardGETRoutes(t, w.router)
	require.Greater(t, len(routes), 100, "sanity: the walk should find the whole GET surface")

	controlHits := map[string]bool{}
	for _, route := range routes {
		for _, p := range w.patGuardPaths(route) {
			if code, body := w.get(t, w.tokens["admin_session"], p); leaks(code, body) {
				controlHits[route] = true
				break
			}
		}
	}
	assert.GreaterOrEqual(t, len(controlHits), patGuardMinControlHits,
		"the admin saw canary data on too few routes: the fixture is not exercising the surface")
	for _, mustSee := range []string{
		"/api/v1/projects", "/api/v1/environments", "/api/v1/secrets/", "/api/v1/folders/",
		"/api/v1/groups/", "/api/v1/roles/", "/api/v1/projects/{id}/access-requests",
		"/api/v1/auth/tokens", "/api/v1/auth/tokens/expired",
	} {
		assert.True(t, controlHits[mustSee], "positive control: the admin must see canary data on GET %s", mustSee)
	}

	reportZeroGrantViolations(t, zeroGrantWalk(t, w, routes, zeroGrantPersonas))

	routeSet := map[string]bool{}
	for _, r := range routes {
		routeSet[r] = true
	}
	for route, reason := range zeroGrantReadExempt {
		assert.True(t, routeSet[route], "zeroGrantReadExempt entry %q is not a GET route any more: remove it", route)
		assert.NotEmpty(t, strings.TrimSpace(reason), "zeroGrantReadExempt entry %q needs a reason", route)
	}
}

// TestZeroGrantMachine_ProjectListIsEmpty200 pins the status-code half of the SDK
// contract question: a machine identity with no grant that lists projects gets
// 200 with an EMPTY list — not a 403, and not the deployment's projects. The empty
// 200 is the documented behaviour (#2780, CatalogHandler.ListProjects'
// doc comment and docs/api), so the SDK contract's "must be forbidden" expectation
// is what is stale; the disclosure half is the walk above.
func TestZeroGrantMachine_ProjectListIsEmpty200(t *testing.T) {
	for _, backend := range zeroGrantBackends {
		t.Run(backend, func(t *testing.T) { testZeroGrantMachineProjectListIsEmpty200(t, backend) })
	}
}

func testZeroGrantMachineProjectListIsEmpty200(t *testing.T, backend string) {
	w := newZeroGrantWorld(t, backend)
	for _, persona := range []string{"machine_in_canary_project", "machine_in_decoy_project"} {
		t.Run(persona, func(t *testing.T) {
			code, body := w.get(t, w.tokens[persona], "/api/v1/projects")
			require.Equal(t, http.StatusOK, code, body)
			var resp struct {
				Data struct {
					Projects []json.RawMessage `json:"projects"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &resp), body)
			assert.Empty(t, resp.Data.Projects, "a zero-grant machine must list no project: %s", body)
			// The canary oracle cannot see the bootstrap "default" project's rows, so the
			// two grant-filtered lists are asserted empty outright.
			code, body = w.get(t, w.tokens[persona], "/api/v1/environments")
			require.Equal(t, http.StatusOK, code, body)
			var envs struct {
				Data struct {
					Environments []json.RawMessage `json:"environments"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &envs), body)
			assert.Empty(t, envs.Data.Environments, "a zero-grant machine must list no environment: %s", body)
			// A route-gated read is a 403, not an empty answer.
			code, body = w.get(t, w.tokens[persona], fmt.Sprintf("/api/v1/projects/%d", w.canaryPID))
			assert.Equal(t, http.StatusForbidden, code, body)
		})
	}
}
