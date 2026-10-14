// deployment_disclosure_family_test.go — proves the fix for the #255/#272-275/#280-281
// deployment-wide disclosure family: a set of reporting/aggregation endpoints that used
// to be gated only by the universal, auto-assigned system_viewer baseline (system.read)
// — or, for #272, by NO permission at all — so any authenticated account (including a
// brand-new user with zero project memberships) could read sensitive data about other
// users/projects/secrets deployment-wide. Each route now requires audit.read (the
// system_admin/system_auditor persona at global scope), which is NOT auto-granted to
// every account. This file proves, for each affected route: a baseline (system_viewer)
// caller is denied (403) and an audit.read holder (system_auditor) succeeds (200) with
// the expected payload shape.
//
// GET /admin/usage (7th+ confirmed instance of the same mistake, found in the same
// campaign that produced server/http/permission_sweep_test.go's exhaustiveness guard) is
// included in the table below. GET /admin/billing/report is the same bug but needs its
// own license-gated fixture, so it gets a dedicated test,
// TestAdminBillingReport_PermissionTiers, further down this file.
package http

import (
	"context"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/license"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFullSchemaTestCore creates a *core.KeyorixCore over a FULLY migrated (production
// schema) in-memory SQLite DB, via the same StorageFactory the server uses at startup.
// The minimal newTestCore (above, in integration_test.go) only migrates a handful of
// tables — not enough for the compliance/hygiene/PAT/machine-credential/risk-register
// storage this file exercises.
func newFullSchemaTestCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Database: config.DatabaseConfig{
				Path: sqlitetest.DSN("kxtest_"),
			},
		},
	}
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	return core.NewKeyorixCore(st)
}

// createAuditorToken creates a user holding ONLY the system_auditor role (global scope)
// — the "genuinely elevated, but not admin-bypass" persona this fix's audit.read gate
// is meant to admit — and returns a session token.
func createAuditorToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	_, err := c.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: "family_auditor", Email: "family_auditor@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	}, "system_auditor", nil, 0, false)
	require.NoError(t, err)
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "family_auditor", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

// createNoPermissionToken creates a user, then strips even the auto-assigned
// system_viewer baseline role — simulating a principal holding NO relevant permission
// at all (the #272 scenario: today that principal succeeds at GET /dashboard/stats
// because the route checks no permission whatsoever; after the fix it must be denied).
func createNoPermissionToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	_, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "family_noperm", Email: "family_noperm@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "family_noperm@example.com", "system_viewer"))
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "family_noperm", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

// familyFixtures seeds one row of real, sensitive data behind each endpoint under test
// (a secret, a PAT, a machine credential, an SoD violation) so the "auditor succeeds
// with the EXPECTED data" assertions are not vacuously true against an empty deployment.
type familyFixtures struct {
	projectID uint
	envID     uint
}

func seedFamilyFixtures(t *testing.T, c *core.KeyorixCore) familyFixtures {
	t.Helper()
	ctx := context.Background()

	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	project := projects[0]

	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	// A live secret, so the deployment-wide inventory CSV (#280) and hygiene rollup
	// (#273) have a real row to disclose (or correctly withhold from a baseline caller).
	_, err = c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "family-disclosure-canary",
		Value:         []byte("s3cr3t-value"),
		ProjectID:     project.ID,
		EnvironmentID: env.ID,
		Type:          "generic",
		CreatedBy:     admin.Username,
		OwnerID:       admin.ID,
	})
	require.NoError(t, err)

	// An expired-but-active PAT, so /pat-hygiene (#275) has a flagged entry.
	pastExpiry := time.Now().Add(-1 * time.Hour)
	_, err = c.CreateOwnPAT(ctx, admin.ID, "leaked-ci-token", &pastExpiry, nil, 0, 0, nil)
	require.NoError(t, err)

	// An expired-but-active machine credential, so /machine-token-hygiene (#274) has a
	// flagged entry.
	mi, err := c.CreateMachineIdentity(ctx, project.ID, "family-ci-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	_, err = c.IssueMachineToken(ctx, project.ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "family-ci-token", ExpiresAt: &pastExpiry})
	require.NoError(t, err)

	// An SoD policy that the system_auditor role itself violates (system_auditor holds
	// both system.read and audit.read), so /sod/violations discloses a real violator.
	_, err = c.CreateSoDPolicy(ctx, admin.ID, "family-test-policy", "", "system.read", "audit.read")
	require.NoError(t, err)

	// A risk exception with free-text Reference/Justification, so /risk-exceptions
	// (#255 bundled sub-finding) has a real row to disclose (or correctly withhold).
	_, err = c.CreateRiskException(ctx, admin.ID, false, "family risk", "other", "secret:family-disclosure-canary",
		"accepted pending rotation", time.Now().Add(48*time.Hour))
	require.NoError(t, err)

	return familyFixtures{projectID: project.ID, envID: env.ID}
}

// familyRoute describes one GET route in the disclosure family under test.
type familyRoute struct {
	name  string
	path  string
	check func(t *testing.T, body []byte, contentType string) // asserts the 200 payload shape
}

func jsonDataField(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	var m map[string]any
	require.NoError(t, json.Unmarshal(env.Data, &m))
	return m
}

// TestDeploymentDisclosureFamily_BaselineDeniedAuditorAllowed covers instances
// #255 (compliance/evidence family incl. posture/controls/controls.csv/digest/
// legal-hold/risk-exceptions/sod-violations), #273 (hygiene), #274
// (machine-token-hygiene), #275 (pat-hygiene), #280 (secrets/inventory.csv), and #281
// (secrets/name-conformance): every route must deny a system_viewer-baseline caller
// (403) and allow a system_auditor (audit.read) caller (200) with the expected data.
func TestDeploymentDisclosureFamily_BaselineDeniedAuditorAllowed(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	createTestToken(t, testCore) // bootstrap admin + seed roles/permissions
	// Tokens are created BEFORE seedFamilyFixtures: it plants an SoD policy
	// ("family-test-policy", system.read + audit.read) that system_auditor itself
	// violates, by design, so /sod/violations has a real row to disclose. Since
	// #419, minting a NEW system_auditor account after that policy exists would be
	// correctly BLOCKED by the grant-time preventive gate — creating the account
	// first (no policy yet) and defining the policy afterward instead reproduces
	// the intended "grandfathered/pre-existing violation" scenario, exactly what
	// the periodic scan is meant to still catch.
	baselineToken := createLimitedToken(t, testCore) // system_viewer only (system.read)
	auditorToken := createAuditorToken(t, testCore)  // system_auditor (audit.read, global)
	fixtures := seedFamilyFixtures(t, testCore)

	// Plant a non-conforming secret BEFORE the naming policy is enabled (naming policy
	// is only enforced at create time — a policy tightened afterward leaves existing
	// "straggler" secrets that violate it, which is exactly what #281's deployment-wide
	// conformance report scans for).
	ctx := context.Background()
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.ListProjects(ctx)
	require.NoError(t, err)
	envs, err := testCore.ListEnvironments(ctx)
	require.NoError(t, err)
	_, err = testCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "Family_NonConforming_Name", Value: []byte("x"), ProjectID: projects[0].ID,
		EnvironmentID: envs[0].ID, Type: "generic", CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	// Enable the naming policy AFTER the straggler secret above was created.
	require.NoError(t, testCore.SetSecretNamePolicy(core.SecretNamePolicy{
		Enabled: true, Pattern: `^[a-z0-9]+(-[a-z0-9]+)*$`, MaxLength: 64,
	}))

	routes := []familyRoute{
		{
			name: "#280 deployment secrets inventory CSV",
			path: "/api/v1/secrets/inventory.csv",
			check: func(t *testing.T, body []byte, contentType string) {
				assert.Contains(t, contentType, "text/csv")
				rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
				require.NoError(t, err)
				require.GreaterOrEqual(t, len(rows), 2, "header + at least one secret row")
				found := false
				for _, row := range rows[1:] {
					if len(row) > 2 && row[2] == "family-disclosure-canary" {
						found = true
					}
				}
				assert.True(t, found, "the canary secret's real name must appear in the CSV for an audit.read holder")
			},
		},
		{
			name: "#281 deployment secret name-conformance",
			path: "/api/v1/secrets/name-conformance",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				assert.Equal(t, true, m["policy_enabled"])
				violations, _ := m["violations"].([]any)
				assert.NotEmpty(t, violations, "the non-conformant secret must be reported")
			},
		},
		{
			name: "#275 pat-hygiene",
			path: "/api/v1/pat-hygiene",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				tokens, _ := m["tokens"].([]any)
				assert.NotEmpty(t, tokens, "the expired PAT must be flagged")
			},
		},
		{
			name: "#274 machine-token-hygiene",
			path: "/api/v1/machine-token-hygiene",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				creds, ok := m["credentials"].([]any)
				if !ok {
					creds, _ = m["tokens"].([]any)
				}
				assert.NotEmpty(t, creds, "the expired machine credential must be flagged")
			},
		},
		{
			name: "#273 deployment hygiene rollup",
			path: "/api/v1/hygiene",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				assert.Contains(t, m, "totals")
			},
		},
		{
			name: "#255 compliance posture",
			path: "/api/v1/compliance/posture",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				assert.Contains(t, m, "access_governance")
			},
		},
		{
			name: "#255 compliance controls",
			path: "/api/v1/compliance/controls",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				assert.Contains(t, m, "controls")
			},
		},
		{
			name: "#255 compliance controls CSV",
			path: "/api/v1/compliance/controls.csv",
			check: func(t *testing.T, body []byte, contentType string) {
				assert.Contains(t, contentType, "text/csv")
				assert.NotEmpty(t, body)
			},
		},
		{
			name: "#255 compliance digest",
			path: "/api/v1/compliance/digest",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				assert.Contains(t, m, "title")
			},
		},
		{
			name: "#255 legal-hold status",
			path: "/api/v1/legal-hold",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				assert.Contains(t, m, "active")
			},
		},
		{
			name: "#255 risk-exceptions (bundled MED free-text sub-finding)",
			path: "/api/v1/risk-exceptions",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				exceptions, _ := m["exceptions"].([]any)
				assert.NotEmpty(t, exceptions, "the seeded risk exception must be disclosed to an audit.read holder")
			},
		},
		{
			name: "#255 sod violations",
			path: "/api/v1/sod/violations",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				violations, _ := m["violations"].([]any)
				assert.NotEmpty(t, violations, "the system_auditor's own system.read+audit.read pair must show up as a violation")
			},
		},
		{
			// admin/usage: per-project secret counts + read activity, deployment-wide,
			// with no per-project ownership check anywhere in the call chain — the
			// confirmed HIGH bug this campaign's fix addresses (7th+ instance of the
			// same system.read-as-sole-gate mistake). See admin_usage.go's header
			// comment and server/http/permission_sweep_test.go's exhaustiveness guard.
			name: "admin usage report",
			path: "/api/v1/admin/usage",
			check: func(t *testing.T, body []byte, _ string) {
				m := jsonDataField(t, body)
				projects, ok := m["projects"].([]any)
				require.True(t, ok, "projects field must be a list")
				found := false
				for _, p := range projects {
					proj, _ := p.(map[string]any)
					if proj == nil {
						continue
					}
					if id, _ := proj["project_id"].(float64); uint(id) == fixtures.projectID {
						found = true
						assert.GreaterOrEqual(t, proj["secret_count"], float64(1),
							"the seeded canary secret must be counted for its project")
					}
				}
				assert.True(t, found, "the seeded project must appear in the usage report for an audit.read holder")
			},
		},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, rt := range routes {
		t.Run(rt.name+"/baseline_denied", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL+rt.path, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+baselineToken)
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equalf(t, http.StatusForbidden, resp.StatusCode,
				"a system_viewer-baseline (system.read only) caller must be denied at %s", rt.path)
		})

		t.Run(rt.name+"/auditor_allowed", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL+rt.path, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+auditorToken)
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			body := make([]byte, 0, 4096)
			buf := make([]byte, 4096)
			for {
				n, rerr := resp.Body.Read(buf)
				body = append(body, buf[:n]...)
				if rerr != nil {
					break
				}
			}
			require.Equalf(t, http.StatusOK, resp.StatusCode,
				"a system_auditor (audit.read) caller must succeed at %s (body: %s)", rt.path, string(body))
			rt.check(t, body, resp.Header.Get("Content-Type"))
		})
	}
}

// TestDashboardStats_PermissionTiers covers #272 — the worst instance of the family:
// GET /dashboard/stats and GET /dashboard/activity required NO permission at all. It
// proves: (a) a principal with NO relevant permission whatsoever is now denied
// (previously it would have succeeded); (b) a baseline system_viewer caller still gets
// their own personal dashboard (200) but with the deployment-wide aggregate fields
// zeroed and the activity feed limited to their own events; (c) an audit.read holder
// gets the full deployment-wide picture.
func TestDashboardStats_PermissionTiers(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	createTestToken(t, testCore)
	// Tokens created BEFORE seedFamilyFixtures — see the identical comment in
	// TestDeploymentDisclosureFamily_BaselineDeniedAuditorAllowed above (#419: the
	// grant-time SoD preventive gate would otherwise block minting system_auditor
	// after the fixture's SoD policy already exists).
	noPermToken := createNoPermissionToken(t, testCore)
	baselineToken := createLimitedToken(t, testCore)
	auditorToken := createAuditorToken(t, testCore)
	seedFamilyFixtures(t, testCore)

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(token, path string) (*http.Response, []byte) {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var body []byte
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			body = append(body, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		return resp, body
	}

	t.Run("no_permission_at_all_denied_stats", func(t *testing.T) {
		resp, _ := get(noPermToken, "/api/v1/dashboard/stats")
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"a principal holding NO permission at all must now be denied — previously this route checked nothing")
	})

	t.Run("no_permission_at_all_denied_activity", func(t *testing.T) {
		resp, _ := get(noPermToken, "/api/v1/dashboard/activity")
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("baseline_gets_own_dashboard_with_aggregates_zeroed", func(t *testing.T) {
		resp, body := get(baselineToken, "/api/v1/dashboard/stats")
		require.Equal(t, http.StatusOK, resp.StatusCode, "the caller's own home dashboard must still work")
		m := jsonDataField(t, body)
		assert.Equal(t, float64(0), m["activeUsers"],
			"a baseline (non-audit.read) caller must not see the deployment-wide active-user count")
		assert.Equal(t, float64(0), m["auditEvents30d"])
		assert.Equal(t, float64(0), m["inactiveUsers"])
	})

	t.Run("baseline_activity_feed_denied", func(t *testing.T) {
		resp, _ := get(baselineToken, "/api/v1/dashboard/activity")
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"the full org-wide activity feed stays behind audit.read even for a baseline caller")
	})

	t.Run("auditor_sees_full_deployment_aggregates", func(t *testing.T) {
		resp, body := get(auditorToken, "/api/v1/dashboard/stats")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		m := jsonDataField(t, body)
		activeUsers, _ := m["activeUsers"].(float64)
		assert.Greater(t, activeUsers, float64(0),
			"an audit.read holder must see the real deployment-wide active-user count")
	})

	t.Run("auditor_activity_feed_allowed", func(t *testing.T) {
		resp, body := get(auditorToken, "/api/v1/dashboard/activity")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		m := jsonDataField(t, body)
		assert.Contains(t, m, "items")
	})
}

// grantBillingLicense issues and installs a short-lived, self-signed "billing"-feature
// license on c, mirroring server/http/handlers/admin_billing_test.go's
// licensedBillingCore — GET /admin/billing/report 403s before ever reaching the
// audit.read check if the deployment has no billing license, so the permission-tier
// test below needs one installed to exercise the actual authz gate rather than the
// license gate.
func grantBillingLicense(t *testing.T, c *core.KeyorixCore) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-2026", pub))
	token, err := license.Issue(license.License{
		Licensee: "family-test GmbH", Plan: "enterprise",
		Features: []string{license.FeatureBilling},
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyID: "license-2026",
	}, priv)
	require.NoError(t, err)
	c.SetLicenseGate(license.NewGate(token, reg, "", 0))
}

// TestAdminBillingReport_PermissionTiers is the admin/billing/report half of the
// admin_usage.go fix (same disclosure-family bug, same fix shape, split out only
// because it needs a licensed deployment to reach the authz check at all — see
// grantBillingLicense above). Proves: a system_viewer-baseline (system.read only)
// caller is denied (403) and an audit.read holder (system_auditor) succeeds (200) with
// the seeded project's real billing figures, not a zeroed/redacted stand-in.
func TestAdminBillingReport_PermissionTiers(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	testCore := newFullSchemaTestCore(t)
	grantBillingLicense(t, testCore)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	createTestToken(t, testCore)
	baselineToken := createLimitedToken(t, testCore) // system_viewer only (system.read)
	auditorToken := createAuditorToken(t, testCore)  // system_auditor (audit.read, global)
	fixtures := seedFamilyFixtures(t, testCore)

	from := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	path := "/api/v1/admin/billing/report?from=" + from + "&to=" + to

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(token string) (*http.Response, []byte) {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var body []byte
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			body = append(body, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		return resp, body
	}

	t.Run("baseline_denied", func(t *testing.T) {
		resp, _ := get(baselineToken)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"a system_viewer-baseline (system.read only) caller must be denied at /admin/billing/report")
	})

	t.Run("auditor_allowed", func(t *testing.T) {
		resp, body := get(auditorToken)
		require.Equalf(t, http.StatusOK, resp.StatusCode,
			"a system_auditor (audit.read) caller must succeed at /admin/billing/report (body: %s)", string(body))
		m := jsonDataField(t, body)
		projects, ok := m["projects"].([]any)
		require.True(t, ok, "projects field must be a list")
		found := false
		for _, p := range projects {
			proj, _ := p.(map[string]any)
			if proj == nil {
				continue
			}
			if id, _ := proj["project_id"].(float64); uint(id) == fixtures.projectID {
				found = true
				assert.GreaterOrEqual(t, proj["secret_count"], float64(1),
					"the seeded canary secret must be counted for its project")
			}
		}
		assert.True(t, found, "the seeded project must appear in the billing report for an audit.read holder")
	})
}
