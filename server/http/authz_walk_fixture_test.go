// authz_walk_fixture_test.go — shared fixture for the route-wide authorization
// walks (AUTHZ-WALKS-HTTP-1): write_routes_deny_walk_test.go and
// dead_credentials_walk_test.go.
//
// # What it builds
//
// Production-shaped storage (newSVWorld: the real factory, so the read-path caches
// are live), SQLite always and Postgres when KEYORIX_TEST_PG_DSN is set. One
// "canary" project owns the objects a denied caller must not be able to touch (a
// secret with two versions, a share, an ACL grant, a group, a role, a victim user
// with a PAT and a session, a machine identity with a token and an OIDC binding, a
// pending invitation, a secret access request); a "decoy" project is where the
// restricted PATs are confined to.
//
// # Route shapes the walks recognise and skip
//
// Both walks enumerate with chi.Walk over NewRouter. Only the shapes below are
// treated specially; every other route is walked.
//
//   - Methods the router registers for /metrics other than GET (CONNECT, OPTIONS,
//     TRACE, QUERY, ...) and HEAD: chi expands one Handle() to every method; they
//     are one handler, the metrics scrape, not API routes.
//   - Static assets (/assets/*, /static/*, /favicon.ico, /manifest.json, /sw.js,
//     /status, /status-es): file serving, no principal.
//   - SCIM (/scim/v2/*): authenticated by a static operator bearer token, not by
//     sessions/PATs/machine tokens; only registered when cfg.SCIM.Enabled.
//   - Multipart and websocket routes: the router has none today
//     (awAssertNoUnrecognisedShapes fails if a handler starts using multipart).
//
// Public routes (login, MFA/WebAuthn second step, refresh, password reset, setup,
// SSO/SAML, system/init, health, readyz, version) are the explicit
// awPublicRoutes allowlist: they take no session/PAT/machine credential, so a dead
// credential and a low-privilege one are the same as no credential there.
package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// awPublicRoutes are routes that carry no session/PAT/machine credential by design.
// "METHOD /path" -> why. Anything not in /api/v1 and not listed here fails the walks
// (awClassify), so a new unauthenticated route has to be classified on purpose.
var awPublicRoutes = map[string]string{
	"POST /auth/login":                        "login: the credential is the password",
	"POST /auth/logout":                       "logout: accepts a session/cookie, answers 401 for a dead one (INV-HTTP-17)",
	"POST /auth/refresh":                      "refresh: the credential is the refresh token",
	"POST /auth/password-reset":               "password reset request",
	"POST /auth/mfa/verify":                   "MFA second step: the bearer is a single-use challenge",
	"POST /auth/webauthn/login/begin":         "WebAuthn second step (challenge bearer)",
	"POST /auth/webauthn/login/finish":        "WebAuthn second step (challenge bearer)",
	"POST /auth/webauthn/passwordless/begin":  "passwordless passkey login",
	"POST /auth/webauthn/passwordless/finish": "passwordless passkey login",
	"POST /system/init":                       "first-run bootstrap (bootstrap token)",
	"GET /auth/setup/{token}":                 "credential-delivery link: the bearer is the setup token",
	"POST /auth/setup/consume":                "credential-delivery link: the bearer is the setup token",
	"GET /auth/sso/providers":                 "login page provider list",
	"GET /auth/sso/{provider}/login":          "SSO redirect",
	"GET /auth/sso/{provider}/callback":       "SSO IdP callback",
	"GET /auth/saml/{provider}/metadata":      "SAML SP metadata",
	"GET /auth/saml/{provider}/login":         "SAML redirect",
	"POST /auth/saml/{provider}/acs":          "SAML assertion consumer",
	"GET /health":                             "liveness probe",
	"GET /readyz":                             "readiness probe",
	"GET /api/v1/version":                     "version-skew probe, registered outside the authenticated group",
	"GET /metrics":                            "Prometheus scrape (its own metrics_token)",
	"GET /status":                             "status page",
	"GET /status-es":                          "status page",
	"GET /favicon.ico":                        "static",
	"GET /manifest.json":                      "static",
	"GET /sw.js":                              "static",
	"GET /assets/*":                           "static",
	"GET /static/*":                           "static",
}

// awSkipped reports whether a route is one of the non-API shapes the header says
// the walks skip (chi's per-method expansion of /metrics, HEAD twins of static files).
func awSkipped(method, route string) bool {
	if route == "/metrics" && method != http.MethodGet {
		return true
	}
	if method == http.MethodHead {
		return true
	}
	return strings.HasPrefix(route, "/scim/v2")
}

type awRoute struct{ Method, Path string }

func (r awRoute) key() string { return r.Method + " " + r.Path }

// awWalkRoutes enumerates every route of the real router.
func awWalkRoutes(t *testing.T, router http.Handler) []awRoute {
	t.Helper()
	routes, ok := router.(chi.Routes)
	require.True(t, ok, "router must expose chi.Routes for walking")
	var out []awRoute
	require.NoError(t, chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if awSkipped(method, route) {
			return nil
		}
		out = append(out, awRoute{method, route})
		return nil
	}))
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// awClassify returns "public" for an allowlisted unauthenticated route, "api" for
// the authenticated /api/v1 surface, and fails the test for anything else: a route
// outside /api/v1 that nobody classified.
func awClassify(t *testing.T, r awRoute) string {
	t.Helper()
	if _, ok := awPublicRoutes[r.key()]; ok {
		return "public"
	}
	if strings.HasPrefix(r.Path, "/api/v1/") {
		return "api"
	}
	t.Errorf("route %s is neither under /api/v1 nor in awPublicRoutes: classify it (public + reason) so the walks know whether it takes a credential", r.key())
	return "unclassified"
}

var awParamRe = regexp.MustCompile(`\{([^}]+)\}`)

// awWorld is the canary fixture.
type awWorld struct {
	*svWorld
	decoyPID, decoyEID uint
	ids                map[string]uint // kind -> canary id
	tokens             map[string]string
	userIDs            map[string]uint // persona -> user id (for owner checks)
	missing            []string        // seeds that failed (logged, tripwired)
	patSpecs           map[string]awPATSpec
}

// awPATSpec is how a restricted PAT persona is minted (and re-minted by revive).
type awPATSpec struct {
	scopes   []string
	pid, eid uint
}

func (w *awWorld) must(t *testing.T, what string, err error) bool {
	t.Helper()
	if err != nil {
		w.missing = append(w.missing, fmt.Sprintf("%s: %v", what, err))
		return false
	}
	return true
}

func newAWWorld(t *testing.T, backend string, replicas int) *awWorld {
	t.Helper()
	sw := newSVWorld(t, backend, replicas)
	c, db, ctx := sw.a.c, sw.a.db, context.Background()
	w := &awWorld{svWorld: sw, ids: map[string]uint{}, tokens: map[string]string{}, userIDs: map[string]uint{}, patSpecs: map[string]awPATSpec{}}
	w.ids["project"], w.ids["env"] = sw.projID, sw.envID
	w.tokens["admin"] = sw.tokens["human"]
	w.userIDs["admin"] = sw.adminID

	decoy, err := c.CreateProject(ctx, "awdecoy", "")
	require.NoError(t, err)
	w.decoyPID = decoy.ID
	var denv models.Environment
	if db.Where("project_id = ? AND name = ?", decoy.ID, "prod").First(&denv).Error != nil {
		denv = models.Environment{Name: "prod", ProjectID: decoy.ID}
		require.NoError(t, db.Create(&denv).Error)
	}
	w.decoyEID = denv.ID

	// Restricted PATs: the global admin's own, narrowed. Each is denied the canary
	// project by a different dimension of PATRestriction.
	for name, spec := range map[string]awPATSpec{
		"pat_decoy_project":   {nil, decoy.ID, 0},
		"pat_decoy_env":       {nil, decoy.ID, denv.ID},
		"pat_users_read_only": {[]string{"users.read"}, 0, 0},
	} {
		res, perr := c.CreateOwnPAT(ctx, sw.adminID, name, nil, spec.scopes, spec.pid, spec.eid, nil)
		require.NoError(t, perr)
		w.tokens[name] = res.PlainToken
		w.patSpecs[name] = spec
	}

	// Zero-grant machine token: an identity in the canary project with NO role.
	zero, err := c.CreateMachineIdentity(ctx, sw.projID, "aw-zero-bot", "service", "", "", sw.adminID, 0)
	require.NoError(t, err)
	zt, err := c.IssueMachineToken(ctx, sw.projID, zero.ID, sw.adminID, core.IssueMachineTokenParams{Name: "aw-zero"})
	require.NoError(t, err)
	w.tokens["machine_zero"] = zt.PlainToken

	// Viewer: a plain user (system_viewer baseline only), and a project viewer of the
	// canary project.
	for _, v := range []struct{ name, role string }{{"awviewer", ""}, {"awprojviewer", "viewer"}} {
		u, uerr := c.CreateUser(ctx, &core.CreateUserRequest{Username: v.name, Email: v.name + "@x.io", Password: svPassword})
		require.NoError(t, uerr)
		if v.role != "" {
			require.NoError(t, c.AddProjectMember(ctx, sw.adminID, sw.projID, u.ID, v.role, false))
		}
		sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: v.name, Password: svPassword})
		require.NoError(t, lerr)
		w.tokens[v.name] = sess.SessionToken
		w.userIDs[v.name] = u.ID
	}

	// Canary objects.
	victim, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "awvictim", Email: "awvictim@x.io", Password: svPassword})
	require.NoError(t, err)
	w.ids["user"] = victim.ID
	w.userIDs["victim"] = victim.ID
	w.must(t, "victim project member", c.AddProjectMember(ctx, sw.adminID, sw.projID, victim.ID, "viewer", false))
	if vs, _, lerr := c.Login(ctx, &core.LoginRequest{Username: "awvictim", Password: svPassword}); w.must(t, "victim login", lerr) {
		var s models.Session
		if w.must(t, "victim session row", db.Where("user_id = ?", victim.ID).First(&s).Error) {
			w.ids["session"] = s.ID
		}
		_ = vs
	}
	if pat, perr := c.CreateOwnPAT(ctx, victim.ID, "victim-pat", nil, nil, 0, 0, nil); w.must(t, "victim pat", perr) {
		w.ids["pat"] = pat.Token.ID
	}

	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "awcanary-secret", Value: []byte("v1"), ProjectID: sw.projID, EnvironmentID: sw.envID,
		Type: "password", CreatedBy: "svadmin", OwnerID: sw.adminID,
	})
	require.NoError(t, err)
	w.ids["secret"] = sec.ID
	other, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "awcanary-other", Value: []byte("v1"), ProjectID: sw.projID, EnvironmentID: sw.envID,
		Type: "password", CreatedBy: "svadmin", OwnerID: sw.adminID,
	})
	require.NoError(t, err)
	w.ids["secret2"] = other.ID
	if _, uerr := c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: sec.ID, Value: []byte("v2"), UpdatedBy: "svadmin"}); w.must(t, "secret v2", uerr) {
		var v models.SecretVersion
		if w.must(t, "version row", db.Where("secret_node_id = ?", sec.ID).Order("id").First(&v).Error) {
			w.ids["version"] = v.ID
		}
	}
	w.must(t, "admin project member", c.AddProjectMember(ctx, sw.adminID, sw.projID, sw.adminID, "project_admin", false))
	if sh, serr := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: sec.ID, RecipientID: victim.ID, Permission: "read", SharedBy: sw.adminID}); w.must(t, "share", serr) {
		w.ids["share"] = sh.ID
	}
	w.must(t, "acl", c.GrantSecretACL(ctx, sw.adminID, other.ID, victim.ID, []string{"secrets.read"}))
	var acl models.SecretACL
	if db.Where("secret_id = ?", other.ID).First(&acl).Error == nil {
		w.ids["acl"] = acl.ID
	}
	if dep, derr := c.AddSecretDependency(ctx, "user", sw.adminID, sec.ID, other.ID, "aw", 0); w.must(t, "dependency", derr) {
		w.ids["dep"] = dep.ID
	}
	if g, gerr := c.CreateGroup(ctx, sw.adminID, &core.CreateGroupRequest{Name: "awcanary-group"}); w.must(t, "group", gerr) {
		w.ids["group"] = g.ID
	}
	if r, _, rerr := c.CreateRole(ctx, sw.adminID, "awcanary-role", "aw", nil); w.must(t, "role", rerr) {
		w.ids["role"] = r.ID
	}
	var perm models.Permission
	if db.Where("name = ?", "secrets.read").First(&perm).Error == nil {
		w.ids["permission"] = perm.ID
	}
	bot, err := c.CreateMachineIdentity(ctx, sw.projID, "aw-canary-bot", "service", "", "", sw.adminID, 0)
	require.NoError(t, err)
	w.ids["machine"] = bot.ID
	if bt, terr := c.IssueMachineToken(ctx, sw.projID, bot.ID, sw.adminID, core.IssueMachineTokenParams{Name: "aw-canary"}); w.must(t, "canary machine token", terr) {
		var cred models.MachineIdentityCredential
		if w.must(t, "cred row", db.Where("token_hash = ?", cgSHA256Hex(bt.PlainToken)).First(&cred).Error) {
			w.ids["cred"] = cred.ID
		}
	}
	if b, berr := c.CreateOIDCBinding(ctx, sw.projID, bot.ID, "https://issuer.example.com", "repo:aw/canary", sw.adminID); w.must(t, "oidc binding", berr) {
		w.ids["binding"] = b.ID
	}
	if inv, ierr := c.InviteToProject(ctx, sw.projID, "awinvitee@x.io", "viewer", sw.adminID, 0); w.must(t, "invitation", ierr) {
		w.ids["invitation"] = inv.ID
	}
	if ar, aerr := c.RequestSecretAccess(ctx, sec.ID, w.userIDs["awviewer"], "aw canary request"); w.must(t, "secret access request", aerr) {
		w.ids["accessreq"] = ar.ID
	}
	if len(w.missing) > 0 {
		t.Logf("fixture seeds that failed (their id falls back to the uniform pool): %s", strings.Join(w.missing, "; "))
	}
	return w
}

// awKindOfParam maps a path parameter to the kind of canary object it names, so a
// typed binding reaches the REAL object (ids of different kinds collide numerically
// in a fresh database, so a uniform binding alone mostly exercises id 1..N of the
// wrong table). "" = no typed mapping: the uniform pool covers it.
func awKindOfParam(route, param string) string {
	switch param {
	case "envId":
		return "env"
	case "versionId", "from", "to":
		return "version"
	case "userId":
		return "user"
	case "roleId":
		return "role"
	case "permissionId":
		return "permission"
	case "machineId":
		return "machine"
	case "tokenId":
		return "cred"
	case "bindingId":
		return "binding"
	case "invitationId":
		return "invitation"
	case "aclId":
		return "acl"
	case "depId":
		return "dep"
	case "projectId":
		return "project"
	case "requestId":
		if strings.HasPrefix(route, "/api/v1/secret-access-requests") {
			return "accessreq"
		}
		return ""
	case "id":
		segs := strings.Split(route, "/")
		for i, s := range segs {
			if s == "{id}" && i > 0 {
				switch segs[i-1] {
				case "projects":
					return "project"
				case "environments":
					return "env"
				case "secrets":
					return "secret"
				case "shares":
					return "share"
				case "users":
					return "user"
				case "groups":
					return "group"
				case "roles":
					return "role"
				case "permissions":
					return "permission"
				case "sessions":
					return "session"
				case "tokens":
					return "pat"
				}
			}
		}
	}
	return ""
}

// awPaths returns the concrete request paths for a route: the typed binding plus a
// uniform binding of every param to each canary id (and one id that exists nowhere).
func (w *awWorld) awPaths(route string) []string {
	if !awParamRe.MatchString(route) {
		return []string{route}
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	typed := awParamRe.ReplaceAllStringFunc(route, func(m string) string {
		p := m[1 : len(m)-1]
		if id := w.ids[awKindOfParam(route, p)]; id != 0 {
			return fmt.Sprint(id)
		}
		return "999999"
	})
	add(typed)
	// The decoy project/environment are where the restricted PATs ARE allowed to act;
	// a canary id that happens to equal their numeric id must not be bound.
	pool := map[uint]bool{999999: true}
	for _, id := range w.ids {
		if id != w.decoyPID && id != w.decoyEID {
			pool[id] = true
		}
	}
	var uni []uint
	for id := range pool {
		uni = append(uni, id)
	}
	sort.Slice(uni, func(i, j int) bool { return uni[i] < uni[j] })
	for _, id := range uni {
		add(awParamRe.ReplaceAllString(route, fmt.Sprint(id)))
	}
	// Path params that are not numeric ids (names, refs, tokens): any value works.
	for i, p := range out {
		out[i] = strings.NewReplacer("{name}", "awcanary", "{provider}", "x", "{token}", "x").Replace(p)
	}
	return out
}

// awBody is the "minimal valid-looking" body: the union of the field names the
// mutating handlers read, filled with canary ids. Handlers ignore unknown fields
// (none uses DisallowUnknownFields), so one body shape reaches the authorization
// step of every route instead of dying in validation first.
func (w *awWorld) awBody() []byte { return w.awBodyN(0) }

// awBodyN is awBody with names/emails made unique by n, so a repeated admin call is
// not refused as a duplicate (the control run).
func (w *awWorld) awBodyN(n int) []byte {
	nm := fmt.Sprintf("awprobe%d", n)
	b, _ := json.Marshal(map[string]any{
		"name": nm, "description": "awprobe", "title": nm, "reason": "awprobe", "justification": "awprobe",
		"email": nm + "@x.io", "username": nm, "display_name": nm, "password": svPassword,
		"current_password": svPassword, "new_password": svPassword,
		"role": "project_admin", "role_name": "project_admin", "action": "approve", "type": "password", "value": "awprobe-value",
		"category": "other", "classification": "internal", "status": "active", "enabled": true,
		"project_id": w.ids["project"], "environment_id": w.ids["env"], "secret_id": w.ids["secret"],
		"user_id": w.ids["user"], "role_id": w.ids["role"], "group_id": w.ids["group"], "recipient_id": w.ids["user"],
		"permission_id": w.ids["permission"], "permission_ids": []uint{w.ids["permission"]},
		"user_ids": []uint{w.ids["user"]}, "secret_ids": []uint{w.ids["secret"], w.ids["secret2"]},
		"ids": []uint{w.ids["secret"]}, "request_ids": []uint{w.ids["accessreq"]},
		"new_owner_id": w.ids["user"], "owner_id": w.ids["user"], "target_project_id": w.ids["project"],
		"target_environment_id": w.ids["env"], "to_version": 1, "version_id": w.ids["version"],
		"permission": "read", "permissions": []string{"secrets.read"}, "scopes": []string{"secrets.read"},
		"issuer": "https://issuer.example.com", "subject": "repo:aw/probe",
		"expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339), "days": 30,
	})
	return b
}

// awDo performs one request against a replica's router without a network hop.
func awDo(r *svReplica, method, token, path string, body []byte) (int, string) {
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// ---- state digest ----------------------------------------------------------

// awNoiseTables are excluded from the digest: they change on every request by
// design (rate limiting, login throttling, sqlite bookkeeping, access-log rows the
// auth path writes) and carry no authorization state. audit_events is compared
// separately (denials only); pending_audit_events is the audit flusher's buffer.
var awNoiseTables = map[string]bool{
	"sqlite_sequence": true, "rate_limits": true, "login_attempts": true, "scheduler_lock_leases": true,
	"api_call_logs": true, "pending_audit_events": true, "audit_events": true, "audit_checkpoints": true,
}

// awNoiseColumns are touched by authentication itself (throttled last-seen stamps).
var awNoiseColumns = map[string]bool{"last_seen_at": true, "last_used_at": true}

type awRow struct {
	hash string
	vals map[string]any
}

type awDigest struct {
	tables map[string][]awRow
	audit  map[uint]models.AuditEvent
}

func awTables(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	all, err := db.Migrator().GetTables()
	require.NoError(t, err)
	var out []string
	for _, tb := range all {
		if !awNoiseTables[tb] {
			out = append(out, tb)
		}
	}
	sort.Strings(out)
	return out
}

func awTakeDigest(t *testing.T, db *gorm.DB, tables []string) *awDigest {
	t.Helper()
	d := &awDigest{tables: map[string][]awRow{}, audit: map[uint]models.AuditEvent{}}
	for _, tb := range tables {
		var rows []map[string]any
		require.NoError(t, db.Table(tb).Find(&rows).Error, tb)
		out := make([]awRow, 0, len(rows))
		for _, r := range rows {
			keys := make([]string, 0, len(r))
			for k := range r {
				if !awNoiseColumns[k] {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			h := sha256.New()
			for _, k := range keys {
				fmt.Fprintf(h, "%s=%v\x00", k, r[k])
			}
			out = append(out, awRow{hash: hex.EncodeToString(h.Sum(nil)), vals: r})
		}
		d.tables[tb] = out
	}
	var evs []models.AuditEvent
	require.NoError(t, db.Find(&evs).Error)
	for _, e := range evs {
		d.audit[e.ID] = e
	}
	return d
}

// awOwned reports whether a changed row belongs to the caller (an allowlisted
// self-service route may change the caller's own rows and nobody else's).
func awOwned(table string, vals map[string]any, callerID uint) bool {
	if callerID == 0 {
		return false
	}
	num := func(v any) uint {
		switch x := v.(type) {
		case int64:
			return uint(x) // #nosec G115 -- ids are small
		case uint:
			return x
		case int:
			return uint(x) // #nosec G115 -- ids are small
		case uint64:
			return uint(x) // #nosec G115 -- ids are small
		case int32:
			return uint(x) // #nosec G115 -- ids are small
		}
		return 0
	}
	if table == "users" {
		return num(vals["id"]) == callerID
	}
	for _, col := range []string{"user_id", "requester_id", "owner_id"} {
		if v, ok := vals[col]; ok && num(v) == callerID {
			return true
		}
	}
	return false
}

// awIsDenialEvent: an audit row a refused request may legitimately add.
func awIsDenialEvent(e models.AuditEvent) bool {
	if e.Success != nil && !*e.Success {
		return true
	}
	et := strings.ToLower(e.EventType)
	return strings.Contains(et, "denied") || strings.Contains(et, "forbidden") || strings.Contains(et, "failed") || strings.Contains(et, "rejected")
}

// awDiff lists what changed between two digests. callerID != 0 exempts rows owned
// by that caller (only used for allowlisted self-service routes).
func awDiff(before, after *awDigest, callerID uint, sideTables ...string) []string {
	side := map[string]bool{}
	for _, tb := range sideTables {
		side[tb] = true
	}
	var out []string
	for tb, arows := range after.tables {
		if side[tb] {
			continue
		}
		brows := before.tables[tb]
		count := map[string]int{}
		for _, r := range brows {
			count[r.hash]++
		}
		for _, r := range arows {
			if count[r.hash] > 0 {
				count[r.hash]--
				continue
			}
			if awOwned(tb, r.vals, callerID) {
				continue
			}
			out = append(out, fmt.Sprintf("%s: row added/changed %v", tb, awBrief(r.vals)))
		}
		count = map[string]int{}
		for _, r := range arows {
			count[r.hash]++
		}
		for _, r := range brows {
			if count[r.hash] > 0 {
				count[r.hash]--
				continue
			}
			if awOwned(tb, r.vals, callerID) {
				continue
			}
			out = append(out, fmt.Sprintf("%s: row removed/changed %v", tb, awBrief(r.vals)))
		}
	}
	for id, e := range after.audit {
		if _, ok := before.audit[id]; ok {
			continue
		}
		if callerID != 0 && e.UserID != nil && *e.UserID == callerID {
			continue // the caller's own audited self-service action
		}
		if !awIsDenialEvent(e) {
			out = append(out, fmt.Sprintf("audit_events: non-denial event added %q", e.EventType))
		}
	}
	for id := range before.audit {
		if _, ok := after.audit[id]; !ok {
			out = append(out, "audit_events: event removed")
		}
	}
	sort.Strings(out)
	return out
}

func awBrief(vals map[string]any) string {
	var parts []string
	for _, k := range []string{"id", "name", "username", "event_type", "state", "user_id", "secret_node_id", "project_id"} {
		if v, ok := vals[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}
