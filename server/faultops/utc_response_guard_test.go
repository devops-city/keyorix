package faultops

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // Etc/GMT-2 must resolve on hosts without a system zoneinfo

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// API timestamps are UTC (docs/API_REFERENCE.md, "Timestamps"). This file is the
// runtime half of that claim's guard: it builds one real world (faultops'
// newFaultWorld: real router, real storage, bootstrapped admin), seeds it by
// running every op in opCatalog (Setup then Execute, fault-free), forces the
// process zone to a non-UTC offset so a time that is not converted shows up with
// that offset, then drives EVERY GET route the router serves and fails on any
// RFC 3339 timestamp that does not end in "Z".
//
// What it checks: JSON string values anywhere in a response body, and CSV cells.
// What it does not: a route listed in utcGuardSkippedRoutes (each with a reason),
// a time field the seeded world never populates (an empty list returns no
// timestamps: TestUTCResponseGuard reports, per route, how many it saw, and the
// structural guards in utc_response_structural_guard_test.go cover types and
// encoders independent of data), and non-RFC 3339 renderings (Unix seconds, a
// date-only "2006-01-02"), which carry no zone to get wrong.

// utcGuardZone is the zone the process runs in during the guard. Any fixed
// non-zero offset works; +02:00 matches the zone #2951 was reported from.
var utcGuardZone = time.FixedZone("UTC+2", 2*60*60)

// rfc3339Re matches an RFC 3339 date-time with its zone designator.
var rfc3339Re = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(Z|z|[+-]\d{2}:\d{2})\b`)

// utcGuardSkippedRoutes are GET routes the runtime guard does not drive, with the
// reason. A key that no longer exists in the router fails the guard (stale skip).
var utcGuardSkippedRoutes = map[string]string{
	"/assets/*":                        "web UI bundle (not built into the test binary); static files",
	"/static/*":                        "web UI bundle; static files",
	"/favicon.ico":                     "web UI bundle; static file",
	"/manifest.json":                   "web UI bundle; static file",
	"/sw.js":                           "web UI bundle; static file",
	"/auth/sso/{provider}/login":       "redirects to an external IdP; no response body",
	"/auth/sso/{provider}/callback":    "needs an IdP authorization code; error path only",
	"/auth/saml/{provider}/login":      "redirects to the IdP with a SAML AuthnRequest; no JSON body",
	"/auth/setup/{token}":              "needs a single-use setup token minted for a new user; covered by the user-invitation journey",
	"/api/v1/secrets/value":            "returns a secret value, no metadata times",
	"/api/v1/admin/billing/report":     "needs the 'billing' license feature (403 unlicensed); the guard world runs without a license",
	"/api/v1/secrets/{id}/certificate": "needs a PEM certificate secret; the guard world seeds none",
}

// utcGuardFreeText reports whether a value is free text or stored record
// content rather than an API time field, so a date-time INSIDE it is data, not a
// zone the API chose:
//   - "description" (any route, JSON or CSV column): free text. Audit event
//     descriptions are part of the hash-chained record (ADR-029) and are never
//     rewritten; some writers embed a local-zone time in them (reported, not
//     fixed here: changing what a writer stores is out of this guard's scope).
//   - anything under an audit "diff": the stored, hash-covered before/after
//     JSON of a mutation.
//
// Timestamps found there are still counted in the inventory, just not failed.
func utcGuardFreeText(where string) bool {
	if where == "csv.description" || strings.HasSuffix(where, ".description") {
		return true
	}
	return strings.HasSuffix(where, ".diff") || strings.Contains(where, ".diff.")
}

// utcGuardFinding is one non-UTC timestamp found in a response.
type utcGuardFinding struct {
	Route string
	Where string
	Value string
}

// utcGuardRouteResult is what the guard saw for one route.
type utcGuardRouteResult struct {
	Route      string
	Path       string
	Status     int
	Timestamps int
	Fields     map[string]bool // JSON paths (array indexes as []) that held a timestamp
}

// utcGuardChildEnv marks the re-executed test process that runs the guard under
// a non-UTC process zone.
const utcGuardChildEnv = "KEYORIX_UTC_GUARD_CHILD"

// utcGuardChildTZ is the TZ the child runs under: "Etc/GMT-2" is UTC+02:00
// (the sign is inverted in the tz database), same offset as utcGuardZone.
const utcGuardChildTZ = "Etc/GMT-2"

// TestUTCResponseGuard runs the guard in a child process whose zone is set from
// the TZ environment variable at startup. It does not assign time.Local: that
// is a package-level variable read, unsynchronised, by every goroutine that
// calls time.Now (net/http connection goroutines, gRPC, the world's
// background workers), so writing it, and restoring it in a Cleanup, raced
// with whichever of them was still winding down.
func TestUTCResponseGuard(t *testing.T) {
	if os.Getenv(utcGuardChildEnv) != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestUTCResponseGuard$", "-test.v")
		cmd.Env = append(os.Environ(), utcGuardChildEnv+"=1", "TZ="+utcGuardChildTZ)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("guard child failed: %v\n%s", err, out)
		}
		t.Logf("guard child output:\n%s", out)
		return
	}
	if _, off := time.Now().Zone(); off != 2*60*60 {
		t.Fatalf("child process zone offset is %ds, want +7200s: the guard would not see an unconverted time", off)
	}

	w := newFaultWorld(t, nil)
	// Encryption first, as in production: ops that need it would otherwise turn
	// it on midway and leave earlier rows (e.g. notification channel URLs)
	// unreadable, which is a fixture artefact, not something to sweep.
	if err := w.ensureEncryption(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	seedUTCGuardWorld(ctx, t, w)

	routes := utcGuardGETRoutes(t, w)
	var findings []utcGuardFinding
	var results []utcGuardRouteResult
	for _, route := range routes {
		if _, skip := utcGuardSkippedRoutes[route]; skip {
			continue
		}
		path, ok := resolveUTCGuardPath(t, w.db, route)
		if !ok {
			findings = append(findings, utcGuardFinding{Route: route, Where: "path", Value: "no concrete path: add a resolver or a skip with a reason"})
			continue
		}
		res, fs := driveUTCGuardRoute(ctx, t, w, route, path)
		results = append(results, res)
		findings = append(findings, fs...)
	}

	for route := range utcGuardSkippedRoutes {
		if !containsString(routes, route) {
			t.Errorf("utcGuardSkippedRoutes has %q, which the router no longer serves: remove it", route)
		}
	}

	grpcInventory, grpcFindings := driveUTCGuardGRPC(ctx, t, w)
	findings = append(findings, grpcFindings...)
	for _, line := range grpcInventory {
		t.Logf("INVENTORY %s", line)
	}

	total := 0
	for _, r := range results {
		total += r.Timestamps
		fields := make([]string, 0, len(r.Fields))
		for f := range r.Fields {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		t.Logf("INVENTORY %s -> %s status=%d timestamps=%d fields=%s", r.Route, r.Path, r.Status, r.Timestamps, strings.Join(fields, ","))
	}
	if total < 50 {
		t.Errorf("the guard saw only %d timestamps across %d routes: the seed no longer populates the world, so a green run proves nothing", total, len(results))
	}
	for _, f := range findings {
		t.Errorf("NON-UTC %s %s: %s", f.Route, f.Where, f.Value)
	}
}

// seedUTCGuardWorld runs every op's Setup and Execute once, in catalog order,
// against w, so the GETs have rows to return. Failures are expected (an op that
// needs an earlier op's state, a deliberate denial) and ignored: this is seeding,
// not an oracle. After each op the admin session is checked and re-established
// if an op revoked it.
func seedUTCGuardWorld(ctx context.Context, t *testing.T, w *faultWorld) {
	t.Helper()
	ran, setupFailed := 0, 0
	for _, op := range opCatalog {
		if utcGuardSeedSkip(op.Key) {
			continue
		}
		func() {
			defer func() { _ = recover() }()
			var state any
			if op.Setup != nil {
				s, err := op.Setup(ctx, w)
				if err != nil {
					setupFailed++
					return
				}
				state = s
			}
			// A DELETE op's Setup creates the object it then deletes: keep the
			// object, so the GETs have it to return.
			if op.Execute != nil && !strings.HasPrefix(op.Key, "REST DELETE ") && !strings.HasSuffix(op.Key, "/withdraw") {
				_, _ = op.Execute(ctx, w, state)
			}
		}()
		ran++
		// Ops are written for a fresh world and reuse fixed secret names; give
		// what this op created a unique name so the next op's Setup does not 409.
		if err := w.db.Exec("UPDATE secret_nodes SET name = name || '-g' || CAST(id AS TEXT) WHERE name NOT LIKE '%-g%'").Error; err != nil {
			t.Fatalf("renaming seeded secrets: %v", err)
		}
		ensureUTCGuardAdminSession(ctx, t, w, op.Key)
	}
	t.Logf("seeded the guard world with %d ops (%d setups failed)", ran, setupFailed)
}

// utcGuardSeedSkipOps are ops the seed does not run because they change the
// guard admin's own credentials (a revoked session alone is recovered by
// ensureUTCGuardAdminSession; a changed password is not).
var utcGuardSeedSkipOps = map[string]string{
	"REST POST /api/v1/auth/change-password": "changes the admin's password",
}

func utcGuardSeedSkip(key string) bool { _, ok := utcGuardSeedSkipOps[key]; return ok }

func ensureUTCGuardAdminSession(ctx context.Context, t *testing.T, w *faultWorld, after string) {
	t.Helper()
	status, _, err := httpJSON(ctx, w, http.MethodGet, "/api/v1/auth/profile", nil)
	if err == nil && status == http.StatusOK {
		return
	}
	session, _, lerr := w.core.Login(ctx, &core.LoginRequest{Username: "faultadmin", Password: "FaultFuzzAdmin123!"})
	if lerr != nil {
		t.Fatalf("admin session lost after seeding op %q (GET /auth/profile %d, %v) and re-login failed: %v", after, status, err, lerr)
	}
	w.adminToken = session.SessionToken
}

func utcGuardGETRoutes(t *testing.T, w *faultWorld) []string {
	t.Helper()
	routes, ok := w.httpServer.Config.Handler.(chi.Routes)
	if !ok {
		t.Fatal("router does not expose chi.Routes")
	}
	seen := map[string]bool{}
	if err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet {
			seen[route] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func driveUTCGuardRoute(ctx context.Context, t *testing.T, w *faultWorld, route, path string) (utcGuardRouteResult, []utcGuardFinding) {
	t.Helper()
	res := utcGuardRouteResult{Route: route, Path: path, Fields: map[string]bool{}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.httpServer.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := w.adminToken
	if strings.HasPrefix(route, "/scim/v2/") {
		token = w.scimToken
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return res, []utcGuardFinding{{Route: route, Where: "request", Value: err.Error()}}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	res.Status = resp.StatusCode

	var findings []utcGuardFinding
	check := func(where, s string) {
		for _, m := range rfc3339Re.FindAllStringSubmatch(s, -1) {
			res.Timestamps++
			res.Fields[where] = true
			if m[1] != "Z" && !utcGuardFreeText(where) {
				findings = append(findings, utcGuardFinding{Route: route, Where: where, Value: m[0]})
			}
		}
	}
	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.Contains(ct, "json") || json.Valid(body):
		var v any
		if err := json.Unmarshal(body, &v); err == nil {
			walkJSONStrings(v, "$", check)
		} else {
			check("$body", string(body))
		}
	case strings.Contains(ct, "csv"):
		rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
		if err != nil {
			check("$body", string(body))
			break
		}
		var header []string
		for i, row := range rows {
			if i == 0 {
				header = row
				continue
			}
			for j, cell := range row {
				col := fmt.Sprint(j)
				if j < len(header) {
					col = header[j]
				}
				check("csv."+col, cell)
			}
		}
	default:
		check("$body", string(body))
	}
	return res, findings
}

func walkJSONStrings(v any, path string, f func(where, s string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			walkJSONStrings(vv, path+"."+k, f)
		}
	case []any:
		for _, vv := range x {
			walkJSONStrings(vv, path+"[]", f)
		}
	case string:
		f(path, x)
	}
}

// resolveUTCGuardPath turns a route pattern into a concrete path using rows the
// seed created. Every URL parameter must be resolved; an unknown parameter makes
// the route fail the guard (add a resolver or a reasoned skip).
func resolveUTCGuardPath(t *testing.T, db *gorm.DB, route string) (string, bool) {
	t.Helper()
	latest := func(model any, where string, args ...any) (uint, bool) {
		var ids []uint
		q := db.Model(model)
		if where != "" {
			q = q.Where(where, args...)
		}
		if err := q.Order("id DESC").Limit(1).Pluck("id", &ids).Error; err != nil || len(ids) == 0 {
			return 0, false
		}
		return ids[0], true
	}
	params := map[string]string{}
	set := func(name string, pick func() (uint, bool)) bool {
		id, ok := pick()
		if !ok {
			return false
		}
		params[name] = fmt.Sprint(id)
		return true
	}

	switch {
	case strings.HasPrefix(route, "/api/v1/secrets/{id}/versions/{versionId}"):
		var c models.SecretVersionComment
		if err := db.Order("id DESC").First(&c).Error; err == nil {
			params["id"], params["versionId"] = fmt.Sprint(c.SecretID), fmt.Sprint(c.VersionID)
			break
		}
		var v models.SecretVersion
		if err := db.Order("id DESC").First(&v).Error; err != nil {
			return "", false
		}
		params["id"], params["versionId"] = fmt.Sprint(v.SecretNodeID), fmt.Sprint(v.ID)
	case strings.HasPrefix(route, "/api/v1/secrets/{id}/versions/{from}/diff/{to}"):
		var vs []models.SecretVersion
		if err := db.Raw("SELECT * FROM secret_versions WHERE secret_node_id = (SELECT secret_node_id FROM secret_versions GROUP BY secret_node_id HAVING COUNT(*) > 1 ORDER BY secret_node_id DESC LIMIT 1) ORDER BY version_number").Scan(&vs).Error; err != nil || len(vs) < 2 {
			return "", false
		}
		params["id"], params["from"], params["to"] = fmt.Sprint(vs[0].SecretNodeID), fmt.Sprint(vs[0].VersionNumber), fmt.Sprint(vs[1].VersionNumber)
	case strings.HasPrefix(route, "/api/v1/secrets/{id}/schedule"):
		if !set("id", func() (uint, bool) {
			return pluckLatest(db, "SELECT secret_node_id FROM secret_access_schedules ORDER BY id DESC LIMIT 1")
		}) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/secrets/{id}/shares"):
		if !set("id", func() (uint, bool) {
			return pluckLatest(db, "SELECT secret_id FROM share_records ORDER BY id DESC LIMIT 1")
		}) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/secrets/{id}"):
		if !set("id", func() (uint, bool) { return latestSecretWithHistory(db) }) {
			return "", false
		}
	case strings.Contains(route, "{machineId}"):
		var m models.MachineIdentity
		if err := db.Order("id DESC").First(&m).Error; err != nil {
			return "", false
		}
		params["id"], params["machineId"] = fmt.Sprint(m.ProjectID), fmt.Sprint(m.ID)
	case strings.Contains(route, "{campaignId}"):
		var c models.AccessReviewCampaign
		if err := db.Order("id DESC").First(&c).Error; err != nil {
			return "", false
		}
		params["id"], params["campaignId"] = fmt.Sprint(c.ProjectID), fmt.Sprint(c.ID)
	case strings.HasPrefix(route, "/api/v1/projects/{id}"):
		if !set("id", func() (uint, bool) { return latestProjectWithData(db) }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/users/{id}"), strings.HasPrefix(route, "/scim/v2/Users/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.User{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/user-roles/user/{userId}"):
		if !set("userId", func() (uint, bool) { return latest(&models.User{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/groups/{id}"), strings.HasPrefix(route, "/scim/v2/Groups/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.Group{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/roles/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.Role{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/permissions/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.Permission{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/notification-channels/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.NotificationChannel{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/alert-escalation-policies/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.AlertEscalationPolicy{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/dynamic-secrets/configs/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.DynamicSecretConfig{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/rotation-policies/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.RotationPolicy{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/secret-templates/{id}"):
		if !set("id", func() (uint, bool) { return latest(&models.SecretTemplate{}, "") }) {
			return "", false
		}
	case strings.HasPrefix(route, "/api/v1/secret-access-requests/{requestId}"):
		if !set("requestId", func() (uint, bool) { return latest(&models.AccessRequest{}, "secret_id IS NOT NULL") }) {
			return "", false
		}
	case strings.Contains(route, "{provider}"):
		params["provider"] = fuzzSAMLProviderName
	}

	path := route
	for name, val := range params {
		path = strings.ReplaceAll(path, "{"+name+"}", val)
	}
	if strings.Contains(path, "{") {
		return "", false
	}
	q, ok := utcGuardQuery(db, route)
	if !ok {
		return "", false
	}
	return path + q, true
}

// utcGuardQuery supplies the query parameters a few routes require, from seeded rows.
func utcGuardQuery(db *gorm.DB, route string) (string, bool) {
	one := func(sql string) (string, bool) {
		var vals []string
		if err := db.Raw(sql).Scan(&vals).Error; err != nil || len(vals) == 0 || vals[0] == "" {
			return "", false
		}
		return url.QueryEscape(vals[0]), true
	}
	switch route {
	case "/api/v1/secrets/by-name":
		var s models.SecretNode
		if err := db.Where("is_secret = ?", true).Order("id DESC").First(&s).Error; err != nil {
			return "", false
		}
		return fmt.Sprintf("?name=%s&project_id=%d&environment_id=%d", url.QueryEscape(s.Name), s.ProjectID, s.EnvironmentID), true
	case "/api/v1/users/by-email":
		return "?email=faultadmin@example.com", true
	case "/api/v1/users/by-username":
		return "?username=faultadmin", true
	case "/api/v1/users/by-external-id":
		v, ok := one("SELECT external_id FROM users WHERE external_id IS NOT NULL AND external_id <> '' AND deleted_at IS NULL ORDER BY id DESC LIMIT 1")
		return "?external_id=" + v, ok
	case "/api/v1/roles/by-name":
		v, ok := one("SELECT name FROM roles ORDER BY id DESC LIMIT 1")
		return "?name=" + v, ok
	case "/api/v1/users/search":
		return "?q=a", true
	case "/api/v1/admin/billing/report", "/api/v1/rotation-calendar":
		// Bounds given WITH a non-UTC offset: a handler that echoes its input
		// time back must still answer in UTC.
		now := time.Now().In(utcGuardZone)
		return fmt.Sprintf("?from=%s&to=%s", url.QueryEscape(now.AddDate(0, -1, 0).Format(time.RFC3339)), url.QueryEscape(now.AddDate(0, 1, 0).Format(time.RFC3339))), true
	}
	return "", true
}

func pluckLatest(db *gorm.DB, sql string) (uint, bool) {
	var ids []uint
	if err := db.Raw(sql).Scan(&ids).Error; err != nil || len(ids) == 0 {
		return 0, false
	}
	return ids[0], true
}

// latestSecretWithHistory picks the live secret with the most versions, so
// per-secret routes have versions, access logs and audit rows to return.
func latestSecretWithHistory(db *gorm.DB) (uint, bool) {
	var ids []uint
	err := db.Raw(`SELECT s.id FROM secret_nodes s LEFT JOIN secret_versions v ON v.secret_node_id = s.id
		WHERE s.deleted_at IS NULL AND s.is_secret = ? GROUP BY s.id ORDER BY COUNT(v.id) DESC, s.id DESC LIMIT 1`, true).Scan(&ids).Error
	if err != nil || len(ids) == 0 {
		return 0, false
	}
	return ids[0], true
}

// latestProjectWithData picks the live project holding the most secrets.
func latestProjectWithData(db *gorm.DB) (uint, bool) {
	var ids []uint
	err := db.Raw(`SELECT p.id FROM projects p LEFT JOIN secret_nodes s ON s.project_id = p.id
		WHERE p.deleted_at IS NULL GROUP BY p.id ORDER BY COUNT(s.id) DESC, p.id DESC LIMIT 1`).Scan(&ids).Error
	if err != nil || len(ids) == 0 {
		return 0, false
	}
	return ids[0], true
}

// utcGuardGRPCSkipped are read-shaped RPCs the gRPC sweep does not call, with
// the reason. A stale entry fails the guard.
var utcGuardGRPCSkipped = map[string]string{
	"keyorix.v1.AuditService.StreamAuditLogs": "server stream that waits for new events; its messages are built by auditEventToProto, the same function GetAuditLogs uses (swept)",
	"keyorix.v1.ConnectService.ReadSecret":    "returns a secret value for a connector credential; the world seeds no connector",
}

// driveUTCGuardGRPC calls every read-shaped unary RPC (faultops'
// isMutatingGRPCMethod == false) with id-like request fields filled from seeded
// rows, then checks every string field in the response for an RFC 3339 time
// that is not UTC. google.protobuf.Timestamp fields carry no zone (seconds and
// nanos since the Unix epoch), so they are UTC by construction; they are counted
// for the inventory only.
func driveUTCGuardGRPC(ctx context.Context, t *testing.T, w *faultWorld) (inventory []string, findings []utcGuardFinding) {
	t.Helper()
	gctx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+w.adminToken))
	ok := 0
	seen := map[string]bool{}
	for _, sd := range allGRPCServiceDescs {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(sd.ServiceName))
		if err != nil {
			t.Fatalf("service %s: %v", sd.ServiceName, err)
		}
		svc := d.(protoreflect.ServiceDescriptor)
		names := make([]string, 0, len(sd.Methods)+len(sd.Streams))
		for _, m := range sd.Methods {
			names = append(names, m.MethodName)
		}
		for _, s := range sd.Streams {
			names = append(names, s.StreamName)
		}
		for _, name := range names {
			if isMutatingGRPCMethod(name) {
				continue
			}
			key := sd.ServiceName + "." + name
			seen[key] = true
			if _, skip := utcGuardGRPCSkipped[key]; skip {
				continue
			}
			md := svc.Methods().ByName(protoreflect.Name(name))
			if md.IsStreamingServer() || md.IsStreamingClient() {
				findings = append(findings, utcGuardFinding{Route: "GRPC " + key, Where: "stream", Value: "streaming RPC not swept: add it to utcGuardGRPCSkipped with a reason, or sweep it"})
				continue
			}
			inT, err := protoregistry.GlobalTypes.FindMessageByName(md.Input().FullName())
			if err != nil {
				t.Fatal(err)
			}
			outT, err := protoregistry.GlobalTypes.FindMessageByName(md.Output().FullName())
			if err != nil {
				t.Fatal(err)
			}
			req, resp := inT.New(), outT.New()
			fillUTCGuardGRPCRequest(w.db, key, sd.ServiceName, req)
			code := codes.OK
			if err := w.grpcConn.Invoke(gctx, "/"+sd.ServiceName+"/"+name, req.Interface(), resp.Interface()); err != nil {
				code = status.Code(err)
			} else {
				ok++
			}
			ts, fields := 0, map[string]bool{}
			walkProtoTimes(resp, "$", func(where string, isTimestamp bool, s string) {
				if isTimestamp {
					ts++
					fields[where+" (Timestamp)"] = true
					return
				}
				for _, m := range rfc3339Re.FindAllStringSubmatch(s, -1) {
					ts++
					fields[where+" (string)"] = true
					if m[1] != "Z" && !utcGuardFreeText(where) {
						findings = append(findings, utcGuardFinding{Route: "GRPC " + key, Where: where, Value: m[0]})
					}
				}
			})
			fl := make([]string, 0, len(fields))
			for f := range fields {
				fl = append(fl, f)
			}
			sort.Strings(fl)
			inventory = append(inventory, fmt.Sprintf("GRPC %s code=%s timestamps=%d fields=%s", key, code, ts, strings.Join(fl, ",")))
		}
	}
	for key := range utcGuardGRPCSkipped {
		if !seen[key] {
			t.Errorf("utcGuardGRPCSkipped has %s, which is no longer a read-shaped RPC: remove it", key)
		}
	}
	if ok < 20 {
		t.Errorf("only %d read RPCs answered OK; the gRPC sweep is not reaching data", ok)
	}
	return inventory, findings
}

// fillUTCGuardGRPCRequest sets the id-like fields of a read request from seeded
// rows: "id" by service, "<thing>_id" by name. Anything else keeps its zero value.
func fillUTCGuardGRPCRequest(db *gorm.DB, key, service string, req protoreflect.Message) {
	pick := func(sql string) uint64 {
		var ids []uint64
		if err := db.Raw(sql).Scan(&ids).Error; err != nil || len(ids) == 0 {
			return 0
		}
		return ids[0]
	}
	secret := func() uint64 { id, _ := latestSecretWithHistory(db); return uint64(id) }
	project := func() uint64 { id, _ := latestProjectWithData(db); return uint64(id) }
	byName := map[string]func() uint64{
		"secret_id":           secret,
		"project_id":          project,
		"user_id":             func() uint64 { return pick("SELECT id FROM users WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 1") },
		"group_id":            func() uint64 { return pick("SELECT id FROM groups WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 1") },
		"role_id":             func() uint64 { return pick("SELECT id FROM roles ORDER BY id DESC LIMIT 1") },
		"environment_id":      func() uint64 { return 1 },
		"machine_identity_id": func() uint64 { return pick("SELECT id FROM machine_identities ORDER BY id DESC LIMIT 1") },
		"config_id":           func() uint64 { return pick("SELECT id FROM dynamic_secret_configs ORDER BY id DESC LIMIT 1") },
		"machine_id":          func() uint64 { return pick("SELECT id FROM machine_identities ORDER BY id DESC LIMIT 1") },
	}
	// Requests whose ids must belong together.
	switch key {
	case "keyorix.v1.MachineIdentityService.ListMachineTokens":
		byName["project_id"] = func() uint64 {
			return pick("SELECT project_id FROM machine_identities ORDER BY id DESC LIMIT 1")
		}
	case "keyorix.v1.SecretService.ListSecretACLs":
		byName["secret_id"] = func() uint64 { return pick("SELECT secret_id FROM secret_acls ORDER BY id DESC LIMIT 1") }
	}
	idByService := map[string]func() uint64{
		"keyorix.v1.SecretService":          secret,
		"keyorix.v1.ProjectService":         project,
		"keyorix.v1.UserService":            byName["user_id"],
		"keyorix.v1.GroupService":           byName["group_id"],
		"keyorix.v1.RoleService":            byName["role_id"],
		"keyorix.v1.MachineIdentityService": byName["machine_identity_id"],
		"keyorix.v1.DynamicSecretService":   byName["config_id"],
	}
	fields := req.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		var get func() uint64
		if string(f.Name()) == "id" {
			get = idByService[service]
		} else {
			get = byName[string(f.Name())]
		}
		// proto3 "optional" fields are filters (GetAuditLogs' user_id,
		// project_id): left unset so the call returns everything.
		if get == nil || f.IsList() || f.HasPresence() {
			continue
		}
		v := get()
		switch f.Kind() {
		case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
			req.Set(f, protoreflect.ValueOfUint32(uint32(v)))
		case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			req.Set(f, protoreflect.ValueOfUint64(v))
		case protoreflect.Int32Kind:
			req.Set(f, protoreflect.ValueOfInt32(int32(v)))
		case protoreflect.Int64Kind:
			req.Set(f, protoreflect.ValueOfInt64(int64(v)))
		}
	}
}

// walkProtoTimes visits every google.protobuf.Timestamp field and every string
// value (fields, lists, map values) in m.
func walkProtoTimes(m protoreflect.Message, path string, f func(where string, isTimestamp bool, s string)) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		p := path + "." + string(fd.Name())
		visit := func(p string, v protoreflect.Value, kind protoreflect.Kind, md protoreflect.MessageDescriptor) {
			switch kind {
			case protoreflect.StringKind:
				f(p, false, v.String())
			case protoreflect.MessageKind, protoreflect.GroupKind:
				if md.FullName() == "google.protobuf.Timestamp" {
					f(p, true, "")
					return
				}
				walkProtoTimes(v.Message(), p, f)
			}
		}
		switch {
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				visit(p+"[]", l.Get(i), fd.Kind(), fd.Message())
			}
		case fd.IsMap():
			v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
				visit(p+"{}", mv, fd.MapValue().Kind(), fd.MapValue().Message())
				return true
			})
		default:
			visit(p, v, fd.Kind(), fd.Message())
		}
		return true
	})
}
