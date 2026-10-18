package http

// human_read_gate_reuse_test.go — OPT-READPATH-2.
//
// A human (session) secret read used to evaluate its per-secret decision twice:
// once in RequireScopedSecretPermission (ACL, role, share) and again in core's
// checkSecretPermission (live owner, share, ACL, role), and read the access
// schedule twice (the read check, then the value step's guard bundle). The core
// read check now reuses the gate's allow for the same user and secret, recorded on
// a request-scoped memo, and the value step reuses the schedule/version snapshot
// the read check took (internal/core/gate_read_decision.go).
//
// TestHumanReadGateReuse_Equivalence is the before/after equivalence: every case of
// a generated matrix is read with the reuse switched off (the read path as it was)
// and on, and the status, the response (value or error body) and the audit and
// access-log rows the read wrote must be identical. It also checks that the reuse
// really ran: an allowed read issues fewer statements with it on.
//
// TestHumanReadStatementCount pins the statement count of a warm human value read
// before its audit write (on the wire, every pool, Postgres): 7. It was 16.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers"
)

// hrCase is one point of the matrix.
type hrCase struct {
	grant     string // how the reader may (or may not) reach the secret
	secret    string // the secret's state at read time
	principal string // the reader's account state at read time
	project   string // the secret's project state at read time
}

func (c hrCase) String() string {
	return c.grant + "/" + c.secret + "/" + c.principal + "/" + c.project
}

var (
	hrGrants = []string{
		"none",                // a member of the project's other environment only
		"role-direct",         // project_viewer at the project
		"role-direct-expired", // the same, expired
		"role-group",          // project_viewer at the project through a group
		"role-group-expired",  // the same, the group's grant expired
		"acl",                 // a SecretACL read grant on the secret
		"share-direct",        // a read share to the reader
		"share-group",         // a read share to a group the reader is in
		"share-expired",       // a read share that has expired
		"owner-live",          // the secret's owner, a project member
		"owner-not-member",    // the secret's owner, no longer a project member
		"outsider",            // a role in another project only
	}
	hrSecretStates    = []string{"active", "suspended", "expired", "deleted", "schedule-denies", "schedule-allows"}
	hrPrincipalStates = []string{"live", "suspended", "deleted"}
	hrProjectStates   = []string{"live", "mfa-required", "deleted"}
)

// hrMatrix: every grant with every secret state (live reader, live project), and every
// grant with every reader and project state (active secret).
func hrMatrix() []hrCase {
	var out []hrCase
	for _, g := range hrGrants {
		for _, s := range hrSecretStates {
			out = append(out, hrCase{g, s, "live", "live"})
		}
		for _, p := range hrPrincipalStates {
			for _, pr := range hrProjectStates {
				if p == "live" && pr == "live" {
					continue // already above
				}
				out = append(out, hrCase{g, "active", p, pr})
			}
		}
	}
	return out
}

// hrOutcome is what one read did: its answer and the rows it wrote.
type hrOutcome struct {
	Status int
	Body   string   // the value and secret id on success, the normalized error body otherwise
	Audit  []string // audit_events rows the request added: type|user|secret|success|actor
	Logs   int      // secret_access_logs rows the request added for the secret
}

func (o hrOutcome) String() string {
	return fmt.Sprintf("%d %s audit=%v logs=%d", o.Status, o.Body, o.Audit, o.Logs)
}

var hrIPSeq atomic.Int64

// hrRead performs one GET /secrets/{id} (with or without the value) on r and
// returns its outcome and the number of statements it issued.
func hrRead(t *testing.T, r *voReplica, token string, secretID uint, withValue bool) (hrOutcome, int) {
	t.Helper()
	var lastAudit uint
	require.NoError(t, r.db.Model(&models.AuditEvent{}).Select("COALESCE(MAX(id), 0)").Scan(&lastAudit).Error)
	var logsBefore int64
	require.NoError(t, r.db.Model(&models.SecretAccessLog{}).Where("secret_node_id = ?", secretID).Count(&logsBefore).Error)

	url := fmt.Sprintf("/api/v1/secrets/%d", secretID)
	if withValue {
		url += "?include_value=true"
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Its own source address per request: the per-IP invalid-token budget would
	// otherwise turn the dead-session cases' 401 into 429 depending on case order.
	ip := hrIPSeq.Add(1)
	req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:4321", byte(ip>>16), byte(ip>>8), byte(ip))
	r.mu.Lock()
	r.counting, r.stmts = true, 0
	r.mu.Unlock()
	resp := httptest.NewRecorder()
	r.srv.Config.Handler.ServeHTTP(resp, req)
	raw := resp.Body.Bytes()
	handlers.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
	r.mu.Lock()
	r.counting = false
	stmts := r.stmts
	r.mu.Unlock()

	out := hrOutcome{Status: resp.Code}
	if resp.Code >= 200 && resp.Code < 300 {
		var body struct {
			Data struct {
				Value  string `json:"value"`
				ID     uint   `json:"ID"`
				Secret struct {
					ID uint `json:"ID"`
				} `json:"secret"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(raw, &body), string(raw))
		out.Body = fmt.Sprintf("value=%q id=%d/%d", body.Data.Value, body.Data.ID, body.Data.Secret.ID)
	} else {
		out.Body = svNormalizeBody(string(raw))
	}
	var evs []models.AuditEvent
	require.NoError(t, r.db.Where("id > ?", lastAudit).Order("id").Find(&evs).Error)
	for _, ev := range evs {
		var user, sec uint
		if ev.UserID != nil {
			user = *ev.UserID
		}
		if ev.SecretNodeID != nil {
			sec = *ev.SecretNodeID
		}
		out.Audit = append(out.Audit, fmt.Sprintf("%s|%d|%d|%v|%s", ev.EventType, user, sec, ev.Success != nil && *ev.Success, ev.ActorType))
	}
	sort.Strings(out.Audit)
	var logsAfter int64
	require.NoError(t, r.db.Model(&models.SecretAccessLog{}).Where("secret_node_id = ?", secretID).Count(&logsAfter).Error)
	out.Logs = int(logsAfter - logsBefore)
	return out, stmts
}

// hrNormalize replaces the ids that differ between two identically built cases (the
// secret, its name and value, the reader) by names, so their outcomes compare.
func hrNormalize(o hrOutcome, s *models.SecretNode, w *voWorld) hrOutcome {
	num := strings.TrimPrefix(s.Name, "hr-secret-")
	o.Body = strings.ReplaceAll(o.Body, "hr-value-"+num, "hr-value-N")
	o.Body = strings.ReplaceAll(o.Body, fmt.Sprintf("id=%d/", s.ID), "id=S/")
	o.Body = strings.ReplaceAll(o.Body, fmt.Sprintf("/%d", s.ID), "/S")
	audit := make([]string, 0, len(o.Audit))
	for _, row := range o.Audit {
		f := strings.Split(row, "|")
		switch f[1] {
		case "0":
		case strconv.FormatUint(uint64(w.users["owner"]), 10):
			f[1] = "owner"
		case strconv.FormatUint(uint64(w.adminID), 10):
			f[1] = "admin"
		default:
			f[1] = "reader" // every other user in a case is that case's reader
		}
		if f[2] == strconv.FormatUint(uint64(s.ID), 10) {
			f[2] = "S"
		}
		audit = append(audit, strings.Join(f, "|"))
	}
	o.Audit = audit
	return o
}

// hrSetup builds one case on its own project, reader and secret, and returns the
// reader's session token and the secret.
func hrSetup(t *testing.T, w *voWorld, roleID map[string]uint, n int, tc hrCase) (string, *models.SecretNode) {
	t.Helper()
	c, ctx, db := w.a.c, context.Background(), w.a.db
	admin, owner := w.adminID, w.users["owner"]

	proj, err := c.CreateProject(ctx, fmt.Sprintf("hr-proj-%d", n), "")
	require.NoError(t, err)
	envA, err := c.CreateEnvironment(ctx, proj.ID, "hr-env-a")
	require.NoError(t, err)
	envB, err := c.CreateEnvironment(ctx, proj.ID, "hr-env-b")
	require.NoError(t, err)
	projScope, envBScope := core.Scope{ProjectID: proj.ID}, core.Scope{ProjectID: proj.ID, EnvironmentID: envB.ID}
	require.NoError(t, c.AssignUserRole(ctx, admin, owner, roleID["project_developer"], projScope, false))

	name := fmt.Sprintf("hr-reader-%d", n)
	u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: voPassword})
	require.NoError(t, err)
	reader := u.ID
	group := func() uint {
		g, gerr := c.CreateGroup(ctx, admin, &core.CreateGroupRequest{Name: fmt.Sprintf("hr-group-%d", n)})
		require.NoError(t, gerr)
		require.NoError(t, c.AddUserToGroup(ctx, admin, false, reader, g.ID, 0))
		return g.ID
	}
	past := time.Now().Add(-time.Minute)

	secretOwner := owner
	switch tc.grant {
	case "none", "acl", "share-direct", "share-group", "share-expired":
		require.NoError(t, c.AssignUserRole(ctx, admin, reader, roleID["project_viewer"], envBScope, false))
	case "role-direct":
		require.NoError(t, c.AssignUserRole(ctx, admin, reader, roleID["project_viewer"], projScope, false))
	case "role-direct-expired":
		require.NoError(t, c.AssignUserRole(ctx, admin, reader, roleID["project_viewer"], projScope, false))
		// Re-created through Create, so UserRole's BeforeSave stores the expiry in UTC
		// (G1619: SQLite compares strings).
		var ur models.UserRole
		require.NoError(t, db.Where("user_id = ? AND project_id = ?", reader, proj.ID).First(&ur).Error)
		require.NoError(t, db.Where("user_id = ? AND project_id = ?", reader, proj.ID).Delete(&models.UserRole{}).Error)
		ur.ExpiresAt = &past
		require.NoError(t, db.Create(&ur).Error)
	case "role-group", "role-group-expired":
		g := group()
		require.NoError(t, c.AssignRoleToGroup(ctx, admin, g, roleID["project_viewer"], projScope, false))
		if tc.grant == "role-group-expired" {
			var gr models.GroupRole
			require.NoError(t, db.Where("group_id = ?", g).First(&gr).Error)
			require.NoError(t, db.Where("group_id = ?", g).Delete(&models.GroupRole{}).Error)
			gr.ExpiresAt = &past
			require.NoError(t, db.Create(&gr).Error)
		}
	case "owner-live":
		require.NoError(t, c.AssignUserRole(ctx, admin, reader, roleID["project_developer"], projScope, false))
		secretOwner = reader
	case "owner-not-member":
		require.NoError(t, c.AssignUserRole(ctx, admin, reader, roleID["project_developer"], core.Scope{ProjectID: w.otherProj}, false))
		secretOwner = reader
	case "outsider":
		require.NoError(t, c.AssignUserRole(ctx, admin, reader, roleID["project_viewer"], core.Scope{ProjectID: w.otherProj}, false))
	default:
		t.Fatalf("unknown grant %q", tc.grant)
	}

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: name, Password: voPassword})
	require.NoError(t, err)

	s, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: fmt.Sprintf("hr-secret-%d", n), Value: []byte(fmt.Sprintf("hr-value-%d", n)),
		ProjectID: proj.ID, EnvironmentID: envA.ID, Type: "generic", CreatedBy: "owner", OwnerID: secretOwner,
	})
	require.NoError(t, err)
	// Warm the read-path caches on this secret with a read that is allowed, so a stale
	// cache entry would show below as a difference.
	ownerTok := w.tokens["owner"]
	if secretOwner == reader {
		ownerTok = sess.SessionToken
	}
	_, _ = hrRead(t, w.a, ownerTok, s.ID, true)

	switch tc.grant {
	case "acl":
		require.NoError(t, c.GrantSecretACL(ctx, admin, s.ID, reader, []string{"secrets.read"}))
	case "share-direct", "share-expired":
		rec, serr := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: s.ID, RecipientID: reader, Permission: "read", SharedBy: owner})
		require.NoError(t, serr)
		if tc.grant == "share-expired" {
			var row models.ShareRecord // through Save(), so BeforeSave runs (G1619)
			require.NoError(t, db.First(&row, rec.ID).Error)
			row.ExpiresAt = &past
			require.NoError(t, db.Save(&row).Error)
		}
	case "share-group":
		// The group needs a role in the project to be shared with; env B's does not
		// reach the secret.
		g := group()
		require.NoError(t, c.AssignRoleToGroup(ctx, admin, g, roleID["project_viewer"], envBScope, false))
		_, serr := c.ShareSecretWithGroup(ctx, &core.GroupShareSecretRequest{SecretID: s.ID, GroupID: g, Permission: "read", SharedBy: owner})
		require.NoError(t, serr)
	}

	switch tc.secret {
	case "active":
	case "suspended":
		_, err = c.SuspendSecret(ctx, s.ID, admin, "opt-readpath-2 equivalence")
		require.NoError(t, err)
	case "expired":
		var row models.SecretNode // through Save(), so BeforeSave runs (G1619)
		require.NoError(t, db.First(&row, s.ID).Error)
		row.Expiration = &past
		require.NoError(t, db.Save(&row).Error)
	case "deleted":
		require.NoError(t, c.DeleteSecret(ctx, s.ID))
	case "schedule-denies":
		_, err = c.SetSecretSchedule(ctx, s.ID, notTodayOrTomorrow(), 0, 24, "UTC")
		require.NoError(t, err)
	case "schedule-allows":
		_, err = c.SetSecretSchedule(ctx, s.ID, "*", 0, 24, "UTC")
		require.NoError(t, err)
	default:
		t.Fatalf("unknown secret state %q", tc.secret)
	}

	switch tc.principal {
	case "live":
	case "suspended":
		require.NoError(t, c.SuspendUser(ctx, admin, reader))
	case "deleted":
		require.NoError(t, c.DeleteUser(ctx, admin, reader))
	default:
		t.Fatalf("unknown principal state %q", tc.principal)
	}

	switch tc.project {
	case "live":
	case "mfa-required": // the reader's session has no second factor
		require.NoError(t, db.Model(&models.Project{}).Where("id = ?", proj.ID).Update("require_mfa", true).Error)
	case "deleted":
		require.NoError(t, c.DeleteProject(ctx, 0, proj.ID, true))
	default:
		t.Fatalf("unknown project state %q", tc.project)
	}
	return sess.SessionToken, s
}

func TestHumanReadGateReuse_Equivalence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { hrEquivalence(t, backend) })
	}
}

func hrEquivalence(t *testing.T, backend string) {
	t.Cleanup(func() { core.SetHumanReadReuseForTesting(true) })
	w := newVOWorld(t, backend, false)
	roles, err := w.a.c.Storage().ListRoles(context.Background())
	require.NoError(t, err)
	roleID := map[string]uint{}
	for _, r := range roles {
		roleID[r.Name] = r.ID
	}

	statuses := map[int]int{}
	n := 0
	for i, tc := range hrMatrix() {
		// Each mode gets its own, identically built case (project, reader, secret):
		// a read leaves state behind (denial-audit windows, access counters), so the
		// two modes must not share one. Alternate which mode goes first.
		order := []bool{false, true}
		if i%2 == 1 {
			order = []bool{true, false}
		}
		got := map[bool][]hrOutcome{}
		stmts := map[bool][]int{}
		for _, reuse := range order {
			n++
			token, s := hrSetup(t, w, roleID, n, tc)
			core.SetHumanReadReuseForTesting(reuse)
			for _, withValue := range []bool{true, false} {
				o, st := hrRead(t, w.a, token, s.ID, withValue)
				got[reuse] = append(got[reuse], hrNormalize(o, s, w))
				stmts[reuse] = append(stmts[reuse], st)
			}
			core.SetHumanReadReuseForTesting(true)
		}
		for k, withValue := range []bool{true, false} {
			label := fmt.Sprintf("%s value=%v", tc, withValue)
			before, after := got[false][k], got[true][k]
			if !assert.Equal(t, before, after, "%s: outcome with the reuse differs from before", label) {
				continue
			}
			statuses[after.Status]++
			if after.Status == http.StatusOK {
				assert.Less(t, stmts[true][k], stmts[false][k], "%s: an allowed read must issue fewer statements with the reuse", label)
			}
			t.Logf("%-56s %s (statements %d -> %d)", label, after, stmts[false][k], stmts[true][k])
		}
	}
	t.Logf("outcomes by status: %v", statuses)
	// The matrix is not vacuous: it allows, refuses on permission, on secret state, on
	// the project's MFA policy, and rejects a dead session.
	for _, st := range []int{http.StatusOK, http.StatusForbidden, http.StatusConflict, http.StatusUnauthorized} {
		assert.Positive(t, statuses[st], "the matrix must contain a %d outcome", st)
	}
}

// TestHumanReadGateReuse_MemoIsPerRequest: the gate's allow never outlives its
// request. After a grant is revoked, the very next read by the same session is
// refused, on both the gate and the core check.
func TestHumanReadGateReuse_MemoIsPerRequest(t *testing.T) {
	w := newVOWorld(t, "sqlite", false)
	c, ctx := w.a.c, context.Background()
	s := w.newSecret(t)
	rec, err := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: s.ID, RecipientID: w.users["sharee"], Permission: "read", SharedBy: w.users["owner"]})
	require.NoError(t, err)
	got, _ := hrRead(t, w.a, w.tokens["sharee"], s.ID, true)
	require.Equal(t, http.StatusOK, got.Status, got.String())
	require.NoError(t, c.RevokeShare(ctx, rec.ID, w.users["owner"]))
	got, _ = hrRead(t, w.a, w.tokens["sharee"], s.ID, true)
	assert.Equal(t, http.StatusForbidden, got.Status, got.String())
	assert.True(t, strings.Contains(got.Body, "Insufficient permissions"), got.Body)
}

// TestHumanReadStatementCount: a warm human session value read issues 7 statements
// before its audit write (it issued 16 when the gate and the core check each
// evaluated the decision and the schedule was read twice). The 7: the session
// re-check, the secret's node stamp, the ACL row and the ancestor walk, the role
// resolution, the project MFA policy, and the schedule/latest-version read.
func TestHumanReadStatementCount(t *testing.T) {
	w, proxy := rcWorld(t)
	sec, val := w.newSecret(t, nil)
	for range 3 { // token cache, read-path caches
		rcRead(t, w, proxy, "human", sec, val)
	}
	stmts, rt := rcRead(t, w, proxy, "human", sec, val)
	rcLog(t, "human warm read", stmts, rt)
	reads := rcReadStatements(stmts)
	require.Len(t, reads, 7, "warm human read: statements before the audit write")
	// The core check's own lookups (shares, group memberships, project membership)
	// and the separate schedule read are gone.
	for _, from := range []string{`FROM "share_records"`, `FROM "user_roles"`, `FROM "group_roles"`, `FROM "secret_access_schedules"`} {
		for _, s := range reads {
			assert.NotContains(t, s.SQL, from, "the core check no longer repeats the gate's decision")
		}
	}
}
