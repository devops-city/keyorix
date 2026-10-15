package http

// Query-count regression tests for list endpoints (LIST-ENDPOINTS-1).
//
// A list request must cost a number of SQL statements that does not grow with the
// rows on the page: per-row GetUser / GetSecretTags / ListSharesBySecret calls turn
// one page into hundreds of round trips. Each test compares the same request over a
// small and a large data set and fails when the large one issues more statements.
// Absolute counts are deliberately not asserted: a legitimate new fixed-cost query
// must not break these, a per-row query must.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// leQueryRecorder records the SQL of every statement while on.
type leQueryRecorder struct {
	mu   sync.Mutex
	on   bool
	sqls []string
}

// leRecorderSeq numbers the gorm callbacks each recorder registers; atomic because
// tests (and their subtests) may build fixtures concurrently.
var leRecorderSeq atomic.Int64

func newLEQueryRecorder(t *testing.T, db *gorm.DB) *leQueryRecorder {
	t.Helper()
	rec := &leQueryRecorder{}
	record := func(d *gorm.DB) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if rec.on {
			rec.sqls = append(rec.sqls, d.Statement.SQL.String())
		}
	}
	name := fmt.Sprintf("listendpoints1:%d", leRecorderSeq.Add(1))
	cb := db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register(name+":q", record))
	require.NoError(t, cb.Row().After("gorm:row").Register(name+":row", record))
	require.NoError(t, cb.Raw().After("gorm:raw").Register(name+":raw", record))
	return rec
}

// get issues an authenticated GET and returns the status, body and the statements it issued.
func (rec *leQueryRecorder) get(t *testing.T, w *rrWorld, token, path string) (int, string, []string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, w.a.srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	rec.mu.Lock()
	rec.on, rec.sqls = true, nil
	rec.mu.Unlock()
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	rec.mu.Lock()
	rec.on = false
	sqls := append([]string(nil), rec.sqls...)
	rec.mu.Unlock()
	return resp.StatusCode, string(body), sqls
}

// leFixture is a world with an admin session, a pool of users and the recorder.
type leFixture struct {
	w     *rrWorld
	rec   *leQueryRecorder
	token string
	users []models.User
	now   time.Time
}

func newLEFixture(t *testing.T, backend string, nUsers int) *leFixture {
	t.Helper()
	w := newRRWorld(t, backend, false)
	f := &leFixture{w: w, rec: newLEQueryRecorder(t, w.a.db), now: time.Now().UTC()}
	f.users = make([]models.User, 0, nUsers)
	for i := range nUsers {
		name := fmt.Sprintf("leuser%04d", i)
		f.users = append(f.users, models.User{Username: name, UsernameFolded: name, Email: name + "@example.com", EmailFolded: name + "@example.com", IsActive: true})
	}
	require.NoError(t, w.a.db.CreateInBatches(&f.users, 100).Error)
	sess, _, err := w.a.c.Login(context.Background(), &core.LoginRequest{Username: "rradmin", Password: rrPassword})
	require.NoError(t, err)
	f.token = sess.SessionToken
	return f
}

// project creates a project with one environment holding n secrets owned by the
// admin; each secret is shared with a distinct user and carries a tag.
func (f *leFixture) project(t *testing.T, name string, n int) uint {
	t.Helper()
	ctx := context.Background()
	p, err := f.w.a.c.CreateProject(ctx, name, "list endpoints")
	require.NoError(t, err)
	env, err := f.w.a.c.CreateEnvironment(ctx, p.ID, name+"-env")
	require.NoError(t, err)
	db := f.w.a.db
	secs := make([]models.SecretNode, 0, n)
	for i := range n {
		secs = append(secs, models.SecretNode{
			Name: fmt.Sprintf("%s-secret-%03d", name, i), ProjectID: p.ID, EnvironmentID: env.ID,
			IsSecret: true, Type: "generic", Status: "active", OwnerID: f.w.adminID, CreatedBy: "x",
			CreatedAt: f.now, UpdatedAt: f.now,
		})
	}
	require.NoError(t, db.CreateInBatches(&secs, 100).Error)
	tag := models.Tag{Name: name + "-tag"}
	require.NoError(t, db.Create(&tag).Error)
	var shares []models.ShareRecord
	var tags []models.SecretTag
	for i := range secs {
		shares = append(shares, models.ShareRecord{
			SecretID: secs[i].ID, OwnerID: f.w.adminID, RecipientID: f.users[i%len(f.users)].ID, Permission: "read",
		})
		tags = append(tags, models.SecretTag{SecretNodeID: secs[i].ID, TagID: tag.ID})
	}
	require.NoError(t, db.CreateInBatches(&shares, 100).Error)
	require.NoError(t, db.CreateInBatches(&tags, 100).Error)
	return p.ID
}

func leBackends(t *testing.T) []string {
	t.Helper()
	return []string{"sqlite", "postgres"}
}

// TestListSecrets_QueryCountDoesNotGrowWithRows: the secrets list resolved each owned
// secret's shares, each share recipient, each shared secret and owner, each ACL grant
// and (for tag / search filters) each secret's tags with its own statement.
func TestListSecrets_QueryCountDoesNotGrowWithRows(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			const small, large = 6, 60
			f := newLEFixture(t, backend, large)
			smallID := f.project(t, "lesmall", small)
			largeID := f.project(t, "lelarge", large)

			for _, q := range []string{"", "&search=nomatch", "&tags=lelarge-tag"} {
				path := func(id uint) string {
					return fmt.Sprintf("/api/v1/secrets?project_id=%d&page_size=100%s", id, q)
				}
				stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, path(smallID))
				stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, path(largeID))
				require.Equal(t, http.StatusOK, stS, bodyS)
				require.Equal(t, http.StatusOK, stL, bodyL)
				if q == "" {
					require.Contains(t, bodyL, fmt.Sprintf(`"total":%d`, large), "the large project must list every secret")
				}
				require.LessOrEqual(t, len(sqlL), len(sqlS)+3,
					"%q: %d statements for %d secrets vs %d for %d: the list issues statements per row", q, len(sqlL), large, len(sqlS), small)
			}
		})
	}
}

// aclProject creates a project with one environment holding n secrets owned by another
// user, each carrying a per-secret ACL grant for the admin: the listing's ACL path.
func (f *leFixture) aclProject(t *testing.T, name string, n int) uint {
	t.Helper()
	ctx := context.Background()
	p, err := f.w.a.c.CreateProject(ctx, name, "list endpoints acl")
	require.NoError(t, err)
	env, err := f.w.a.c.CreateEnvironment(ctx, p.ID, name+"-env")
	require.NoError(t, err)
	db := f.w.a.db
	secs := make([]models.SecretNode, 0, n)
	for i := range n {
		secs = append(secs, models.SecretNode{
			Name: fmt.Sprintf("%s-secret-%03d", name, i), ProjectID: p.ID, EnvironmentID: env.ID,
			IsSecret: true, Type: "generic", Status: "active", OwnerID: f.users[0].ID, CreatedBy: "x",
			CreatedAt: f.now, UpdatedAt: f.now,
		})
	}
	require.NoError(t, db.CreateInBatches(&secs, 100).Error)
	acls := make([]models.SecretACL, 0, n)
	for i := range secs {
		acls = append(acls, models.SecretACL{
			SecretID: secs[i].ID, UserID: f.w.adminID, Permissions: `["secrets.read"]`,
			GrantedBy: f.users[0].ID, CreatedAt: f.now, UpdatedAt: f.now,
		})
	}
	require.NoError(t, db.CreateInBatches(&acls, 100).Error)
	return p.ID
}

// TestListSecrets_ACLPathQueryCountDoesNotGrowWithGrants: the ACL-granted nodes were
// fetched with one GetSecret per grant.
func TestListSecrets_ACLPathQueryCountDoesNotGrowWithGrants(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			const small, large = 6, 60
			f := newLEFixture(t, backend, 2)
			smallID := f.aclProject(t, "leaclsmall", small)
			largeID := f.aclProject(t, "leacllarge", large)

			path := func(id uint) string {
				return fmt.Sprintf("/api/v1/secrets?project_id=%d&page_size=100", id)
			}
			stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, path(smallID))
			stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, path(largeID))
			require.Equal(t, http.StatusOK, stS, bodyS)
			require.Equal(t, http.StatusOK, stL, bodyL)
			require.Contains(t, bodyL, fmt.Sprintf(`"total":%d`, large), "the large project must list every ACL-granted secret")
			require.LessOrEqual(t, len(sqlL), len(sqlS)+3,
				"%d statements for %d ACL grants vs %d for %d: the ACL path issues statements per grant", len(sqlL), large, len(sqlS), small)
		})
	}
}

// leWithoutPerSecretAuthz drops the statements of the per-distinct-secret
// AuthorizeSecret(secrets.read) call that annotates share views with secret names
// (#3153): ACL rows and their folder ancestor walk, the single-row secret fetch, the
// role resolution and the cache-epoch probe. That authorization is deliberately one
// decision per secret, the same one GET /secrets/{id} makes, and batching it is a
// separate change; what this guard pins is that the LOOKUPS (usernames, group names,
// secrets, projects) stay batched. A new statement that is not one of these still counts.
func leWithoutPerSecretAuthz(sqls []string) []string {
	unquote := strings.NewReplacer("`", "", `"`, "")
	out := make([]string, 0, len(sqls))
	for _, s := range sqls {
		q := unquote.Replace(s)
		switch {
		case strings.Contains(q, "FROM secret_acls"),
			strings.Contains(q, "user_roles"),
			strings.Contains(q, "cache_epoch"),
			strings.Contains(q, "SELECT id,parent_id FROM secret_nodes"),
			strings.Contains(q, "FROM secret_nodes WHERE secret_nodes.id = ") && strings.Contains(q, "LIMIT"): // Postgres parameterizes it ("LIMIT $2")
			continue
		}
		out = append(out, s)
	}
	return out
}

// TestListShares_QueryCountDoesNotGrowWithShares: the shares list resolved each share's
// secret, recipient and creator with its own statement. The admin's shares accumulate
// across the two projects, so the second request lists many more rows than the first.
func TestListShares_QueryCountDoesNotGrowWithShares(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			const small, large = 6, 60
			f := newLEFixture(t, backend, large)
			const route = "/api/v1/shares?pageSize=100"

			f.project(t, "leshsmall", small)
			stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, route)
			f.project(t, "leshlarge", large)
			stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, route)
			require.Equal(t, http.StatusOK, stS, bodyS)
			require.Equal(t, http.StatusOK, stL, bodyL)
			require.Contains(t, bodyL, "leshlarge-secret-", "the large set of shares must be listed")
			lookupsS, lookupsL := leWithoutPerSecretAuthz(sqlS), leWithoutPerSecretAuthz(sqlL)
			require.LessOrEqual(t, len(lookupsL), len(lookupsS)+3,
				"%d lookup statements for %d shares vs %d for %d: the shares list issues statements per row", len(lookupsL), small+large, len(lookupsS), small)
		})
	}
}

// TestAuditLogs_QueryCountDoesNotGrowWithActors: resolving actor names issued one
// GetUser per distinct actor on the page.
func TestAuditLogs_QueryCountDoesNotGrowWithActors(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			const nUsers = 60
			f := newLEFixture(t, backend, nUsers)
			ok := true
			evs := make([]models.AuditEvent, 0, nUsers)
			for i := range f.users {
				uid := f.users[i].ID
				evs = append(evs, models.AuditEvent{
					EventType: "secret.read", UserID: &uid, Success: &ok, ActorType: "user",
					EventTime: f.now.Add(-time.Duration(i) * time.Second),
				})
			}
			require.NoError(t, f.w.a.db.CreateInBatches(&evs, 100).Error)

			for _, route := range []string{"/api/v1/audit/logs", "/api/v1/audit/search?q=secret"} {
				sep := "?"
				if strings.Contains(route, "?") {
					sep = "&"
				}
				stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, route+sep+"page_size=2")
				stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, route+sep+"page_size=50")
				require.Equal(t, http.StatusOK, stS, bodyS)
				require.Equal(t, http.StatusOK, stL, bodyL)
				require.Contains(t, bodyL, "leuser", "actor names must still be resolved")
				require.LessOrEqual(t, len(sqlL), len(sqlS)+1,
					"%s: %d statements for 50 rows vs %d for 2: the list issues statements per actor", route, len(sqlL), len(sqlS))
			}
		})
	}
}

// TestUsersList_QueryCountDoesNotGrowWithPageSize: the project-count enrichment read
// each user's role scopes (two statements) and onboarding journal (one) separately.
func TestUsersList_QueryCountDoesNotGrowWithPageSize(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			f := newLEFixture(t, backend, 60)
			stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, "/api/v1/users?page_size=2")
			stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, "/api/v1/users?page_size=50")
			require.Equal(t, http.StatusOK, stS, bodyS)
			require.Equal(t, http.StatusOK, stL, bodyL)
			require.Contains(t, bodyL, `"project_count"`, "the enrichment must still be present")
			require.LessOrEqual(t, len(sqlL), len(sqlS)+1,
				"%d statements for 50 users vs %d for 2: the list issues statements per user", len(sqlL), len(sqlS))
		})
	}
}

// TestProjectAccessReview_QueryCountDoesNotGrowWithSecrets: the review listed shares per
// secret and looked up every distinct owner, recipient, group and machine one by one.
func TestProjectAccessReview_QueryCountDoesNotGrowWithSecrets(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			const small, large = 6, 60
			f := newLEFixture(t, backend, large)
			smallID := f.project(t, "arsmall", small)
			largeID := f.project(t, "arlarge", large)
			stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, fmt.Sprintf("/api/v1/projects/%d/access-review", smallID))
			stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, fmt.Sprintf("/api/v1/projects/%d/access-review", largeID))
			require.Equal(t, http.StatusOK, stS, bodyS)
			require.Equal(t, http.StatusOK, stL, bodyL)
			require.Contains(t, bodyL, "leuser", "share recipients must still be named")
			require.LessOrEqual(t, len(sqlL), len(sqlS)+3,
				"%d statements for %d secrets vs %d for %d: the review issues statements per secret or principal", len(sqlL), large, len(sqlS), small)
		})
	}
}

// TestSecretsInventoryCSV_QueryCountDoesNotGrowWithOwners: one GetUser per distinct owner.
func TestSecretsInventoryCSV_QueryCountDoesNotGrowWithOwners(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			const small, large = 6, 60
			f := newLEFixture(t, backend, large)
			smallID := f.project(t, "invsmall", small)
			largeID := f.project(t, "invlarge", large)
			for _, pid := range []uint{smallID, largeID} {
				var secs []models.SecretNode
				require.NoError(t, f.w.a.db.Where("project_id = ?", pid).Find(&secs).Error)
				for i := range secs {
					require.NoError(t, f.w.a.db.Model(&models.SecretNode{}).Where("id = ?", secs[i].ID).
						Update("owner_id", f.users[i%len(f.users)].ID).Error)
				}
			}
			stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, fmt.Sprintf("/api/v1/projects/%d/secrets/inventory.csv", smallID))
			stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, fmt.Sprintf("/api/v1/projects/%d/secrets/inventory.csv", largeID))
			require.Equal(t, http.StatusOK, stS, bodyS)
			require.Equal(t, http.StatusOK, stL, bodyL)
			require.Contains(t, bodyL, "leuser", "owner names must still be resolved")
			require.LessOrEqual(t, len(sqlL), len(sqlS)+1,
				"%d statements for %d owners vs %d for %d: one lookup per owner", len(sqlL), large, len(sqlS), small)
		})
	}
}

// TestMachineAuditReport_QueryCountDoesNotGrowWithIdentities: one credential list per identity.
func TestMachineAuditReport_QueryCountDoesNotGrowWithIdentities(t *testing.T) {
	for _, backend := range leBackends(t) {
		t.Run(backend, func(t *testing.T) {
			f := newLEFixture(t, backend, 1)
			db := f.w.a.db
			seed := func(prefix string, n int) {
				for i := range n {
					m := models.MachineIdentity{ProjectID: f.w.projectID, Name: fmt.Sprintf("%s%03d", prefix, i), IdentityType: "ci", State: "active", CreatedAt: f.now, UpdatedAt: f.now}
					require.NoError(t, db.Create(&m).Error)
					used := f.now.Add(-time.Hour)
					require.NoError(t, db.Create(&models.MachineIdentityCredential{
						MachineIdentityID: m.ID, Name: "c", TokenHash: fmt.Sprintf("%s-%d-h", prefix, i), LastUsedAt: &used, CreatedAt: f.now,
					}).Error)
				}
			}
			seed("few", 4)
			stS, bodyS, sqlS := f.rec.get(t, f.w, f.token, "/api/v1/machine-identities/audit")
			seed("many", 56)
			stL, bodyL, sqlL := f.rec.get(t, f.w, f.token, "/api/v1/machine-identities/audit")
			require.Equal(t, http.StatusOK, stS, bodyS)
			require.Equal(t, http.StatusOK, stL, bodyL)
			require.Contains(t, bodyL, "many055")
			require.LessOrEqual(t, len(sqlL), len(sqlS)+1,
				"%d statements for 60 identities vs %d for 4: one credential query per identity", len(sqlL), len(sqlS))
		})
	}
}
