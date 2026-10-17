package core

// authz_secret_batch_equivalence_test.go — SHARES-BATCH-AUTHZ-1.
//
// AuthorizeSecretsBatch must decide every secret exactly as AuthorizeSecret does, for
// every rule the per-row decision has: PAT restriction, ACL (own and folder-ancestor,
// membership-gated), role at the secret's project/environment (direct, via group, with
// expiry, deleted project/environment/group, admin bypass), the share term (direct and
// group, expired, revoked, corrupt level, scoped group membership, project membership
// at access time) and the elevation audit it records.
//
// TestAuthorizeSecretsBatch_EqualsPerRow builds one world holding the cross product of
//
//	principals: role kind x group-membership kind
//	secrets:    location (project/env, deleted project/env, global, folder, nested,
//	            deeper than the walk's cap, ancestor in another project, deleted ancestor,
//	            parent cycle) x share state (none, direct, group, expired, revoked, corrupt)
//	ACL rows:   a deterministic spread over (principal, node) on leaves and folders
//
// and asserts, for every principal, permission and PAT context, that the per-row and
// batch decisions are identical secret by secret and that they record the same share
// elevations in the same order. The matrix is built from the rules, not from the batch
// code; a rule the batch gets wrong shows up as the (principal, secret) pairs that
// differ. TestAuthorizeSecretsBatch_QueryCountDoesNotGrowWithRows pins the statements.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type sbUser struct {
	id    uint
	label string
}

type sbWorld struct {
	w       *c4World
	users   []sbUser
	targets []*models.SecretNode // the secrets (and a few folders) every decision is made on
	p1, p2  *models.Project
	e1a     *models.Environment
}

// sbShareStates are the share rows a secret carries (the recipients are spread over the
// principals, see addShares).
var sbShareStates = []string{
	"none", "direct-read", "direct-write", "direct-read-expired", "direct-read-revoked",
	"direct-corrupt", "group-read", "group-write", "group-read-expired", "group-corrupt", "mixed",
}

var sbRoleKinds = []string{
	"none", "read@p1", "read@p1/e1a", "read@global", "write@p1", "bypass@p1", "bypass@global",
	"read@p1-expired", "read@p1-future", "read@p2", "read@deleted-project", "read@p1+deleted-env-secret",
	"member@p1(no perms)", "read@p1-via-group", "read-via-deleted-group", "read-via-group-member-scoped-p2",
	"member@p1-via-group", "read@p1-via-expired-group",
}

var sbGroupKinds = []string{"no-share-group", "share-group-global", "share-group-scoped-p1", "share-group-scoped-p2", "share-group-deleted"}

func sbBuild(t *testing.T, backend string) *sbWorld {
	t.Helper()
	w := newC4World(t, backend)
	db := w.db
	sw := &sbWorld{w: w}

	pRead := w.permission(permSecretsRead)
	pWrite := w.permission(permSecretsWrite)
	rRead := w.role(false, pRead)
	rWrite := w.role(false, pWrite)
	rBypass := w.role(true)
	rNone := w.role(false)

	sw.p1, sw.p2 = w.project(), w.project()
	pDel := w.project()
	sw.e1a = w.env(sw.p1.ID)
	e1b := w.env(sw.p1.ID)
	e1del := w.env(sw.p1.ID)
	e2 := w.env(sw.p2.ID)
	eDel := w.env(pDel.ID)

	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	// Groups: roles through a group, and the groups shares are made to.
	gRole := func(roleID, projectID uint, exp *time.Time) *models.Group {
		g := w.group()
		require.NoError(t, db.Create(&models.GroupRole{GroupID: g.ID, RoleID: roleID, ProjectID: projectID, ExpiresAt: exp}).Error)
		return g
	}
	gRead := gRole(rRead.ID, sw.p1.ID, nil)
	gReadDeleted := gRole(rRead.ID, sw.p1.ID, nil)
	gReadScoped := gRole(rRead.ID, sw.p1.ID, nil)
	gMember := gRole(rNone.ID, sw.p1.ID, nil)
	gReadExpired := gRole(rRead.ID, sw.p1.ID, &past)
	require.NoError(t, db.Delete(&models.Group{}, gReadDeleted.ID).Error)
	shareGroups := []*models.Group{w.group(), w.group(), w.group(), w.group()}
	require.NoError(t, db.Delete(&models.Group{}, shareGroups[3].ID).Error)

	for _, rk := range sbRoleKinds {
		for _, gk := range sbGroupKinds {
			u := w.user()
			sw.users = append(sw.users, sbUser{id: u.ID, label: rk + "/" + gk})
			grant := func(roleID, project, env uint, exp *time.Time) {
				require.NoError(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: roleID, ProjectID: project, EnvironmentID: env, ExpiresAt: exp}).Error)
			}
			member := func(groupID, project uint) {
				require.NoError(t, db.Create(&models.UserGroup{UserID: u.ID, GroupID: groupID, ProjectID: project}).Error)
			}
			switch rk {
			case "read@p1":
				grant(rRead.ID, sw.p1.ID, 0, nil)
			case "read@p1/e1a":
				grant(rRead.ID, sw.p1.ID, sw.e1a.ID, nil)
			case "read@global":
				grant(rRead.ID, 0, 0, nil)
			case "write@p1":
				grant(rWrite.ID, sw.p1.ID, 0, nil)
			case "bypass@p1":
				grant(rBypass.ID, sw.p1.ID, 0, nil)
			case "bypass@global":
				grant(rBypass.ID, 0, 0, nil)
			case "read@p1-expired":
				grant(rRead.ID, sw.p1.ID, 0, &past)
			case "read@p1-future":
				grant(rRead.ID, sw.p1.ID, 0, &future)
			case "read@p2":
				grant(rRead.ID, sw.p2.ID, 0, nil)
			case "read@deleted-project":
				grant(rRead.ID, pDel.ID, 0, nil)
			case "read@p1+deleted-env-secret":
				grant(rRead.ID, sw.p1.ID, e1del.ID, nil)
			case "member@p1(no perms)":
				grant(rNone.ID, sw.p1.ID, 0, nil)
			case "read@p1-via-group":
				member(gRead.ID, 0)
			case "read-via-deleted-group":
				member(gReadDeleted.ID, 0)
			case "read-via-group-member-scoped-p2":
				member(gReadScoped.ID, sw.p2.ID)
			case "member@p1-via-group":
				member(gMember.ID, 0)
			case "read@p1-via-expired-group":
				member(gReadExpired.ID, 0)
			}
			switch gk {
			case "share-group-global":
				member(shareGroups[0].ID, 0)
			case "share-group-scoped-p1":
				member(shareGroups[1].ID, sw.p1.ID)
			case "share-group-scoped-p2":
				member(shareGroups[2].ID, sw.p2.ID)
			case "share-group-deleted":
				member(shareGroups[3].ID, 0)
			}
		}
	}
	require.NoError(t, db.Delete(&models.Environment{}, e1del.ID).Error)
	require.NoError(t, db.Delete(&models.Project{}, pDel.ID).Error)

	owner := sw.users[0].id
	node := func(name string, parent *models.SecretNode, project, env uint, isSecret bool) *models.SecretNode {
		n := &models.SecretNode{
			Name: name, ProjectID: project, EnvironmentID: env, IsSecret: isSecret, Type: "generic",
			Status: "active", OwnerID: owner, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if parent != nil {
			pid := parent.ID
			n.ParentID = &pid
		}
		require.NoError(t, db.Create(n).Error)
		return n
	}

	// Parents the leaves hang off.
	f1 := node("f1", nil, sw.p1.ID, sw.e1a.ID, false)
	f2 := node("f2", nil, sw.p1.ID, e1b.ID, false)
	f3 := node("f3", f2, sw.p1.ID, e1b.ID, false)
	deepRoot := node("deep-0", nil, sw.p1.ID, sw.e1a.ID, false)
	chain := []*models.SecretNode{deepRoot}
	for i := 1; i < 25; i++ {
		chain = append(chain, node(fmt.Sprintf("deep-%d", i), chain[i-1], sw.p1.ID, sw.e1a.ID, false))
	}
	foreignFolder := node("foreign-folder", nil, sw.p2.ID, e2.ID, false)
	goneFolder := node("gone-folder", nil, sw.p1.ID, sw.e1a.ID, false)
	cycA := node("cyc-a", nil, sw.p1.ID, sw.e1a.ID, true)
	cycB := node("cyc-b", cycA, sw.p1.ID, sw.e1a.ID, true)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", cycA.ID).Update("parent_id", cycB.ID).Error)
	require.NoError(t, db.First(cycA, cycA.ID).Error) // the batch decides on the rows it is given: hand it the stored ones

	// ACL-capable nodes: every leaf and every folder, spread over the principals.
	var aclNodes []*models.SecretNode
	aclNodes = append(aclNodes, f1, f2, f3, foreignFolder, goneFolder, cycA, cycB)
	aclNodes = append(aclNodes, chain...)

	type location struct {
		name              string
		parent            *models.SecretNode
		project, env      uint
		suspendedProperty bool
	}
	locations := []location{
		{name: "p1e1a", project: sw.p1.ID, env: sw.e1a.ID},
		{name: "p1e1b", project: sw.p1.ID, env: e1b.ID},
		{name: "p2e2", project: sw.p2.ID, env: e2.ID},
		{name: "deleted-project", project: pDel.ID, env: eDel.ID},
		{name: "deleted-env", project: sw.p1.ID, env: e1del.ID},
		{name: "global", project: 0, env: 0},
		{name: "in-folder", parent: f1, project: sw.p1.ID, env: sw.e1a.ID},
		{name: "nested", parent: f3, project: sw.p1.ID, env: e1b.ID},
		{name: "deep", parent: chain[24], project: sw.p1.ID, env: sw.e1a.ID},
		{name: "foreign-folder", parent: foreignFolder, project: sw.p1.ID, env: sw.e1a.ID},
		{name: "gone-parent", parent: goneFolder, project: sw.p1.ID, env: sw.e1a.ID},
		{name: "suspended", project: sw.p1.ID, env: sw.e1a.ID, suspendedProperty: true},
	}
	var leaves []*models.SecretNode
	idx := 0
	for _, loc := range locations {
		for _, st := range sbShareStates {
			leaf := node(fmt.Sprintf("%s|%s", loc.name, st), loc.parent, loc.project, loc.env, true)
			if loc.suspendedProperty {
				require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", leaf.ID).Update("status", "suspended").Error)
				leaf.Status = "suspended"
			}
			sw.addShares(t, leaf, st, idx, shareGroups)
			leaves = append(leaves, leaf)
			idx++
		}
	}
	aclNodes = append(aclNodes, leaves...)
	require.NoError(t, db.Delete(&models.SecretNode{}, goneFolder.ID).Error)

	// Explicit ACL cases the spread cannot be trusted to hit: a grant on an ancestor
	// beyond the walk's cap, one just inside it, one on a folder in a project the
	// grantee is (not) a member of, and one on a deleted folder, which makes the per-row
	// decision error and deny even for a user whose role would allow.
	userByLabel := map[string]uint{}
	for _, u := range sw.users {
		userByLabel[u.label] = u.id
	}
	explicit := []struct {
		label string
		node  *models.SecretNode
	}{
		{"member@p1(no perms)/share-group-global", chain[2]},
		{"member@p1(no perms)/share-group-scoped-p1", chain[8]},
		{"member@p1(no perms)/no-share-group", foreignFolder},
		{"read@p2/no-share-group", foreignFolder},
		{"read@p1/no-share-group", goneFolder},
		{"read@p1/share-group-global", cycB},
		{"member@p1(no perms)/share-group-scoped-p2", cycB},
	}
	explicitUser := map[uint]bool{} // no spread ACLs for these: their one ACL is the whole story
	var acls []models.SecretACL
	for _, e := range explicit {
		uid, ok := userByLabel[e.label]
		require.True(t, ok, e.label)
		explicitUser[uid] = true
		acls = append(acls, models.SecretACL{SecretID: e.node.ID, UserID: uid, Permissions: `["secrets.read"]`, GrantedBy: owner, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	}
	// ACL rows: ~13% of (principal, node) pairs; read, write only, or both.
	perms := []string{`["secrets.read"]`, `["secrets.write"]`, `["secrets.read","secrets.write"]`}
	for j, u := range sw.users {
		for i, n := range aclNodes {
			if k := (j*7 + i*3) % 23; k < 3 && !explicitUser[u.id] {
				acls = append(acls, models.SecretACL{SecretID: n.ID, UserID: u.id, Permissions: perms[k], GrantedBy: owner, CreatedAt: time.Now(), UpdatedAt: time.Now()})
			}
		}
	}
	require.NoError(t, db.CreateInBatches(&acls, 200).Error)

	sw.targets = append(sw.targets, leaves...)
	sw.targets = append(sw.targets, f1, f2, f3, chain[3], foreignFolder, cycA, cycB)
	return sw
}

// addShares creates the share rows of one state on leaf. Direct states give a share to
// the principals whose index plus the secret's index is even; group states share to all
// four share groups (one of them deleted).
func (sw *sbWorld) addShares(t *testing.T, leaf *models.SecretNode, state string, idx int, groups []*models.Group) {
	t.Helper()
	db := sw.w.db
	past := time.Now().Add(-time.Hour)
	owner := sw.users[0].id
	direct := func(perm string, exp *time.Time) {
		var rows []models.ShareRecord
		for j, u := range sw.users {
			if (j+idx)%2 == 0 {
				rows = append(rows, models.ShareRecord{SecretID: leaf.ID, OwnerID: owner, RecipientID: u.id, Permission: perm, ExpiresAt: exp})
			}
		}
		require.NoError(t, db.CreateInBatches(&rows, 100).Error)
	}
	group := func(perm string, exp *time.Time) {
		for _, g := range groups {
			require.NoError(t, db.Create(&models.ShareRecord{SecretID: leaf.ID, OwnerID: owner, RecipientID: g.ID, IsGroup: true, Permission: perm, ExpiresAt: exp}).Error)
		}
	}
	switch state {
	case "direct-read":
		direct("read", nil)
	case "direct-write":
		direct("write", nil)
	case "direct-read-expired":
		direct("read", &past)
	case "direct-read-revoked":
		direct("read", nil)
		require.NoError(t, db.Where("secret_id = ?", leaf.ID).Delete(&models.ShareRecord{}).Error)
	case "direct-corrupt":
		direct("owner", nil)
	case "group-read":
		group("read", nil)
	case "group-write":
		group("write", nil)
	case "group-read-expired":
		group("read", &past)
	case "group-corrupt":
		group("owner", nil)
	case "mixed":
		direct("read", nil)
		group("write", nil)
	}
}

// sbRender is one recorded share elevation as a comparable string.
func sbRender(es []shareElevation) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, fmt.Sprintf("user=%d secret=%d perm=%s action=%s share=%d level=%s source=%s",
			e.userID, e.secretID, e.perm, e.action, *e.grant.ShareID, e.grant.Level, e.grant.Source))
	}
	return out
}

func TestAuthorizeSecretsBatch_EqualsPerRow(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			sw := sbBuild(t, backend)
			c := sw.w.core
			type patCase struct {
				name string
				pat  *PATRestriction
			}
			pats := []patCase{
				{"no-pat", nil},
				{"pat-p1", &PATRestriction{ProjectID: sw.p1.ID}},
				{"pat-write-only", &PATRestriction{Permissions: []string{permSecretsWrite}}},
				{"pat-env", &PATRestriction{EnvironmentID: sw.e1a.ID}},
			}
			var decisions, allowed, denied, elevations, aclOnly, auditRows int
			var diffs []string
			for ui, u := range sw.users {
				cases := pats[:1]
				if ui%9 == 0 {
					cases = pats
				}
				for _, pc := range cases {
					for _, perm := range []string{permSecretsRead, permSecretsWrite} {
						base := context.Background()
						if pc.pat != nil {
							base = WithPATRestriction(base, pc.pat)
						}
						perCtx, perRec := WithShareElevationRecorder(base)
						per := make([]bool, len(sw.targets))
						for i, s := range sw.targets {
							per[i], _ = c.AuthorizeSecret(perCtx, u.id, s.ID, perm)
						}
						batCtx, batRec := WithShareElevationRecorder(base)
						got, err := c.AuthorizeSecretsBatch(batCtx, u.id, perm, sw.targets)
						require.NoError(t, err)
						require.Len(t, got, len(sw.targets))

						perElev, batElev := sbRender(perRec.drain()), sbRender(batRec.drain())
						for i, s := range sw.targets {
							decisions++
							if per[i] {
								allowed++
							} else {
								denied++
							}
							if got[s.ID] != per[i] {
								diffs = append(diffs, fmt.Sprintf("%s / %s / %s on %q: per-row=%v batch=%v", u.label, pc.name, perm, s.Name, per[i], got[s.ID]))
							}
						}
						if fmt.Sprint(perElev) != fmt.Sprint(batElev) {
							diffs = append(diffs, fmt.Sprintf("%s / %s / %s: share elevations differ\n  per-row: %v\n  batch:   %v", u.label, pc.name, perm, perElev, batElev))
						}
						elevations += len(perElev)
						// A project member whose role grants nothing, on a secret nobody shared,
						// can only be allowed by an ACL grant (here: on an ancestor 16 levels up).
						if perm == permSecretsRead && pc.pat == nil && u.label == "member@p1(no perms)/share-group-scoped-p1" {
							for i, s := range sw.targets {
								if per[i] && s.Name == "deep|none" {
									aclOnly++
								}
							}
						}
					}
				}
			}
			// Without a request recorder (the GET /shares route has none) a read elevation
			// is audited at once: per-row and batch must write the same rows.
			for ui, u := range sw.users {
				if ui%7 != 0 {
					continue
				}
				before := sbAuditHighWater(t, sw.w.db)
				for _, s := range sw.targets {
					_, _ = c.AuthorizeSecret(context.Background(), u.id, s.ID, permSecretsRead)
				}
				perRows := sbAuditSince(t, sw.w.db, before)
				mid := sbAuditHighWater(t, sw.w.db)
				_, err := c.AuthorizeSecretsBatch(context.Background(), u.id, permSecretsRead, sw.targets)
				require.NoError(t, err)
				batRows := sbAuditSince(t, sw.w.db, mid)
				if fmt.Sprint(perRows) != fmt.Sprint(batRows) {
					diffs = append(diffs, fmt.Sprintf("%s: audit rows differ without a recorder\n  per-row: %d rows\n  batch:   %d rows", u.label, len(perRows), len(batRows)))
				}
				auditRows += len(perRows)
			}
			require.Empty(t, diffs, "the batch authoriser and the per-row decision differ on %d of %d decisions; first: %v", len(diffs), decisions, firstN(diffs, 15))
			// The matrix must exercise every outcome, or equality proves little.
			require.Positive(t, allowed, "no decision allowed: the matrix is vacuous")
			require.Positive(t, denied, "no decision denied: the matrix is vacuous")
			require.Positive(t, elevations, "no share elevation recorded: the share term is not exercised")
			require.Positive(t, auditRows, "no share elevation audited without a recorder: the immediate-audit path is not exercised")
			require.Positive(t, aclOnly, "no ACL-only allow in the matrix: the ACL term is not exercised")
			t.Logf("%s: %d decisions equal (%d allowed, %d denied, %d share elevations)", backend, decisions, allowed, denied, elevations)
		})
	}
}

func sbAuditHighWater(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	var max uint
	require.NoError(t, db.Model(&models.AuditEvent{}).Select("COALESCE(MAX(id), 0)").Scan(&max).Error)
	return max
}

// sbAuditSince renders the share_access_elevated rows written after id.
func sbAuditSince(t *testing.T, db *gorm.DB, after uint) []string {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, db.Where("id > ? AND event_type = ?", after, string(ShareAuditEventAccessElevated)).Order("id").Find(&rows).Error)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("user=%v secret=%v project=%v desc=%s diff=%s", ptrVal(r.UserID), ptrVal(r.SecretNodeID), ptrVal(r.ProjectID), r.Description, r.Diff))
	}
	return out
}

func ptrVal(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

// TestAuthorizeSecretsBatch_InputShape: a nil entry is skipped and a secret listed
// twice is decided once; an empty page costs nothing and returns an empty map.
func TestAuthorizeSecretsBatch_InputShape(t *testing.T) {
	w := newC4World(t, "sqlite")
	counter := c4CountStatements(t, w.db)
	u := w.user()
	var got map[uint]bool
	var err error
	stmts := counter.during(func() {
		got, err = w.core.AuthorizeSecretsBatch(context.Background(), u.ID, permSecretsRead, nil)
	})
	require.NoError(t, err)
	require.Empty(t, got)
	require.Empty(t, stmts, "an empty page must not read anything")

	p := w.project()
	n := &models.SecretNode{Name: "s", ProjectID: p.ID, IsSecret: true, Type: "generic", Status: "active", OwnerID: u.ID, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	require.NoError(t, w.db.Create(n).Error)
	got, err = w.core.AuthorizeSecretsBatch(context.Background(), u.ID, permSecretsRead, []*models.SecretNode{nil, n, n})
	require.NoError(t, err)
	require.Equal(t, map[uint]bool{n.ID: false}, got)
}

// TestAuthorizeSecretsBatch_QueryCountDoesNotGrowWithRows: the statements one page costs
// are the same for 3 secrets and for 60, in every decision path (role, ACL with a folder
// walk, direct and group share, nothing granting).
func TestAuthorizeSecretsBatch_QueryCountDoesNotGrowWithRows(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			s := w.core.storage
			ctx := context.Background()
			pRead := w.permission(permSecretsRead)
			rRead, rNone := w.role(false, pRead), w.role(false)
			owner := w.user()

			// One user per path, each over its own set of projects so per-project work
			// would show too.
			readUser, aclUser, shareUser, groupShareUser, noneUser := w.user(), w.user(), w.user(), w.user(), w.user()
			shareGroup := w.group()
			require.NoError(t, s.AddUserToGroup(ctx, groupShareUser.ID, shareGroup.ID, 0))

			const small, large = 3, 60
			build := func(n int) []*models.SecretNode {
				var out []*models.SecretNode
				folder := &models.SecretNode{Name: w.name("folder"), IsSecret: false, Type: "generic", Status: "active", OwnerID: owner.ID, CreatedAt: time.Now(), UpdatedAt: time.Now()}
				fp := w.project()
				folder.ProjectID, folder.EnvironmentID = fp.ID, w.env(fp.ID).ID
				require.NoError(t, w.db.Create(folder).Error)
				require.NoError(t, s.AssignRole(ctx, aclUser.ID, rNone.ID, Scope{ProjectID: fp.ID}))
				require.NoError(t, w.db.Create(&models.SecretACL{SecretID: folder.ID, UserID: aclUser.ID, Permissions: `["secrets.read"]`, GrantedBy: owner.ID}).Error)
				for range n {
					p := w.project() // a project per secret: nothing may be done per project either
					e := w.env(p.ID)
					require.NoError(t, s.AssignRole(ctx, readUser.ID, rRead.ID, Scope{ProjectID: p.ID}))
					for _, u := range []*models.User{shareUser, groupShareUser} {
						require.NoError(t, s.AssignRole(ctx, u.ID, rNone.ID, Scope{ProjectID: p.ID}))
					}
					require.NoError(t, s.AssignRoleToGroup(ctx, shareGroup.ID, rNone.ID, Scope{ProjectID: p.ID}))
					parent := folder.ID
					sec := &models.SecretNode{Name: w.name("sec"), ProjectID: fp.ID, EnvironmentID: folder.EnvironmentID, ParentID: &parent, IsSecret: true, Type: "generic", Status: "active", OwnerID: owner.ID, CreatedAt: time.Now(), UpdatedAt: time.Now()}
					plain := &models.SecretNode{Name: w.name("sec"), ProjectID: p.ID, EnvironmentID: e.ID, IsSecret: true, Type: "generic", Status: "active", OwnerID: owner.ID, CreatedAt: time.Now(), UpdatedAt: time.Now()}
					require.NoError(t, w.db.Create(sec).Error)
					require.NoError(t, w.db.Create(plain).Error)
					require.NoError(t, w.db.Create(&models.ShareRecord{SecretID: plain.ID, OwnerID: owner.ID, RecipientID: shareUser.ID, Permission: "read"}).Error)
					require.NoError(t, w.db.Create(&models.ShareRecord{SecretID: plain.ID, OwnerID: owner.ID, RecipientID: shareGroup.ID, IsGroup: true, Permission: "read"}).Error)
					out = append(out, sec, plain)
				}
				return out
			}
			smallPage, largePage := build(small), build(large)
			counter := c4CountStatements(t, w.db)
			// A recorder, as on every per-secret route: without one each share-granted
			// read writes its own audit row (see the equivalence test), which is a write
			// the decision makes, not a read it needs.
			ctx, _ = WithShareElevationRecorder(ctx)

			for _, tc := range []struct {
				name string
				user *models.User
			}{{"role", readUser}, {"acl-folder", aclUser}, {"direct-share", shareUser}, {"group-share", groupShareUser}, {"nothing", noneUser}} {
				var gotL map[uint]bool
				sqlS := counter.during(func() {
					_, err := w.core.AuthorizeSecretsBatch(ctx, tc.user.ID, permSecretsRead, smallPage)
					require.NoError(t, err)
				})
				sqlL := counter.during(func() {
					var err error
					gotL, err = w.core.AuthorizeSecretsBatch(ctx, tc.user.ID, permSecretsRead, largePage)
					require.NoError(t, err)
				})
				yes := func(m map[uint]bool) int {
					n := 0
					for _, ok := range m {
						if ok {
							n++
						}
					}
					return n
				}
				if tc.name != "nothing" {
					require.Positive(t, yes(gotL), "%s: the path was not exercised (nothing allowed)", tc.name)
				}
				require.LessOrEqual(t, len(sqlL), len(sqlS), "%s: %d statements for %d secrets vs %d for %d: the batch issues statements per row", tc.name, len(sqlL), len(largePage), len(sqlS), len(smallPage))
				t.Logf("%s: %d statements for %d secrets, %d for %d", tc.name, len(sqlL), len(largePage), len(sqlS), len(smallPage))
			}
		})
	}
}
