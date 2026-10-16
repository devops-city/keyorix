// authz_secret_batch.go — AuthorizeSecretsBatch (SHARES-BATCH-AUTHZ-1).
//
// A list endpoint that must know, for each secret on its page, whether the caller may
// perm it (the shares list printing a secret's name only to a reader, #3153) used to
// call AuthorizeSecret once per secret: ACL rows and a folder walk, the secret fetch,
// the role resolution, the secret's shares, the group memberships and the project
// membership, a handful of statements per row, N rows deep.
//
// AuthorizeSecretsBatch decides the whole page from a fixed number of statements and
// returns, for every secret, exactly what AuthorizeSecret(ctx, userID, secret.ID, perm)
// returns for a human user. It is not a second policy: each step is the per-row step
// with its read done once for the page, and every pure rule is the per-row function
// itself (shareNeedFor, shareMayElevate, directShareGrant, highestGroupShare,
// groupShareGrant, UserRoleGrant.AppliesAt over ResolveUserPermissionAt's own role
// predicates). The steps, in AuthorizeSecretAction's order:
//
//  1. the PAT restriction against the secret's scope (no read);
//  2. an ACL grant of perm on the secret or one of its folder ancestors, honoured only
//     while the user is a live member of the granting node's project (HasSecretACL);
//  3. the role decision at the secret's project/environment (Authorize);
//  4. the share term (sharePermissionFor, no action named, so a write share elevates
//     nothing): an active direct share, else a group share through a group the user
//     is in, both only for a live project member, each recording its elevation on the
//     request exactly as the per-row decision does (noteShareElevation).
//
// A per-row decision that errors (a missing ancestor node, a failed role lookup) is a
// denial of that row, as annotateShareViewSecrets always treated it. A failure of a
// batch read returns the error and no decisions: the caller fails closed.
//
// A machine principal never reaches this path (AuthorizeSecretPrincipal), and neither
// does a caller that names a SecretAction: this is the "list view" form, action "".
//
// Statements: ACL listing, ancestor levels (at most secretAncestorDepthCap, only when
// the user holds an ACL of perm), project memberships (at most two), role grants, the
// page's shares, the user's group memberships. None grows with the number of secrets.
// TestAuthorizeSecretsBatch_EqualsPerRow pins the equivalence over a generated matrix;
// TestAuthorizeSecretsBatch_QueryCountDoesNotGrowWithRows pins the statement count.
package core

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// secretAncestorDepthCap mirrors the storage walk's cap (store.maxAncestorDepth): the
// per-row HasSecretACL looks at no more than this many ancestors, so the batch must
// not either. The equivalence matrix includes a chain deeper than the cap.
const secretAncestorDepthCap = 20

type batchVerdict uint8

const (
	batchUndecided batchVerdict = iota
	batchAllow
	batchDeny
)

// AuthorizeSecretsBatch: see the file header. The result has an entry for every
// non-nil secret in secrets; a secret listed twice is decided once.
func (c *KeyorixCore) AuthorizeSecretsBatch(ctx context.Context, userID uint, perm string, secrets []*models.SecretNode) (map[uint]bool, error) {
	rows := make([]*models.SecretNode, 0, len(secrets))
	seen := make(map[uint]struct{}, len(secrets))
	for _, s := range secrets {
		if s == nil {
			continue
		}
		if _, dup := seen[s.ID]; dup {
			continue
		}
		seen[s.ID] = struct{}{}
		rows = append(rows, s)
	}
	verdict := make(map[uint]batchVerdict, len(rows))
	pending := make([]*models.SecretNode, 0, len(rows))
	pat := patRestrictionFromContext(ctx)
	for _, s := range rows {
		if !pat.Allows(perm, Scope{ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID}) {
			verdict[s.ID] = batchDeny
			continue
		}
		pending = append(pending, s)
	}

	members := &batchMembership{known: map[uint]bool{}}
	var err error
	if pending, err = c.batchACLStage(ctx, userID, perm, pending, verdict, members); err != nil {
		return nil, err
	}
	if pending, err = c.batchRoleStage(ctx, userID, perm, pending, verdict); err != nil {
		return nil, err
	}
	if err = c.batchShareStage(ctx, userID, perm, pending, verdict, members); err != nil {
		return nil, err
	}

	out := make(map[uint]bool, len(rows))
	for _, s := range rows {
		out[s.ID] = verdict[s.ID] == batchAllow
	}
	return out, nil
}

// batchMembership caches IsProjectMember answers for one batch; ensure fetches the
// ones not known yet in one ProjectMembershipsAmong call.
type batchMembership struct {
	known map[uint]bool
}

func (m *batchMembership) ensure(ctx context.Context, c *KeyorixCore, userID uint, projectIDs []uint) error {
	var missing []uint
	for _, id := range projectIDs {
		if id == 0 {
			m.known[0] = false // IsProjectMember: project 0 is never a membership
			continue
		}
		if _, ok := m.known[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	missing = dedupeUints(missing)
	res, err := c.storage.ProjectMembershipsAmong(ctx, userID, missing)
	if err != nil {
		return err
	}
	for _, id := range missing {
		m.known[id] = res[id]
	}
	return nil
}

// batchACLStage is HasSecretACL for every pending secret (step 2). It returns the
// secrets still undecided.
func (c *KeyorixCore) batchACLStage(ctx context.Context, userID uint, perm string, pending []*models.SecretNode, verdict map[uint]batchVerdict, members *batchMembership) ([]*models.SecretNode, error) {
	if len(pending) == 0 {
		return pending, nil
	}
	acls, err := c.storage.ListSecretACLsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	// GetSecretACL returns the first row (by id) of a (secret, user) pair.
	withPerm := make(map[uint]bool, len(acls))
	seenACL := make(map[uint]struct{}, len(acls))
	for _, a := range acls {
		if _, dup := seenACL[a.SecretID]; dup {
			continue
		}
		seenACL[a.SecretID] = struct{}{}
		if slices.Contains(DecodeSecretACLPerms(a.Permissions), perm) {
			withPerm[a.SecretID] = true
		}
	}
	if len(withPerm) == 0 {
		return pending, nil // no ACL row grants perm: HasSecretACL is false for every secret
	}

	nodes, chains, err := c.batchSecretAncestry(ctx, pending)
	if err != nil {
		return nil, err
	}
	candidates := func(s *models.SecretNode) []uint {
		return append([]uint{s.ID}, chains[s.ID]...)
	}
	var projects []uint
	for _, s := range pending {
		for _, cand := range candidates(s) {
			if node := nodes[cand]; withPerm[cand] && node != nil {
				projects = append(projects, node.ProjectID)
			}
		}
	}
	if err := members.ensure(ctx, c, userID, projects); err != nil {
		return nil, err
	}

	remaining := make([]*models.SecretNode, 0, len(pending))
	for _, s := range pending {
		decided := false
		for _, cand := range candidates(s) {
			if !withPerm[cand] {
				continue
			}
			node := nodes[cand]
			if node == nil { // aclGrantsPermission: the node fetch failed, so the decision errors (deny)
				verdict[s.ID] = batchDeny
				decided = true
				break
			}
			if members.known[node.ProjectID] {
				verdict[s.ID] = batchAllow
				decided = true
				break
			}
		}
		if !decided {
			remaining = append(remaining, s)
		}
	}
	return remaining, nil
}

// batchSecretAncestry resolves, for every secret in rows, the ancestor chain
// GetSecretAncestors would return (immediate parent first, at most
// secretAncestorDepthCap, stopping at a root, a repeat or a parent that does not
// resolve) and the live node of every id that appears on a chain. It reads one
// level of nodes per round for all secrets together. An ancestor id whose node is
// not live is on the chain but absent from the node map, as in the walk.
func (c *KeyorixCore) batchSecretAncestry(ctx context.Context, rows []*models.SecretNode) (map[uint]*models.SecretNode, map[uint][]uint, error) {
	type walk struct {
		root    uint
		cur     uint
		visited map[uint]struct{}
		chain   []uint
		done    bool
	}
	nodes := make(map[uint]*models.SecretNode, len(rows))
	walks := make([]*walk, 0, len(rows))
	for _, s := range rows {
		nodes[s.ID] = s
		walks = append(walks, &walk{root: s.ID, cur: s.ID, visited: map[uint]struct{}{}})
	}
	absent := map[uint]struct{}{} // looked up, no live row
	fetch := func(ids []uint) error {
		var need []uint
		for _, id := range dedupeUints(ids) {
			_, known := nodes[id]
			if _, gone := absent[id]; !known && !gone {
				need = append(need, id)
			}
		}
		if len(need) == 0 {
			return nil
		}
		fetched, err := c.storage.GetSecretsByIDs(ctx, need)
		if err != nil {
			return err
		}
		for _, n := range fetched {
			if n != nil {
				nodes[n.ID] = n
			}
		}
		for _, id := range need {
			if _, ok := nodes[id]; !ok {
				absent[id] = struct{}{}
			}
		}
		return nil
	}
	for range secretAncestorDepthCap {
		var cur []uint
		for _, w := range walks {
			if !w.done {
				cur = append(cur, w.cur)
			}
		}
		if err := fetch(cur); err != nil {
			return nil, nil, err
		}
		advanced := false
		for _, w := range walks {
			if w.done {
				continue
			}
			node, ok := nodes[w.cur]
			if !ok || node.ParentID == nil {
				w.done = true
				continue
			}
			parent := *node.ParentID
			if _, cycle := w.visited[parent]; cycle {
				w.done = true
				continue
			}
			w.visited[parent] = struct{}{}
			w.chain = append(w.chain, parent)
			w.cur = parent
			advanced = true
		}
		if !advanced {
			break
		}
	}
	// The last ancestor a walk appended was never a walk position, and HasSecretACL
	// resolves every ancestor it looks at: fetch those too.
	var tail []uint
	for _, w := range walks {
		tail = append(tail, w.chain...)
	}
	if err := fetch(tail); err != nil {
		return nil, nil, err
	}
	chains := make(map[uint][]uint, len(walks))
	for _, w := range walks {
		chains[w.root] = w.chain
	}
	return nodes, chains, nil
}

// batchRoleStage is Authorize at each pending secret's scope (step 3): the user's
// role grants are read once and the role set at a scope is derived in memory
// (UserRoleGrant.AppliesAt), then answered as ResolveUserPermissionAt does: empty
// set denies, an admin-bypass role allows, otherwise RoleSetHasPermission (asked once
// per distinct role set). Secrets the role allows are decided; the rest go on.
func (c *KeyorixCore) batchRoleStage(ctx context.Context, userID uint, perm string, pending []*models.SecretNode, verdict map[uint]batchVerdict) ([]*models.SecretNode, error) {
	if len(pending) == 0 {
		return pending, nil
	}
	grants, err := c.storage.ListUserRoleGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	type decision struct {
		allowed bool
		err     error
	}
	byScope := map[Scope]decision{}
	bySet := map[string]decision{}
	decide := func(scope Scope) decision {
		if d, ok := byScope[scope]; ok {
			return d
		}
		var ids []uint
		bypass := false
		for _, g := range grants {
			if g.AppliesAt(scope) {
				ids = append(ids, g.RoleID)
				bypass = bypass || g.Bypass
			}
		}
		var d decision
		switch ids = dedupeUints(ids); {
		case len(ids) == 0:
		case bypass:
			d.allowed = true
		default:
			slices.Sort(ids)
			parts := make([]string, len(ids))
			for i, id := range ids {
				parts[i] = strconv.FormatUint(uint64(id), 10)
			}
			key := strings.Join(parts, ",")
			if cached, ok := bySet[key]; ok {
				d = cached
			} else {
				d.allowed, d.err = c.storage.RoleSetHasPermission(ctx, ids, perm)
				bySet[key] = d
			}
		}
		byScope[scope] = d
		return d
	}
	remaining := make([]*models.SecretNode, 0, len(pending))
	for _, s := range pending {
		d := decide(Scope{ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID})
		switch {
		case d.err != nil: // Authorize errored: the row is denied, the share term is not consulted
			verdict[s.ID] = batchDeny
		case d.allowed:
			verdict[s.ID] = batchAllow
		default:
			remaining = append(remaining, s)
		}
	}
	return remaining, nil
}

// batchShareStage is the share term for the secrets ACL and role both refused
// (step 4). Every secret still undecided after it is denied.
func (c *KeyorixCore) batchShareStage(ctx context.Context, userID uint, perm string, pending []*models.SecretNode, verdict map[uint]batchVerdict, members *batchMembership) error {
	if len(pending) == 0 {
		return nil
	}
	need := shareNeedFor(perm)
	if need == PermissionNone || !shareMayElevate(need, "") || userID == 0 {
		for _, s := range pending {
			verdict[s.ID] = batchDeny
		}
		return nil
	}
	ids := make([]uint, 0, len(pending))
	for _, s := range pending {
		ids = append(ids, s.ID)
	}
	now := c.shareEffectiveNow()
	all, err := c.storage.ListSharesBySecretIDs(ctx, ids, now)
	if err != nil {
		return err
	}
	bySecret := make(map[uint][]*models.ShareRecord, len(pending))
	for _, sh := range activeShares(all, now) {
		bySecret[sh.SecretID] = append(bySecret[sh.SecretID], sh)
	}
	for _, list := range bySecret {
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID }) // the single-secret read's natural order
	}

	var memberships []storage.UserGroupMembershipAt
	membershipsLoaded := false
	groupsAt := func(projectID uint) map[uint]struct{} {
		if !membershipsLoaded {
			// A failed lookup means no group share applies (activeShareGrant), for
			// every secret: remember it so the page costs one failed statement.
			memberships, _ = c.storage.ListUserLiveGroupMemberships(ctx, userID)
			membershipsLoaded = true
		}
		set := map[uint]struct{}{}
		for _, m := range memberships {
			if m.ProjectID == 0 || m.ProjectID == projectID {
				set[m.GroupID] = struct{}{}
			}
		}
		return set
	}

	type candidate struct {
		secret *models.SecretNode
		grant  shareGrant
	}
	var granted []candidate
	var projects []uint
	for _, s := range pending {
		shares := bySecret[s.ID]
		grant := c.directShareGrant(shares, userID, need)
		if grant.Level == PermissionNone && slices.ContainsFunc(shares, func(sh *models.ShareRecord) bool { return sh.IsGroup }) {
			level, shareID := c.highestGroupShare(shares, groupsAt(s.ProjectID))
			grant = c.groupShareGrant(level, shareID, need)
		}
		if grant.Level == PermissionNone {
			verdict[s.ID] = batchDeny
			continue
		}
		granted = append(granted, candidate{secret: s, grant: grant})
		projects = append(projects, s.ProjectID)
	}
	if err := members.ensure(ctx, c, userID, projects); err != nil {
		return err
	}
	// The elevations are recorded last and in page order, as the per-row decisions did.
	for _, g := range granted {
		if !members.known[g.secret.ProjectID] {
			verdict[g.secret.ID] = batchDeny
			continue
		}
		if c.noteShareElevation(ctx, userID, g.secret, perm, "", g.grant) {
			verdict[g.secret.ID] = batchAllow
		} else {
			verdict[g.secret.ID] = batchDeny
		}
	}
	return nil
}
