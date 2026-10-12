// share_owned_list.go — the owner-scoped share list behind the Sharing Management page
// (SHARE-3).
//
// GET /api/v1/shares is gated on GLOBAL secrets.read, so a project-only owner (a
// project_admin of P and nothing else) could share P's secrets but could not open the
// page that lists and revokes those shares. Decision (Andrei, 2026-10-10): a caller
// without global secrets.read gets an owner-scoped list instead.
//
// The rule, for caller U:
//   - only shares U created (ShareRecord.OwnerID == U; ShareSecret only lets the
//     secret's owner create a share, and stamps it with that owner), and
//   - only on secrets whose project U is a member of NOW, per IsProjectMember (the one
//     definition, project_membership_definition.go). Removing U from P hides U's
//     shares in P at once; re-adding U shows them again. A share on a secret that no
//     longer resolves (deleted) is not listed.
//   - when the request carries a PAT least-privilege restriction (ADR-042), only on
//     secrets that token may read: the same PATRestriction.Allows(secrets.read,
//     secret's project+environment) check AuthorizeSecret makes before any read of
//     the secret itself (PAT-SCOPE-002). The route gate only proves the token may
//     read secrets SOMEWHERE; without this a token confined to project A listed the
//     owner's shares in every project.
//
// Nothing else widens it: holding global secrets.read does not add other users' shares
// here (that is GET /api/v1/shares, unchanged), and received shares are not listed.
// Machine identities are refused: a share is created by a user.
package core

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// OwnedShareListDeniedMessage is the reason every refused owner-scoped share list
// carries, from the route gate (router.go) and from ListOwnedShareViews itself.
const OwnedShareListDeniedMessage = "You can only list the shares you created in projects you are a member of: " +
	"that needs a role in at least one project that lets you read its secrets. " +
	"Ask a project admin to give you a role in the project."

// ErrOwnedShareListDenied: the caller may not use the owner-scoped share list.
var ErrOwnedShareListDenied = errors.New("not authorized: the owner-scoped share list needs a user with a project role")

// ListOwnedShareViews returns the shares actorID created on secrets in projects
// actorID is currently a member of, enriched like ListUserShareViews and ordered by
// share id. See the file header for the rule. Fails closed: a storage error during the
// membership checks is an error, never a partial list.
func (c *KeyorixCore) ListOwnedShareViews(ctx context.Context, actorType string, actorID uint) ([]ShareView, error) {
	if actorType != ActorTypeUser || actorID == 0 {
		return nil, shareRefusal(ErrOwnedShareListDenied)
	}
	owned, err := c.storage.ListSharesByOwner(ctx, actorID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("owned share list: %w", err)
	}
	if shareFetchMayBeTruncated(owned) {
		return nil, ErrShareListOverCap
	}
	visible, err := c.sharesInMemberProjects(ctx, actorID, owned)
	if err != nil {
		return nil, err
	}
	sort.Slice(visible, func(i, j int) bool { return visible[i].ID < visible[j].ID })
	return c.shareViews(ctx, visible)
}

// sharesInMemberProjects keeps the shares whose secret resolves, lies in a project
// userID is a member of (IsProjectMember, asked once per project), and lies within
// the request's PAT restriction for secrets.read (no restriction: every scope).
func (c *KeyorixCore) sharesInMemberProjects(ctx context.Context, userID uint, shares []*models.ShareRecord) ([]*models.ShareRecord, error) {
	if len(shares) == 0 {
		return []*models.ShareRecord{}, nil
	}
	secretIDs := make([]uint, 0, len(shares))
	for _, s := range shares {
		if s != nil {
			secretIDs = append(secretIDs, s.SecretID)
		}
	}
	secrets, err := c.storage.GetSecretsByIDs(ctx, dedupeUints(secretIDs))
	if err != nil {
		return nil, fmt.Errorf("owned share list: resolve secrets: %w", err)
	}
	pat := patRestrictionFromContext(ctx)
	projectOf := make(map[uint]uint, len(secrets))
	for _, sec := range secrets {
		if sec == nil {
			continue
		}
		if !pat.Allows(permSecretsRead, Scope{ProjectID: sec.ProjectID, EnvironmentID: sec.EnvironmentID}) {
			continue // outside the token's project, environment or permissions
		}
		projectOf[sec.ID] = sec.ProjectID
	}
	member := map[uint]bool{}
	out := make([]*models.ShareRecord, 0, len(shares))
	for _, s := range shares {
		if s == nil {
			continue
		}
		pid, ok := projectOf[s.SecretID]
		if !ok || pid == 0 {
			continue // the secret is gone, or outside the PAT restriction
		}
		isMember, seen := member[pid]
		if !seen {
			isMember, err = c.IsProjectMember(ctx, userID, pid)
			if err != nil {
				return nil, fmt.Errorf("owned share list: membership: %w", err)
			}
			member[pid] = isMember
		}
		if isMember {
			out = append(out, s)
		}
	}
	return out, nil
}
