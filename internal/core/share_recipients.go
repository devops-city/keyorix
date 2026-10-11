// share_recipients.go — the project-scoped recipient search behind the Share dialog
// (SHARE-2).
//
// Before this, the dialog looked recipients up with GET /api/v1/users, a GLOBAL
// users.read gate, so a project-only admin could share a secret but could not find
// anyone to share it with (E2E-SHARE-1 had to give its owner the global
// system_auditor role to get past it). SearchShareRecipients answers exactly the
// question the dialog asks: "which users could I share a secret in project P with?"
//
// Who may ask, for project P:
//   - a user who can share secrets in P: secrets.write at P's scope AND a member of P
//     (the same owner-must-be-a-member rule ShareSecret enforces, RBAC-001), or
//   - a holder of global users.read, who can already list every user (GET /users),
//     so the answer tells them nothing new. Global admins keep today's behaviour.
//
// Machine identities are refused: a share recipient is a user and the sharer is a
// user (ShareSecret's SharedBy is a user id).
//
// What comes back: only users who are ACTIVE members of P, per IsProjectMember (the
// one definition of membership, project_membership_definition.go), so the list is
// exactly the set ShareSecret would accept as recipients. A soft-deleted, inactive,
// suspended or deprovisioned account is not listed. Each row carries id, username and
// display name. Email is included, and matched, only when the caller may already
// read emails of P's members (users.read at P's scope, the gate of
// GET /projects/{id}/members): otherwise an email-prefix match would be an oracle for
// an address the caller cannot see.
package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ShareRecipientSearchDeniedMessage is the reason every refused recipient search
// carries, on the HTTP route gate (router.go) and from SearchShareRecipients itself.
// One fixed text for every refusal, so it never tells a caller whether the project
// exists.
const ShareRecipientSearchDeniedMessage = "You can only search for share recipients in a project where you can share secrets: " +
	"that needs a role in this project that allows sharing (for example project_admin). " +
	"Ask a project admin to give you a role in the project."

// ErrShareRecipientSearchDenied: the caller may not search recipients in this project.
var ErrShareRecipientSearchDenied = errors.New("not authorized: share recipient search needs a role in the project that allows sharing")

const (
	shareRecipientDefaultPageSize = 20
	shareRecipientMaxPageSize     = 100
	shareRecipientMaxPage         = 10000
)

// ShareRecipient is one search result: the minimum the dialog needs to pick a user.
type ShareRecipient struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	// Email is set only when the caller may read the emails of the project's members.
	Email string `json:"email,omitempty"`
}

// ShareRecipientSearchRequest is the input to SearchShareRecipients.
type ShareRecipientSearchRequest struct {
	ActorType string // ActorTypeUser or ActorTypeMachine
	ActorID   uint
	ProjectID uint
	// Query is a case-insensitive prefix of the username, of the display name (or of
	// any word in it) or, when the caller may see emails, of the email. Empty lists
	// every recipient.
	Query    string
	Page     int
	PageSize int
}

// ShareRecipientPage is one page of results, ordered by username.
type ShareRecipientPage struct {
	Recipients []ShareRecipient `json:"recipients"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
}

// SearchShareRecipients lists the active members of req.ProjectID the caller could
// share a secret with. See the file header for who may ask and what is returned.
// Fails closed: any storage error during the authorization checks is an error, never
// a partial answer.
func (c *KeyorixCore) SearchShareRecipients(ctx context.Context, req ShareRecipientSearchRequest) (*ShareRecipientPage, error) {
	if req.ActorType != ActorTypeUser || req.ActorID == 0 || req.ProjectID == 0 {
		return nil, shareRefusal(ErrShareRecipientSearchDenied)
	}
	if err := c.requireShareRecipientSearch(ctx, req.ActorID, req.ProjectID); err != nil {
		return nil, err
	}
	showEmail, err := c.Authorize(ctx, req.ActorID, "users.read", Scope{ProjectID: req.ProjectID})
	if err != nil {
		return nil, fmt.Errorf("share recipient search: email visibility: %w", err)
	}

	candidates, err := c.shareRecipientCandidates(ctx, req.ProjectID)
	if err != nil {
		return nil, err
	}
	query := strings.ToLower(strings.TrimSpace(req.Query))
	matches := make([]ShareRecipient, 0, len(candidates))
	for _, id := range candidates {
		u, err := c.storage.GetUser(ctx, id)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				continue // soft-deleted or gone: not a recipient
			}
			return nil, fmt.Errorf("share recipient search: load user %d: %w", id, err)
		}
		if u == nil {
			continue
		}
		if !shareRecipientActive(u) || !shareRecipientMatches(u, query, showEmail) {
			continue
		}
		// The candidate set comes from the project's grant rows; IsProjectMember is
		// the one definition and has the last word (expiry, deleted groups).
		member, err := c.IsProjectMember(ctx, u.ID, req.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("share recipient search: membership: %w", err)
		}
		if !member {
			continue
		}
		rec := ShareRecipient{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}
		if showEmail {
			rec.Email = u.Email
		}
		matches = append(matches, rec)
	}
	sort.Slice(matches, func(i, j int) bool {
		a, b := strings.ToLower(matches[i].Username), strings.ToLower(matches[j].Username)
		if a != b {
			return a < b
		}
		return matches[i].ID < matches[j].ID
	})

	page, pageSize := clampShareRecipientPage(req.Page, req.PageSize)
	out := &ShareRecipientPage{Recipients: []ShareRecipient{}, Total: len(matches), Page: page, PageSize: pageSize}
	if start := (page - 1) * pageSize; start < len(matches) {
		end := start + pageSize
		if end > len(matches) {
			end = len(matches)
		}
		out.Recipients = matches[start:end]
	}
	return out, nil
}

// requireShareRecipientSearch: secrets.write at the project's scope, and either
// membership of the project or global users.read.
func (c *KeyorixCore) requireShareRecipientSearch(ctx context.Context, actorID, projectID uint) error {
	canShare, err := c.Authorize(ctx, actorID, "secrets.write", Scope{ProjectID: projectID})
	if err != nil {
		return fmt.Errorf("share recipient search: authorize: %w", err)
	}
	if !canShare {
		return shareRefusal(ErrShareRecipientSearchDenied)
	}
	member, err := c.IsProjectMember(ctx, actorID, projectID)
	if err != nil {
		return fmt.Errorf("share recipient search: caller membership: %w", err)
	}
	if member {
		return nil
	}
	globalUsersRead, err := c.Authorize(ctx, actorID, "users.read", Scope{})
	if err != nil {
		return fmt.Errorf("share recipient search: authorize: %w", err)
	}
	if !globalUsersRead {
		return shareRefusal(ErrShareRecipientSearchDenied)
	}
	return nil
}

// shareRecipientCandidates returns the distinct user ids holding a live grant in the
// project, directly or through a group: a superset of the members, which the caller
// narrows with IsProjectMember.
func (c *KeyorixCore) shareRecipientCandidates(ctx context.Context, projectID uint) ([]uint, error) {
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("share recipient search: project grants: %w", err)
	}
	seen := make(map[uint]struct{})
	var ids, groupIDs []uint
	add := func(id uint) {
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	for _, a := range assignments {
		switch a.PrincipalType {
		case "user":
			add(a.PrincipalID)
		case "group":
			groupIDs = append(groupIDs, a.PrincipalID)
		}
	}
	if len(groupIDs) > 0 {
		byGroup, err := c.storage.ListGroupMembersByGroupIDs(ctx, groupIDs)
		if err != nil {
			return nil, fmt.Errorf("share recipient search: group members: %w", err)
		}
		for _, members := range byGroup {
			for _, u := range members {
				add(u.ID)
			}
		}
	}
	return ids, nil
}

// shareRecipientActive: an account that can be used — not deactivated, not
// suspended or deprovisioned.
func shareRecipientActive(u *models.User) bool {
	return u.IsActive && !AccountLoginBlocked(u.ID, NormalizeAccountState(u.AccountState))
}

func shareRecipientMatches(u *models.User, query string, matchEmail bool) bool {
	if query == "" {
		return true
	}
	if strings.HasPrefix(strings.ToLower(u.Username), query) {
		return true
	}
	name := strings.ToLower(u.DisplayName)
	if strings.HasPrefix(name, query) {
		return true
	}
	for _, word := range strings.Fields(name) {
		if strings.HasPrefix(word, query) {
			return true
		}
	}
	return matchEmail && strings.HasPrefix(strings.ToLower(u.Email), query)
}

func clampShareRecipientPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if page > shareRecipientMaxPage {
		page = shareRecipientMaxPage
	}
	if pageSize < 1 {
		pageSize = shareRecipientDefaultPageSize
	}
	if pageSize > shareRecipientMaxPageSize {
		pageSize = shareRecipientMaxPageSize
	}
	return page, pageSize
}
