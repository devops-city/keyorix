// pat_restriction_listing.go — applying a PAT restriction (ADR-042) to reads whose
// visibility is decided OUTSIDE Authorize/AuthorizeSecret.
//
// The restriction is enforced at the authorization chokepoint, so a read gated by
// Authorize at a scope that covers every row it returns honours it for free. A read
// that decides visibility itself — "what this user personally owns, was shared or
// was granted", "this user's notifications" — never reaches that chokepoint for the
// rows it returns, and so ignored the restriction entirely: an environment-confined
// or users.read-only token listed the owner's secrets in every project, and every
// restricted token read notifications naming secrets in other projects (PAT-GUARD-1;
// the same class as #3018's GET /shares/owned).
//
// Each filter here keeps a row only if the restriction would let the token read it
// at the row's OWN scope — the exact check AuthorizeSecret makes before it honours
// an ACL grant (PAT-SCOPE-002). A nil restriction (session, machine, unrestricted
// PAT) keeps everything, so these are no-ops for every caller but a restricted PAT.
//
// The family-wide guard is server/http/pat_restriction_read_family_test.go's
// TestEveryGETRouteHonoursPATRestriction (and its gRPC twin): it calls every GET
// route with restricted tokens against a canary project and fails on any response
// that discloses it.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrRestrictedPATCannotMintPAT refuses a PAT-creation request authenticated by a
// restricted PAT. A child token is created unrestricted unless the request asks
// otherwise, so allowing it would let a leaked confined token mint the owner's full
// authority — the one outcome ADR-042's restriction exists to prevent.
var ErrRestrictedPATCannotMintPAT = errors.New("a restricted personal access token cannot create personal access tokens")

// ErrRestrictedPATCannotBreakGlass refuses a break-glass activation authenticated
// by a restricted PAT (PAT-GUARD-2, Andrei's decision of 2026-10-11). Activation is
// deliberately not RBAC-gated, so Authorize never sees it, and it grants the owner
// an emergency role at a project: a privilege-escalation path a token confined
// below its owner must not reach. Revoking the owner's own tokens and sessions stays
// allowed for a restricted PAT, since it only ever reduces access.
var ErrRestrictedPATCannotBreakGlass = errors.New("a restricted personal access token cannot activate break-glass access")

// patAllowsSecretRead reports whether the request's PAT restriction permits
// secrets.read on secret at the secret's own project/environment.
func patAllowsSecretRead(ctx context.Context, secret *models.SecretNode) bool {
	r := patRestrictionFromContext(ctx)
	if r == nil {
		return true
	}
	if secret == nil {
		return false
	}
	return r.Allows(permSecretsRead, Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID})
}

// filterSecretsByPATRestriction drops every secret the request's PAT restriction
// does not let it read. It returns in unchanged when there is no restriction.
func filterSecretsByPATRestriction(ctx context.Context, in []*models.SecretWithSharingInfo) []*models.SecretWithSharingInfo {
	if patRestrictionFromContext(ctx) == nil {
		return in
	}
	out := make([]*models.SecretWithSharingInfo, 0, len(in))
	for _, s := range in {
		if s != nil && patAllowsSecretRead(ctx, s.SecretNode) {
			out = append(out, s)
		}
	}
	return out
}

// patAllowsNotification reports whether the request's PAT restriction lets it see
// n. A notification names the resource it is about (a secret, an access request, a
// break-glass activation), so it is treated as a read of its project's secrets:
// secrets.read at the notification's project scope.
//
// A notification with no project is refused to every restricted token. Several of
// them still name project resources (read-quota alerts name the secret), and
// nothing on the row says which project, so there is no scope to check them
// against. Fail closed: the restricted token sees fewer notifications, never ones
// from outside its restriction.
func patAllowsNotification(ctx context.Context, n *models.Notification) bool {
	r := patRestrictionFromContext(ctx)
	if r == nil {
		return true
	}
	if n == nil || n.ProjectID == nil {
		return false
	}
	return r.Allows(permSecretsRead, Scope{ProjectID: *n.ProjectID})
}

// patNotificationScope turns the request's PAT restriction into the storage scope
// of the notifications it may see, so the narrowing happens in the query and a
// limit or count applies to visible rows only. ok is false when it may see none.
//
// Exact, not approximate: patAllowsNotification checks secrets.read at
// Scope{ProjectID: n.ProjectID} for a row with a project and refuses a row without
// one, and PATRestriction.Allows looks at that scope only through ProjectID, and
// only for a project-confined token. So a confined token sees exactly its
// project's rows or none, and an unconfined one every row with a project or none;
// the probe below asks which. TestPATNotificationScope_MatchesPerRowCheck compares
// the two over every restriction shape.
func patNotificationScope(ctx context.Context) (storage.NotificationScope, bool) {
	r := patRestrictionFromContext(ctx)
	probe := r.ProjectID
	if probe == 0 {
		probe = ^uint(0) // any project: an unconfined token does not look at which
	}
	if !r.Allows(permSecretsRead, Scope{ProjectID: probe}) {
		return storage.NotificationScope{}, false
	}
	return storage.NotificationScope{ProjectID: r.ProjectID}, true
}

// requireAccessRequestAuthorityAt is requireAdminAuthorityAt for the secret
// access-request family (list pending, get, approve, reject). Those routes carry no
// permission gate — the admin-authority check IS their authorization — and
// requireAdminAuthorityAt resolves roles directly, never through Authorize, so a
// project-confined admin token could see and resolve requests in every project.
// The restriction is checked as roles.assign at the request's project: approving a
// secret access request is the same decision as resolving a project access request,
// which the router gates on roles.assign.
func (c *KeyorixCore) requireAccessRequestAuthorityAt(ctx context.Context, actorID, projectID uint) error {
	if !patRestrictionFromContext(ctx).Allows(permRolesAssign, Scope{ProjectID: projectID}) {
		return fmt.Errorf("admin authority is required")
	}
	return c.requireAdminAuthorityAt(ctx, actorID, projectID)
}

// patAllowsOwnAccessRequest reports whether a restricted PAT may see one of its
// owner's own secret access requests: secrets.read at the request's project, since
// the request is about reading a secret there.
func patAllowsOwnAccessRequest(ctx context.Context, req *models.AccessRequest) bool {
	return patRestrictionFromContext(ctx).Allows(permSecretsRead, Scope{ProjectID: req.ProjectID})
}

// secretScopesByID batch-loads the secrets behind ids. A secret that is gone has
// no entry, so a caller checking a row against it fails closed.
func (c *KeyorixCore) secretScopesByID(ctx context.Context, ids []uint) (map[uint]*models.SecretNode, error) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- ids come from one bounded storage page (a user's shares, one audit page), never from a client; one batched GetSecretsByIDs call
	out := map[uint]*models.SecretNode{}
	if len(ids) == 0 {
		return out, nil
	}
	secrets, err := c.storage.GetSecretsByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, s := range secrets {
		out[s.ID] = s
	}
	return out, nil
}

// countSharesVisibleToPAT counts the shares whose secret the request's PAT
// restriction lets it read (GET /dashboard/stats's shared tiles). Without a
// restriction it is len(shares).
func (c *KeyorixCore) countSharesVisibleToPAT(ctx context.Context, shares []*models.ShareRecord) (int, error) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- shares is the caller's own share list from storage, not client input; one batched lookup
	if patRestrictionFromContext(ctx) == nil {
		return len(shares), nil
	}
	ids := make([]uint, 0, len(shares))
	for _, sh := range shares {
		ids = append(ids, sh.SecretID)
	}
	secrets, err := c.secretScopesByID(ctx, ids)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sh := range shares {
		if s, ok := secrets[sh.SecretID]; ok && patAllowsSecretRead(ctx, s) {
			n++
		}
	}
	return n, nil
}

// dashboardRecentActivity is how many rows GET /dashboard/stats's recent-activity
// list shows.
const dashboardRecentActivity = 5

// Bounds on the restricted-PAT scan in ownRecentActivity: at most
// dashboardActivityScanPages pages of dashboardActivityScanPageSize events. A user
// whose newest 500 events are all outside the token's restriction gets a shorter
// list, never one from outside it.
const (
	dashboardActivityScanPageSize = 50
	dashboardActivityScanPages    = 10
)

// ownRecentActivity returns the caller's newest dashboardRecentActivity audit
// events (the dashboard's recent activity for a caller without audit.read). Every
// row names what it is about, so for a restricted PAT it keeps only the events
// patAllowsAuditEvent passes, scanning further pages so a filtered-out row does
// not just shorten the list.
func (c *KeyorixCore) ownRecentActivity(ctx context.Context, userID uint) ([]*models.AuditEvent, error) {
	if patRestrictionFromContext(ctx) == nil {
		events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{UserID: &userID, Page: 1, PageSize: dashboardRecentActivity})
		return events, err
	}
	out := make([]*models.AuditEvent, 0, dashboardRecentActivity)
	for page := 1; page <= dashboardActivityScanPages; page++ {
		events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{UserID: &userID, Page: page, PageSize: dashboardActivityScanPageSize})
		if err != nil {
			return out, err
		}
		var ids []uint
		for _, e := range events {
			if e.SecretNodeID != nil {
				ids = append(ids, *e.SecretNodeID)
			}
		}
		secrets, err := c.secretScopesByID(ctx, ids)
		if err != nil {
			return out, err
		}
		for _, e := range events {
			if patAllowsAuditEvent(ctx, e, secrets) {
				out = append(out, e)
				if len(out) == dashboardRecentActivity {
					return out, nil
				}
			}
		}
		if len(events) < dashboardActivityScanPageSize {
			break
		}
	}
	return out, nil
}

// patAllowsAuditEvent reports whether a restricted PAT may see one of its owner's
// own audit events: secrets.read at the event's project, and at its secret's own
// scope when it is about a secret (secrets maps SecretNodeID to that secret). An
// event with neither is refused, as patAllowsNotification refuses a notification
// with no project: descriptions name resources ("... secret <name>") and nothing
// on the row says which project they belong to. Fail closed.
func patAllowsAuditEvent(ctx context.Context, e *models.AuditEvent, secrets map[uint]*models.SecretNode) bool {
	r := patRestrictionFromContext(ctx)
	if r == nil {
		return true
	}
	if e == nil || (e.ProjectID == nil && e.SecretNodeID == nil) {
		return false
	}
	if e.ProjectID != nil && !r.Allows(permSecretsRead, Scope{ProjectID: *e.ProjectID}) {
		return false
	}
	if e.SecretNodeID != nil && !patAllowsSecretRead(ctx, secrets[*e.SecretNodeID]) {
		return false
	}
	return true
}
