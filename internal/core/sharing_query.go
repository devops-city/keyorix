// sharing_query.go — ListSharedSecrets, ListSecretShares, ListSharesByUser, CheckSharePermission.
//
// Read-only query operations over share records.
// For share create/update/revoke see sharing.go.
package core

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSharedSecrets lists all secrets shared with a user.
func (c *KeyorixCore) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	secrets, err := c.storage.ListSharedSecrets(ctx, userID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// PAT-GUARD-1: both callers (HTTP GET /shared-secrets, gRPC ListSharedSecrets)
	// gate on GLOBAL secrets.read, which a scope-confined PAT already fails, so this
	// is a no-op for them. It keeps the function itself from returning a secret
	// outside a PAT restriction if a future caller gates it more weakly.
	visible := make([]*models.SecretNode, 0, len(secrets))
	for _, s := range secrets {
		if patAllowsSecretRead(ctx, s) {
			visible = append(visible, s)
		}
	}
	return visible, nil
}

// ListSharedSecretsForUser lists the secrets shared with targetUserID, on
// behalf of actorID. A self-view (actorID == targetUserID) needs nothing
// beyond the route's own secrets.read gate, matching ListSharedSecrets.
//
// A cross-user (admin) view requires TWO independent things, both checked
// here (not just at the router), because neither alone is sufficient:
//
//  1. roles.read, globally. secrets.read (the route's own permission gate)
//     is routinely bundled with users.read into ordinary, non-admin roles
//     (project_viewer, project_developer, project_auditor all hold both —
//     see auth_bootstrap.go's defaultRoles) — a router-level gate on either
//     or both is not an admin check, just the baseline every project member
//     already clears. roles.read is the existing permission this codebase
//     already uses to distinguish "can view another user's account" from
//     "can view another user's SENSITIVE, admin-tier data" — GetUserRolesForUser
//     (server/http/router.go) gates the identical class of problem
//     (enumerating another user's attack surface) on roles.read instead of
//     the blanket users.read for exactly this reason. Matched here rather
//     than inventing a new permission.
//  2. The S1 admin-rank ceiling (requireAdminRankCeilingForTarget, CLI-split
//     inventory #2012/#2017): actorID must hold, at every scope, every
//     permission targetUserID already holds. roles.read alone is not
//     sufficient either — it only proves the actor is SOME kind of admin,
//     not that they outrank THIS target specifically.
//
// A target that does not exist, and an actor lacking roles.read, both
// resolve through the IDENTICAL refusal path as a genuine ceiling refusal —
// same wrapped error, same audit event, same (generic, clientSafe-collapsed)
// HTTP response. Without this, a caller could distinguish "this numeric ID
// belongs to no one" / "I'm not admin enough to even try" from "this ID
// belongs to someone I'm not allowed to see" — an existence oracle for admin
// accounts, exactly what ADR-096's 403-for-both convention exists to close
// for scoped resources. This extends the same discipline to a USER target.
func (c *KeyorixCore) ListSharedSecretsForUser(ctx context.Context, actorID, targetUserID uint) ([]*models.SecretNode, error) {
	if targetUserID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if actorID != targetUserID {
		if allowed, aerr := c.Authorize(ctx, actorID, permRolesRead, Scope{}); aerr != nil || !allowed {
			aid := actorID
			c.writeAuditEventFailed(ctx, EventAdminRankCeilingRefused, &aid, nil, "",
				fmt.Sprintf("actor %d refused: lacks %s required to view another user's shared secrets (target %d)", actorID, permRolesRead, targetUserID))
			return nil, fmt.Errorf("%w: missing admin permission to view another user's shared secrets", ErrInsufficientAdminAuthority)
		}
		if _, err := c.storage.GetUser(ctx, targetUserID); err != nil {
			aid := actorID
			c.writeAuditEventFailed(ctx, EventAdminRankCeilingRefused, &aid, nil, "",
				fmt.Sprintf("actor %d refused: target user %d does not exist", actorID, targetUserID))
			return nil, fmt.Errorf("%w: target user not found", ErrInsufficientAdminAuthority)
		}
		if err := c.requireAdminRankCeilingForTarget(ctx, actorID, targetUserID, "view shared secrets for"); err != nil {
			return nil, err
		}
	}
	secrets, err := c.storage.ListSharedSecrets(ctx, targetUserID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}
	if actorID != targetUserID {
		aid := actorID
		c.writeAuditEvent(ctx, string(ShareAuditEventSharedSecretsAdminViewed), &aid, nil,
			fmt.Sprintf("admin viewed shared secrets for user %d (%d result(s))", targetUserID, len(secrets)))
	}
	return secrets, nil
}

// ListSecretShares lists all shares for a specific secret.
func (c *KeyorixCore) ListSecretShares(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if _, err := c.GetSecret(ctx, secretID); err != nil {
		return nil, err
	}
	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Drop expired time-bound shares so the list matches what actually authorizes
	// (every enforcement path filters via activeShares); they're swept separately.
	return activeShares(shares, c.shareEffectiveNow()), nil
}

// ListSecretSharesWithPermissionCheck lists a secret's shares, but only for its
// owner — the share list (recipients, permission levels) is owner-only, matching
// UpdateSharePermission/RevokeShare. Without this, any caller with secrets.read
// could enumerate who has access to any secret. Authenticated request surfaces
// (HTTP/gRPC) use this; the local CLI uses ListSecretShares directly.
//
// Owner authority is gated on live project membership (requireLiveOwnerAuthority),
// matching the sharing.go/group_sharing.go mutation paths (RBAC-001): a user removed
// from the secret's project keeps their OwnerID tag until ClearProjectSecretOwnership
// runs, so a bare ownership check alone would let a departed owner keep reading the
// secret's recipient list forever.
func (c *KeyorixCore) ListSecretSharesWithPermissionCheck(ctx context.Context, secretID, userID uint) ([]*models.ShareRecord, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret, err := c.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if isLiveOwner, err := c.requireLiveOwnerAuthority(ctx, secret, userID); err != nil {
		return nil, err
	} else if !isLiveOwner {
		return nil, fmt.Errorf("not authorized to view shares for this secret")
	}
	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Drop expired time-bound shares — see ListSecretShares.
	return activeShares(shares, c.shareEffectiveNow()), nil
}

// ListSharesByUser lists shares involving the user (received as recipient + outgoing as owner).
func (c *KeyorixCore) ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error) {
	received, owned, err := c.sharesReceivedAndOwned(ctx, userID)
	if err != nil {
		return nil, err
	}
	return mergeSharesByID(received, owned), nil
}

// sharesReceivedAndOwned fetches the two storage lists ListSharesByUser merges.
func (c *KeyorixCore) sharesReceivedAndOwned(ctx context.Context, userID uint) (received, owned []*models.ShareRecord, err error) {
	if userID == 0 {
		return nil, nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	received, err = c.storage.ListSharesByUser(ctx, userID, c.shareEffectiveNow())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	owned, err = c.storage.ListSharesByOwner(ctx, userID, c.shareEffectiveNow())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return received, owned, nil
}

// mergeSharesByID unions the lists by share id, ordered by id.
func mergeSharesByID(received, owned []*models.ShareRecord) []*models.ShareRecord {
	byID := make(map[uint]*models.ShareRecord)
	for _, s := range received {
		if s != nil {
			byID[s.ID] = s
		}
	}
	for _, s := range owned {
		if s != nil {
			byID[s.ID] = s
		}
	}
	out := make([]*models.ShareRecord, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ShareView is an enriched, transport-ready share record: recipient and creator are
// resolved to display names and the JSON is camelCase to match the web client (which
// consumes the /shares list verbatim, without field mapping).
type ShareView struct {
	ID            uint       `json:"id"`
	SecretID      uint       `json:"secretId"`
	RecipientType string     `json:"recipientType"` // "user" | "group"
	RecipientID   uint       `json:"recipientId"`
	RecipientName string     `json:"recipientName"`
	Permission    string     `json:"permission"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"` // nil = permanent (time-bound shares)
	CreatedAt     time.Time  `json:"createdAt"`
	CreatedBy     string     `json:"createdBy"` // username of the share's owner
	// SecretName, ProjectID and ProjectName are set only when the caller may read the
	// secret (annotateShareViewSecrets, #3153); otherwise they are omitted.
	SecretName  string `json:"secretName,omitempty"`
	ProjectID   uint   `json:"projectId,omitempty"`
	ProjectName string `json:"projectName,omitempty"`
}

// ListUserShareViews returns the user's shares (received + owned) as enriched views
// with recipient/creator names resolved, ready to serialise for the web sharing UI.
func (c *KeyorixCore) ListUserShareViews(ctx context.Context, userID uint) ([]ShareView, error) {
	received, owned, err := c.sharesReceivedAndOwned(ctx, userID)
	if err != nil {
		return nil, err
	}
	if shareFetchMayBeTruncated(received) || shareFetchMayBeTruncated(owned) {
		return nil, ErrShareListOverCap
	}
	views, err := c.shareViews(ctx, mergeSharesByID(received, owned))
	if err != nil {
		return nil, err
	}
	c.annotateShareViewSecrets(ctx, userID, views)
	return views, nil
}

// shareFetchMayBeTruncated: storage list queries without pagination return at most
// maxUnboundedListRows (10000, internal/storage/store) rows and cut the rest off
// silently, so a result of that size cannot be told from a truncated one. The cap in
// shareViews alone would never fire on a single such list; refuse, never show a list
// that may be missing shares (the page that revokes them).
func shareFetchMayBeTruncated(shares []*models.ShareRecord) bool {
	return len(shares) >= maxShareViewBatchSize
}

// maxShareViewBatchSize bounds how many share rows one list call enriches. The rows
// come from storage (never a request payload), but enrichment does a user/group
// lookup per distinct recipient and creator, and the CLI's embedded mode calls core
// directly, so a very large share table would turn one list call into an unbounded
// run of round trips (CWE-400). Same pattern as maxBulkAccessRequestBatchSize. The
// list is refused (ErrShareListOverCap, a 422 on HTTP), never truncated: a silently
// shortened list would hide shares from the page that revokes them. Real pagination
// in core is a parked follow-up.
const maxShareViewBatchSize = 10000

// ErrShareListOverCap: the share list exceeds maxShareViewBatchSize. Transports map it
// to a typed 4xx, not a 500.
var ErrShareListOverCap = fmt.Errorf("share list is over the cap of %d shares per request", maxShareViewBatchSize)

// shareViews enriches share records with recipient/creator display names, resolving
// each user and group once.
func (c *KeyorixCore) shareViews(ctx context.Context, shares []*models.ShareRecord) ([]ShareView, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	if len(shares) > maxShareViewBatchSize {
		return nil, ErrShareListOverCap
	}
	userNames := map[uint]string{}
	resolveUser := func(id uint) string {
		if id == 0 {
			return ""
		}
		if n, ok := userNames[id]; ok {
			return n
		}
		name := fmt.Sprintf("User %d", id)
		if u, err := c.storage.GetUser(ctx, id); err == nil && u != nil && u.Username != "" {
			name = u.Username
		}
		userNames[id] = name
		return name
	}
	groupNames := map[uint]string{}
	resolveGroup := func(id uint) string {
		if n, ok := groupNames[id]; ok {
			return n
		}
		name := fmt.Sprintf("Group %d", id)
		if g, err := c.storage.GetGroup(ctx, id); err == nil && g != nil && g.Name != "" {
			name = g.Name
		}
		groupNames[id] = name
		return name
	}

	views := make([]ShareView, 0, len(shares))
	for _, s := range shares {
		v := ShareView{
			ID:          s.ID,
			SecretID:    s.SecretID,
			RecipientID: s.RecipientID,
			Permission:  s.Permission,
			ExpiresAt:   s.ExpiresAt,
			CreatedAt:   s.CreatedAt,
			CreatedBy:   resolveUser(s.OwnerID),
		}
		if s.IsGroup {
			v.RecipientType = "group"
			v.RecipientName = resolveGroup(s.RecipientID)
		} else {
			v.RecipientType = "user"
			v.RecipientName = resolveUser(s.RecipientID)
		}
		views = append(views, v)
	}
	return views, nil
}

// CheckSharePermission checks if a user has permission to access a secret.
func (c *KeyorixCore) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	if secretID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.CheckSharePermission(ctx, secretID, userID, c.shareEffectiveNow())
}
