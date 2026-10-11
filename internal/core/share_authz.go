// share_authz.go — the share term of every per-secret authorization decision (#2941).
//
// Decision (Andrei, 2026-10-10, #2941): a share MAY elevate a project member's access
// on that one secret. A member's effective permission on a secret is
//
//	max(role permission, active share permission)
//
// where "active share permission" is the highest level any direct share to the user,
// or group share to a group the user belongs to (scoped to the secret's project),
// grants — with four limits, each enforced here and nowhere else:
//
//  1. Shares never apply to a non-member. The recipient must be a live member of the
//     secret's project (IsProjectMember) at ACCESS time, not only when the share was
//     created: RemoveProjectMember deletes role grants and ACLs but not share rows, so
//     without this a removed member's leftover share would become their only grant.
//  2. Expired shares grant nothing (shareActive), even before the sweeper reclaims the
//     row. A revoked share is a deleted row, so it grants nothing by construction.
//  3. A share grants only what its level says: read → secrets.read, write →
//     secrets.read + secrets.write FOR THE ALLOWLISTED ACTIONS ONLY (#3001 follow-up,
//     Andrei 2026-10-10 19:33: update the value, update metadata, rotate; see
//     secretActionShareElevates). Never secrets.delete, secrets.manage, owner, the
//     right to share (ShareSecret's owner gate is separate), or any secrets.write action
//     off the allowlist (suspend/resume, move, transfer, rollback, ...). A level outside
//     read|write (a corrupt row) grants nothing.
//  4. Machine identities never take this path: share recipients are user IDs, and a
//     machine principal's ID lives in a different ID space (see
//     AuthorizeSecretPrincipal).
//
// Audit: an elevation is recorded on the request's ShareElevationRecorder when it is
// decided and written as share_access_elevated only when the transport reports the
// action PERFORMED (CommitShareElevations: HTTP 2xx, gRPC nil error). Refused or failed
// requests write nothing, and a decision the role (or an ACL) made writes nothing.
//
// Both decision functions use sharePermissionFor: AuthorizeSecret (the gate every
// per-secret HTTP route, gRPC RPC and core helper consults) and CheckSecretPermission
// (the core *WithPermissionCheck paths). share_authz_guard_test.go fails the build if
// either stops calling it, or if a transport's per-secret gate stops calling
// AuthorizeSecret.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ShareAuditEventAccessElevated records an action a share authorized that the
// actor's role (and any ACL) alone would not have, written when the action was
// performed: the action, the secret, the share id, the actor and the share's level.
const ShareAuditEventAccessElevated ShareAuditEvent = "share_access_elevated"

// SecretAction names one secrets.write operation on one existing secret. Every
// share-aware secrets.write gate names the action it guards (HTTP
// RequireScopedSecretPermission's action argument, gRPC authorizeSecretScoped's), as
// do the core's own write checks (EnforceSecretActionPermission), so the share term
// can decide per action. A gate or check that names no action gets no write-share
// elevation: unnamed means not allowlisted.
type SecretAction string

// The secrets.write actions. Each one MUST have an entry in secretActionShareElevates
// (share_action_allowlist_guard_test.go fails the build otherwise).
const (
	// SecretActionUpdate: PUT /secrets/{id}, gRPC UpdateSecret — a new value and/or
	// type, description, metadata map, tags. Lifecycle fields are a separate action.
	SecretActionUpdate SecretAction = "secret.update"
	// SecretActionUpdateMetadata: description and tags on their own routes.
	SecretActionUpdateMetadata SecretAction = "secret.update_metadata"
	// SecretActionRotate: POST /secrets/{id}/rotate (rotation = a new value).
	SecretActionRotate SecretAction = "secret.rotate"

	// SecretActionUpdateLifecycle: an update that changes the expiry or the read
	// limit. Either can take the secret away from everyone else (the same denial of
	// service as suspend), so it is not "metadata".
	SecretActionUpdateLifecycle SecretAction = "secret.update_lifecycle"
	SecretActionClassify        SecretAction = "secret.classify"
	SecretActionSetAutoRotate   SecretAction = "secret.set_auto_rotate"
	SecretActionRollback        SecretAction = "secret.rollback"
	SecretActionCommentVersion  SecretAction = "secret.comment_version"
	SecretActionAddDependency   SecretAction = "secret.add_dependency" // #nosec G101 -- authorization action name, not a credential
	SecretActionRemoveDep       SecretAction = "secret.remove_dependency"
	SecretActionMove            SecretAction = "secret.move"
	SecretActionTransferOwner   SecretAction = "secret.transfer_ownership"
	SecretActionSuspend         SecretAction = "secret.suspend"
	SecretActionResume          SecretAction = "secret.resume"
	SecretActionShare           SecretAction = "secret.share"
)

// secretActionShareElevates is THE write-share allowlist (#3001 follow-up, Andrei
// 2026-10-10 19:33), and the only place it is written down: true means an active
// write share to a project member authorizes the action on that one secret even
// though the member's role does not grant secrets.write. Every SecretAction has an
// explicit entry; an action missing here (or the empty action) is not elevated.
//
// Not elevated, and why: suspend/resume (an incident freeze a recipient could undo,
// or a denial of service), lifecycle (same), move/transfer (changes who governs the
// secret), share (widens access; also owner-only in core), rollback (can reinstate a
// leaked credential), classification (can lift the restricted-tier read approval
// gate), auto-rotate (rotation policy and upstream backend binding), dependencies and
// version comments (not on the list; fail closed until someone decides otherwise).
var secretActionShareElevates = map[SecretAction]bool{
	SecretActionUpdate:          true,
	SecretActionUpdateMetadata:  true,
	SecretActionRotate:          true,
	SecretActionUpdateLifecycle: false,
	SecretActionClassify:        false,
	SecretActionSetAutoRotate:   false,
	SecretActionRollback:        false,
	SecretActionCommentVersion:  false,
	SecretActionAddDependency:   false,
	SecretActionRemoveDep:       false,
	SecretActionMove:            false,
	SecretActionTransferOwner:   false,
	SecretActionSuspend:         false,
	SecretActionResume:          false,
	SecretActionShare:           false,
}

// IsKnownSecretAction reports whether a has an allowlist decision.
func IsKnownSecretAction(a SecretAction) bool {
	_, ok := secretActionShareElevates[a]
	return ok
}

// ShareElevatesAction reports whether a write share may elevate action a.
func ShareElevatesAction(a SecretAction) bool { return secretActionShareElevates[a] }

// ErrShareActionNotElevated: the actor's share covers secrets.write on this secret,
// but the action is not one a share may elevate.
var ErrShareActionNotElevated = errors.New("not authorized: a share does not grant this action")

// ShareActionNotElevatedMessage is the fixed user-facing reason for
// ErrShareActionNotElevated, used by HTTP and gRPC alike.
const ShareActionNotElevatedMessage = "A share on this secret only lets you update its value and metadata or rotate it. " +
	"This action needs a project role that grants secrets.write: ask a project admin."

// Typed refusals for share management (#2976: every one of these used to surface as
// a bare "Not authorized to share this secret"). Each wraps the i18n
// ErrorPermissionDenied text, so every existing "permission denied" → 403 /
// PermissionDenied mapping still applies; ShareRefusalMessage gives transports the
// user-facing reason.
var (
	// ErrShareNotOwner: only the secret's owner may share it or change its shares.
	ErrShareNotOwner = errors.New("not authorized: only the secret's owner can share it")
	// ErrShareOwnerNotMember: the actor owns the secret but is not a live member of
	// its project (RBAC-001). A global role makes nobody a member of any project.
	ErrShareOwnerNotMember = errors.New("not authorized: the owner is not a member of the secret's project")
	// ErrShareRecipientNotMember: shares never apply to non-members.
	ErrShareRecipientNotMember = errors.New("not authorized: the recipient is not a member of the secret's project")
	// ErrShareGroupNotInProject: the recipient group holds no role in the secret's
	// project.
	ErrShareGroupNotInProject = errors.New("not authorized: the recipient group has no role in the secret's project")
)

// shareRefusal wraps a share-management sentinel so it reads as a permission denial
// to every existing string-matching mapper and as the sentinel to errors.Is.
func shareRefusal(sentinel error) error {
	return fmt.Errorf("%s: %w", i18n.T("ErrorPermissionDenied", nil), sentinel)
}

// ShareRefusalMessage returns the fixed, user-facing explanation for a share
// management refusal, and false for any other error. HTTP and gRPC both use it so the
// two transports say the same thing. Never echoes err itself.
func ShareRefusalMessage(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrShareOwnerNotMember):
		return "You own this secret but you are not a member of this secret's project, and only a project member can share it. " +
			"Ask a project admin to give you a role in the project (for example project_admin), then share again.", true
	case errors.Is(err, ErrShareRecipientNotMember):
		return "The recipient is not a member of this secret's project. Shares only apply to project members: " +
			"give them a role in the project first (for example project_viewer), then share again.", true
	case errors.Is(err, ErrShareGroupNotInProject):
		return "The recipient group has no role in this secret's project. Shares only apply to project members: " +
			"give the group a role in the project first, then share again.", true
	case errors.Is(err, ErrShareNotOwner):
		return "Only the secret's owner can share it or change its shares.", true
	case errors.Is(err, ErrShareRecipientSearchDenied):
		return ShareRecipientSearchDeniedMessage, true
	case errors.Is(err, ErrShareActionNotElevated):
		return ShareActionNotElevatedMessage, true
	}
	return "", false
}

// requireShareAuthority is the owner gate of every share mutation (ShareSecret,
// ShareSecretWithGroup, UpdateSharePermission, RevokeShare): actorID must own the
// secret AND be a live member of its project (requireLiveOwnerAuthority, RBAC-001).
// Returns a typed refusal saying which half failed.
func (c *KeyorixCore) requireShareAuthority(ctx context.Context, secret *models.SecretNode, actorID uint) error {
	if !secretOwnedBy(secret.OwnerID, actorID) {
		return shareRefusal(ErrShareNotOwner)
	}
	isLiveOwner, err := c.requireLiveOwnerAuthority(ctx, secret, actorID)
	if err != nil {
		return err
	}
	if !isLiveOwner {
		return shareRefusal(ErrShareOwnerNotMember)
	}
	return nil
}

// shareGrant is the outcome of sharePermissionFor.
type shareGrant struct {
	Level   PermissionLevel // PermissionNone, PermissionRead or PermissionWrite
	ShareID *uint
	Source  string // "direct_share" or "group_share"
}

// shareLevel maps a stored share permission to the level it grants. Only read and
// write exist (ShareSecretRequest validates oneof=read write); anything else grants
// nothing, so a corrupt row can never read as owner (hasRequiredPermission would
// otherwise rank a literal "owner" above write).
func shareLevel(stored string) PermissionLevel {
	switch PermissionLevel(stored) {
	case PermissionRead:
		return PermissionRead
	case PermissionWrite:
		return PermissionWrite
	}
	return PermissionNone
}

// sharePermissionFor is the share term: the active share that grants userID at least
// need on secret secretID (in project projectID) for action, or a PermissionNone grant.
// A write need is satisfied only for an allowlisted action (secretActionShareElevates)
// — this check is the allowlist's single enforcement point, and both decision
// functions (AuthorizeSecret, CheckSecretPermission) reach shares only through here.
func (c *KeyorixCore) sharePermissionFor(ctx context.Context, userID, secretID, projectID uint, need PermissionLevel, action SecretAction) (shareGrant, error) {
	if need == PermissionWrite && !secretActionShareElevates[action] {
		return shareGrant{Level: PermissionNone}, nil
	}
	return c.activeShareGrant(ctx, userID, secretID, projectID, need)
}

// shareCoversButNotElevated reports whether userID holds an active share covering
// need on the secret even though action is not allowlisted — only so a refusal can
// say why. It never grants anything. Lookup errors read as false (the caller is
// already refusing).
func (c *KeyorixCore) shareCoversButNotElevated(ctx context.Context, userID, secretID, projectID uint, need PermissionLevel, action SecretAction) bool {
	if need != PermissionWrite || secretActionShareElevates[action] {
		return false
	}
	grant, err := c.activeShareGrant(ctx, userID, secretID, projectID, need)
	return err == nil && grant.Level != PermissionNone
}

// activeShareGrant returns the active share that grants userID at least need on
// secret secretID (which lives in project projectID), or a PermissionNone grant when
// none does (see the file header for the limits), WITHOUT the action allowlist: only
// sharePermissionFor and shareCoversButNotElevated may call it. Direct shares are consulted first,
// then group shares (CheckGroupPermissions); a group-membership lookup failure counts
// as "no group grant" — the share term can only ever ADD access, so failing to
// evaluate it denies the elevation and leaves the caller's role/ACL decision as it
// was. Any other storage error fails closed with (none, err).
func (c *KeyorixCore) activeShareGrant(ctx context.Context, userID, secretID, projectID uint, need PermissionLevel) (shareGrant, error) {
	none := shareGrant{Level: PermissionNone}
	if userID == 0 {
		return none, nil
	}
	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return none, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Drop expired (time-bound) shares before any authorization: an expired share
	// must never grant access, even though the sweep that reclaims its row runs later.
	shares = activeShares(shares, c.shareEffectiveNow())

	grant := none
	for _, share := range shares {
		if share.IsGroup || share.RecipientID != userID {
			continue
		}
		if lvl := shareLevel(share.Permission); c.hasRequiredPermission(lvl, need) {
			id := share.ID
			grant = shareGrant{Level: lvl, ShareID: &id, Source: "direct_share"}
			break
		}
	}
	if grant.Level == PermissionNone {
		groupLevel, groupShareID, gerr := c.CheckGroupPermissions(ctx, secretID, userID, shares, projectID)
		if gerr != nil {
			log.Printf("share authorization: group-share lookup failed (user_id=%d secret_id=%d); no group share applies: %v", userID, secretID, gerr)
		} else if lvl := shareLevel(string(groupLevel)); c.hasRequiredPermission(lvl, need) {
			grant = shareGrant{Level: lvl, ShareID: groupShareID, Source: "group_share"}
		}
	}
	if grant.Level == PermissionNone {
		return none, nil
	}

	// Shares never apply to a non-member — checked last so a caller with no
	// covering share pays no membership lookup.
	member, err := c.IsProjectMember(ctx, userID, projectID)
	if err != nil {
		return none, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if !member {
		return none, nil
	}
	return grant, nil
}

// shareNeedFor maps an RBAC permission to the share level that would satisfy it.
// Only secrets.read and secrets.write can ever be satisfied by a share; every other
// permission (secrets.delete, secrets.manage, roles.assign, ...) maps to
// PermissionNone, which sharePermissionFor never grants.
func shareNeedFor(perm string) PermissionLevel {
	switch perm {
	case permSecretsRead:
		return PermissionRead
	case permSecretsWrite:
		return PermissionWrite
	}
	return PermissionNone
}

// shareElevationDetail is the structured payload of a share_access_elevated event.
type shareElevationDetail struct {
	Action          string `json:"action"`
	ShareID         uint   `json:"share_id"`
	Permission      string `json:"permission"`
	SharePermission string `json:"share_permission"`
	Source          string `json:"source"`
}

// shareElevation is one decision a share made, waiting for the action to be performed.
type shareElevation struct {
	userID    uint
	secretID  uint
	projectID uint
	perm      string
	action    string
	grant     shareGrant
}

// ShareElevationRecorder collects the share elevations decided while serving one
// request, so they are audited when the request's action is performed rather than
// when it is authorized. Transports create one per request
// (WithShareElevationRecorder) and call CommitShareElevations once the action
// succeeded; a request that fails or is refused is simply never committed.
type ShareElevationRecorder struct {
	mu      sync.Mutex
	pending []shareElevation
}

type shareElevationRecorderKey struct{}

// WithShareElevationRecorder returns ctx carrying a fresh recorder.
func WithShareElevationRecorder(ctx context.Context) (context.Context, *ShareElevationRecorder) {
	rec := &ShareElevationRecorder{}
	return context.WithValue(ctx, shareElevationRecorderKey{}, rec), rec
}

func shareElevationRecorderFrom(ctx context.Context) *ShareElevationRecorder {
	rec, _ := ctx.Value(shareElevationRecorderKey{}).(*ShareElevationRecorder)
	return rec
}

func (r *ShareElevationRecorder) add(e shareElevation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.pending {
		if p.userID == e.userID && p.secretID == e.secretID && p.action == e.action &&
			p.grant.ShareID != nil && e.grant.ShareID != nil && *p.grant.ShareID == *e.grant.ShareID {
			return // the gate and the handler deciding the same thing is one elevation
		}
	}
	r.pending = append(r.pending, e)
}

func (r *ShareElevationRecorder) drain() []shareElevation {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.pending
	r.pending = nil
	return out
}

// CommitShareElevations writes one share_access_elevated row per elevation recorded
// on rec, and clears it. Call it only after the action succeeded. Best-effort like
// every other audit write: the action has already happened.
func (c *KeyorixCore) CommitShareElevations(ctx context.Context, rec *ShareElevationRecorder) {
	if rec == nil {
		return
	}
	for _, e := range rec.drain() {
		c.writeShareElevation(ctx, e)
	}
}

// noteShareElevation handles a grant the share term made. With a recorder on ctx the
// elevation waits there for CommitShareElevations. Without one, nobody can tell us
// the action was performed: a write elevation is then refused (fail closed — an
// elevated write is either audited when performed or not performed at all), and a
// read elevation is audited now, as before #3001's follow-up (the read is what the
// caller does next; this is the core-internal read path with no transport around it).
// Returns whether the grant stands.
func (c *KeyorixCore) noteShareElevation(ctx context.Context, userID uint, secret *models.SecretNode, perm string, action SecretAction, grant shareGrant) bool {
	if grant.ShareID == nil {
		return false
	}
	name := string(action)
	if name == "" {
		name = perm
	}
	e := shareElevation{userID: userID, secretID: secret.ID, projectID: secret.ProjectID, perm: perm, action: name, grant: grant}
	if rec := shareElevationRecorderFrom(ctx); rec != nil {
		rec.add(e)
		return true
	}
	if perm != permSecretsRead {
		log.Printf("share authorization: %s on secret %d not elevated: no request recorder to audit it when performed", name, secret.ID)
		return false
	}
	c.writeShareElevation(ctx, e)
	return true
}

func (c *KeyorixCore) writeShareElevation(ctx context.Context, e shareElevation) {
	detail, _ := json.Marshal(shareElevationDetail{
		Action: e.action, ShareID: *e.grant.ShareID, Permission: e.perm,
		SharePermission: string(e.grant.Level), Source: e.grant.Source,
	})
	uid, sid, pid := e.userID, e.secretID, e.projectID
	desc := fmt.Sprintf("%s on secret %d performed under share %d (%s, %s); the actor's role alone does not grant %s",
		e.action, e.secretID, *e.grant.ShareID, e.grant.Source, e.grant.Level, e.perm)
	c.writeAuditEventDiff(ctx, string(ShareAuditEventAccessElevated), &uid, &sid, &pid, "", desc, string(detail))
}
