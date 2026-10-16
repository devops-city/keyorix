package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A session-creating write (CreateSession, RotateSession) that reports an error
// may still have committed: a lost acknowledgement, or a commit that landed
// before the driver error. The caller used to treat every such error as "no
// session" and report the login as failed, so a row that DID land was a live
// session nobody held: it showed in the owner's session list, outlived the
// failure until expiry, and a revocation sweep had to find it (#2844, found by
// the exhaustive login-op fault sweep: CreateSession#1/effect-then-error).
//
// The rule these helpers enforce: a login either delivers the session it wrote
// or leaves no usable session behind.
//
//   - The write reported an error: read the row back by its token. Present
//     means the write committed, and the session is delivered exactly as if the
//     write had succeeded (the credential was already verified; the row is the
//     one this call built). Absent means nothing landed, and the error stands.
//   - The write panicked: the row is deleted if it landed, then the panic
//     continues. A panic is a bug, not an ambiguous acknowledgement, so it is
//     never turned into a success.
//
// The token is the key because it is the one thing the caller holds that names
// exactly this row: the ID is unknown when the insert reported failure, and a
// refresh shares its FamilyID with the rest of the lineage. The token was never
// disclosed, so nothing can have cached it.

// EventUndeliveredSessionRevoked records that a session row was found and
// deleted after the write that created it panicked, so its token was never
// handed to the client.
const EventUndeliveredSessionRevoked = "auth.undelivered_session_revoked" // #nosec G101 -- audit event type, not a credential

// EventUndeliveredSessionUnresolved records that, after a session write failed,
// it could not be established whether the row exists, or a row that exists could
// not be deleted: a live session the user never received may exist. Loud on
// purpose, like EventSessionReuseFamilyRevokeFailed. #nosec G101 -- audit event type, not a credential
const EventUndeliveredSessionUnresolved = "auth.undelivered_session_unresolved"

// sessionWriteLanded reports whether the session whose plaintext token is token
// exists, after the write that created it returned writeErr. It returns the
// stored row when it does. A lookup that itself fails is audited as
// EventUndeliveredSessionUnresolved and reported as not landed, so the caller
// keeps failing closed. Panic-safe.
func (c *KeyorixCore) sessionWriteLanded(ctx context.Context, token string, userID uint, ip, origin string, writeErr error) (row *models.Session) {
	uid := userID
	besteffort.Run(ctx, "core.sessionWriteLanded", func() error {
		got, err := c.storage.GetSession(ctx, token)
		if err == nil {
			log.Printf("%s: the session write for user %d reported %v but the row is present (session %d); it committed and is delivered", origin, userID, writeErr, got.ID)
			row = got
			return nil
		}
		if storage.IsSessionNotFound(err) {
			return nil
		}
		c.writeAuditEventFailed(ctx, EventUndeliveredSessionUnresolved, &uid, nil, ip,
			fmt.Sprintf("%s failed for user %d (%v), and whether its session was written could not be checked: %v; a live session the user never received may exist", origin, userID, writeErr, err))
		return err
	})
	return row
}

// revokeUndeliveredSession deletes the session whose plaintext token is token,
// if it exists. Best-effort and panic-safe: it runs on a path that is already
// failing and must not replace that failure with its own. Not found is silent;
// a deleted row is audited as EventUndeliveredSessionRevoked, a failure as
// EventUndeliveredSessionUnresolved.
func (c *KeyorixCore) revokeUndeliveredSession(ctx context.Context, token string, userID uint, ip, origin string) {
	uid := userID
	besteffort.Run(ctx, "core.revokeUndeliveredSession", func() error {
		row, err := c.storage.GetSession(ctx, token)
		if err != nil {
			if storage.IsSessionNotFound(err) {
				return nil
			}
			c.writeAuditEventFailed(ctx, EventUndeliveredSessionUnresolved, &uid, nil, ip,
				fmt.Sprintf("%s failed for user %d, and the session it may have written could not be looked up: %v; a live session the user never received may exist", origin, userID, err))
			return err
		}
		if err := c.storage.DeleteSession(ctx, row.ID); err != nil {
			c.writeAuditEventFailed(ctx, EventUndeliveredSessionUnresolved, &uid, nil, ip,
				fmt.Sprintf("%s failed for user %d after its session %d was written, and deleting it failed: %v; the session is live and was never delivered", origin, userID, row.ID, err))
			return err
		}
		c.writeAuditEventFull(ctx, EventUndeliveredSessionRevoked, &uid, nil, nil, ip,
			fmt.Sprintf("%s failed for user %d after its session %d was written; the undelivered session was deleted", origin, userID, row.ID))
		return nil
	})
}

// ErrLoginWritePanicked marks a login denied because a storage write after the
// credential matched panicked (#3277): the session insert (mintLoginSession) or
// the TOTP anti-replay mark (markTOTPStepUsedAfterMatch). It always travels
// with that write's ordinary post-verdict error sentinel, so the transport
// answers it like a wrong credential; on its own it only tells
// VerifyMFALoginPending not to give the consumed TOTP step back.
var ErrLoginWritePanicked = errors.New("a post-verdict login write panicked")

// mintLoginSession is mintSessionWith for a login whose credential has already
// matched. A panic in the session write comes back as an error wrapping
// ErrLoginWritePanicked (#3277), so every caller denies it through the same
// post-verdict branch as the write's error: the wrong-credential response, the
// lockout counted, the slot kept, auth.login_error. A panic used to reach the
// Recovery middleware instead: a 500 a wrong credential can never get (it never
// reaches the insert), so the status code answered "was the credential
// correct?", while the lockout went uncounted and nothing was audited.
//
// Commit-aware: by the time the panic gets here createSession has already
// deleted the row if it landed (or audited auth.undelivered_session_unresolved
// if that could not be done), and no token is returned, so the denial leaves no
// usable session. Nothing in mintSessionWith after the insert can panic out
// (EnforceSessionLimit is besteffort.Run), so a recovered panic never follows
// a delivered row. Only login paths use this; setup consume, SSO and
// impersonation keep mintSession's propagation.
func (c *KeyorixCore) mintLoginSession(ctx context.Context, userID uint, userAgent, ip string, setupOnly bool) (session *models.Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: login session write for user %d panicked after the credential matched; "+
				"denying it as a post-verdict fault: %v\n%s", userID, r, debug.Stack())
			session, err = nil, fmt.Errorf("%w: session write for user %d: %v", ErrLoginWritePanicked, userID, r)
		}
	}()
	return c.mintSessionWith(ctx, userID, userAgent, ip, setupOnly)
}

// createSession is CreateSession with the rule above applied: on an error it
// delivers the row if it landed, on a panic it deletes the row if it landed and
// re-raises.
func (c *KeyorixCore) createSession(ctx context.Context, session *models.Session, ip, origin string) (created *models.Session, err error) {
	token, userID := session.SessionToken, session.UserID
	returned := false
	defer func() {
		if returned {
			return
		}
		if p := recover(); p != nil {
			c.revokeUndeliveredSession(ctx, token, userID, ip, origin)
			panic(p)
		}
	}()
	created, err = c.storage.CreateSession(ctx, session)
	returned = true
	if err == nil {
		return created, nil
	}
	if row := c.sessionWriteLanded(ctx, token, userID, ip, origin, err); row != nil {
		session.ID = row.ID
		session.SessionToken = token
		return session, nil
	}
	return nil, err
}
