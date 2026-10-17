package core

// gate_read_decision.go — OPT-READPATH-2.
//
// A human per-secret read is decided twice in one request: by the transport's
// gate (AuthorizeSecretAction: ACL, role, share) and again by the core read check
// (checkSecretPermission: live owner, share, ACL, role). Both read the same live
// rows with no transaction between them, and the gate's grant set is contained in
// the core check's (every term the gate allows on, the core check allows on too),
// so once the gate has allowed the read the second evaluation cannot deny it
// (short of a storage error in the second evaluation, or a grant revoked in the
// milliseconds between the two, which is the same outcome as a revocation that
// lands just after the second); it only repeats about eight statements.
//
// The gate therefore records its allow on a request-scoped memo, and the core
// read check consumes it instead of evaluating the decision again. The memo:
//   - exists only on a context a transport created for ONE request
//     (WithShareElevationRecorder: the HTTP per-secret gates and the gRPC
//     interceptor), so nothing is cached across requests;
//   - holds an allow of secrets.read with no action only (never a write, delete
//     or owner decision, never a refusal);
//   - is taken once: the first read check of the same user on the same secret
//     consumes it, any later check evaluates in full;
//   - is never consulted for a machine actor (machines never reach
//     checkSecretPermission's human branches, and the gate records nothing for
//     them).
// The PAT restriction is still checked by the consumer against the secret's
// scope, so a narrowed token is judged the same way twice.

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// gateReadDecision is the memo: the last secrets.read allow the request's gate made.
type gateReadDecision struct {
	mu     sync.Mutex
	userID uint
	secret *models.SecretNode // the row the gate decided on; nil = nothing recorded
}

type gateReadDecisionKey struct{}

// withGateReadDecision returns ctx carrying a fresh, empty memo.
func withGateReadDecision(ctx context.Context) context.Context {
	return context.WithValue(ctx, gateReadDecisionKey{}, &gateReadDecision{})
}

func gateReadDecisionFrom(ctx context.Context) *gateReadDecision {
	m, _ := ctx.Value(gateReadDecisionKey{}).(*gateReadDecision)
	return m
}

// noteGateReadAllow records that the gate allowed userID secrets.read (no action) on
// secret. Anything else is not recorded.
func noteGateReadAllow(ctx context.Context, userID uint, secret *models.SecretNode, perm string, action SecretAction) {
	m := gateReadDecisionFrom(ctx)
	if m == nil || perm != permSecretsRead || action != "" || userID == 0 || secret == nil || secret.ID == 0 ||
		actorTypeFromContext(ctx) == ActorTypeMachine {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userID, m.secret = userID, secret
}

// takeGateReadAllow returns the secret the gate allowed userID to read, when the memo
// holds exactly that (same user, same secret id), and clears the memo; nil otherwise.
func takeGateReadAllow(ctx context.Context, userID, secretID uint) *models.SecretNode {
	m := gateReadDecisionFrom(ctx)
	if m == nil || readPathReuseOff.Load() || actorTypeFromContext(ctx) == ActorTypeMachine {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.secret == nil || m.userID != userID || m.secret.ID != secretID {
		return nil
	}
	s := m.secret
	m.userID, m.secret = 0, nil
	return s
}

// readPathReuseOff disables both OPT-READPATH-2 reuses: the gate's read decision
// (the decision is evaluated twice) and the value step's schedule/version snapshot
// (read again), i.e. the read path as it was before. Tests only: the before/after
// equivalence runs every case both ways.
var readPathReuseOff atomic.Bool

// SetHumanReadReuseForTesting turns both reuses on (the default) or off. Tests only.
func SetHumanReadReuseForTesting(on bool) { readPathReuseOff.Store(!on) }
