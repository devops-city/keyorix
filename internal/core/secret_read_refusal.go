// secret_read_refusal.go — the secret's own state refusing a value read
// (ERRMAP-1).
//
// After the caller's read permission has been established, a value read can
// still be refused by the secret itself: outside its access schedule, past its
// expiration, while suspended, or once its max-reads budget is spent. These are
// ordinary, caller-actionable outcomes, not server faults, so every transport
// maps them to a client error with a stable code instead of 500/Internal:
//
//	refusal                      REST  gRPC                error code
//	outside access schedule      403   PermissionDenied    SecretAccessOutsideSchedule
//	expired                      409   FailedPrecondition  SecretExpired
//	suspended                    409   FailedPrecondition  SecretSuspended
//	max reads exhausted          409   FailedPrecondition  SecretMaxReadsExhausted
//
// The schedule is a permission decision (who may read, and when), so it shares
// the 403/PermissionDenied of every other read denial. The other three describe
// the secret's current state, each reversible by an operator (extend or clear
// the expiration, resume, raise max_reads), so they are 409 Conflict — the
// status this API already uses for "the resource's state does not allow this
// request" — rather than 410 Gone (which claims permanence and is cacheable by
// default) or 403 (which clients read as "you lack permission").
//
// Only ever classify an error from a read whose authorization already passed:
// the refusals name the secret's state, so surfacing one to a caller who cannot
// see the secret would confirm it exists. Every value-read path checks read
// permission before these guards run (see enforceSecretReadGuardsWith).
package core

import (
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// Sentinels for the secret-state refusals. ErrAccessOutsideSchedule
// (secret_schedule.go) is the fourth member of the family.
var (
	ErrSecretExpired           = errors.New("secret has expired")
	ErrSecretSuspended         = errors.New("secret is suspended")
	ErrSecretMaxReadsExhausted = errors.New("secret has reached its maximum number of reads")
)

// secretStateError keeps a refusal's existing (localized) message text while
// letting errors.Is find its sentinel.
type secretStateError struct {
	msg      string
	sentinel error
	// clearSyncedCopies is set on a suspended refusal whose suspension carries the
	// "also clear synced Kubernetes copies" marker (SecretNode.SuspendClearSyncedCopies).
	clearSyncedCopies bool
}

func (e *secretStateError) Error() string { return e.msg }
func (e *secretStateError) Unwrap() error { return e.sentinel }

// errSecretExpired carries clearSyncedCopies only when the expired secret is also
// suspended with the clear marker (#3215); every other expired refusal passes false.
func errSecretExpired(clearSyncedCopies bool) error {
	return &secretStateError{msg: i18n.T("ErrorSecretExpired", nil), sentinel: ErrSecretExpired, clearSyncedCopies: clearSyncedCopies}
}

func errSecretSuspended(clearSyncedCopies bool) error {
	return &secretStateError{msg: "secret is suspended", sentinel: ErrSecretSuspended, clearSyncedCopies: clearSyncedCopies}
}

func errSecretMaxReadsExhausted() error {
	return &secretStateError{msg: i18n.T("ErrorMaxReadsExceeded", nil), sentinel: ErrSecretMaxReadsExhausted}
}

// SecretReadRefusalKind says which class of client error a refusal is.
type SecretReadRefusalKind int

const (
	// SecretReadRefusalDenied is a permission-class refusal (REST 403,
	// gRPC PermissionDenied).
	SecretReadRefusalDenied SecretReadRefusalKind = iota + 1
	// SecretReadRefusalState is a secret-state refusal (REST 409,
	// gRPC FailedPrecondition).
	SecretReadRefusalState
)

// Stable wire codes (the REST error envelope's `error` field). Part of the API
// contract: clients branch on them, so never rename one.
const (
	SecretReadRefusalCodeOutsideSchedule   = "SecretAccessOutsideSchedule"
	SecretReadRefusalCodeExpired           = "SecretExpired"
	SecretReadRefusalCodeSuspended         = "SecretSuspended"
	SecretReadRefusalCodeMaxReadsExhausted = "SecretMaxReadsExhausted"
)

// SecretReadRefusal is the client-safe description of a refused value read: a
// stable code and a fixed message that carries no internal error text.
type SecretReadRefusal struct {
	Kind    SecretReadRefusalKind
	Code    string
	Message string
	// ClearSyncedCopies is true only on a SecretSuspended refusal whose suspension asked
	// for the synced Kubernetes copies to be cleared, or on a SecretExpired refusal of a
	// secret that is also suspended with that marker (expiry is judged first, #3215).
	// An expired secret that is not suspended never carries it. Authorization has already passed
	// when a refusal is built (see the file comment), so it reveals nothing new.
	ClearSyncedCopies bool
}

// secretReadRefusals is the whole family, in the order ClassifySecretReadRefusal
// tests them. Exported read-only through SecretReadRefusalFamily for the
// transport-level family tests.
var secretReadRefusals = []struct {
	sentinel error
	refusal  SecretReadRefusal
}{
	{ErrAccessOutsideSchedule, SecretReadRefusal{Kind: SecretReadRefusalDenied, Code: SecretReadRefusalCodeOutsideSchedule,
		Message: "secret access is not permitted outside the configured time window"}},
	{ErrSecretExpired, SecretReadRefusal{Kind: SecretReadRefusalState, Code: SecretReadRefusalCodeExpired,
		Message: "secret has expired; its value can no longer be read"}},
	{ErrSecretSuspended, SecretReadRefusal{Kind: SecretReadRefusalState, Code: SecretReadRefusalCodeSuspended,
		Message: "secret is suspended; its value cannot be read until it is resumed"}},
	{ErrSecretMaxReadsExhausted, SecretReadRefusal{Kind: SecretReadRefusalState, Code: SecretReadRefusalCodeMaxReadsExhausted,
		Message: "secret has reached its maximum number of reads"}},
}

// ClassifySecretReadRefusal reports whether err is one of the secret-state
// refusals above and, if so, its client-safe form. Call it only on an error
// from a read whose authorization already passed (see the file comment).
func ClassifySecretReadRefusal(err error) (SecretReadRefusal, bool) {
	if err == nil {
		return SecretReadRefusal{}, false
	}
	for _, r := range secretReadRefusals {
		if errors.Is(err, r.sentinel) {
			out := r.refusal
			var se *secretStateError
			if errors.As(err, &se) && (se.sentinel == ErrSecretSuspended || se.sentinel == ErrSecretExpired) {
				out.ClearSyncedCopies = se.clearSyncedCopies
			}
			return out, true
		}
	}
	return SecretReadRefusal{}, false
}

// SecretReadRefusalFamily returns every refusal's sentinel and client form, for
// tests that must cover the whole family.
func SecretReadRefusalFamily() map[error]SecretReadRefusal {
	out := make(map[error]SecretReadRefusal, len(secretReadRefusals))
	for _, r := range secretReadRefusals {
		out[r.sentinel] = r.refusal
	}
	return out
}

// String names the kind for test output.
func (k SecretReadRefusalKind) String() string {
	switch k {
	case SecretReadRefusalDenied:
		return "denied"
	case SecretReadRefusalState:
		return "state"
	default:
		return fmt.Sprintf("SecretReadRefusalKind(%d)", int(k))
	}
}
