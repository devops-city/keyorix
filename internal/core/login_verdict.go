package core

import (
	"context"
	"sync/atomic"
)

// LoginVerdict records whether a second-factor login has reached a verdict on
// the submitted credential: the TOTP code or recovery code was compared, or
// the WebAuthn assertion was validated, whatever the result.
//
// It exists for a transport that has to act on a PANIC, where no error value
// says how far the call got (#3048). The HTTP handlers reserve the per-IP
// login-attempt slot before calling core and hand it back on a panic only
// while Reached() is false. A pre-verdict storage panic says nothing about
// the credential, so it must not spend the IP's budget (#2565, CR3). After
// the verdict, the request was a real attempt and keeps its slot, exactly as
// the same fault returned as an error does (#2880, #2894). Releasing it then
// would make a faulted correct credential cheaper than a wrong one.
//
// A nil *LoginVerdict reports false, so a caller that did not ask for one
// keeps the conservative "not reached" reading.
type LoginVerdict struct{ reached atomic.Bool }

type loginVerdictKey struct{}

// WithLoginVerdict returns ctx carrying a fresh LoginVerdict for core's login
// functions to mark, and that verdict.
func WithLoginVerdict(ctx context.Context) (context.Context, *LoginVerdict) {
	v := &LoginVerdict{}
	return context.WithValue(ctx, loginVerdictKey{}, v), v
}

// Reached reports whether the credential had been evaluated.
func (v *LoginVerdict) Reached() bool { return v != nil && v.reached.Load() }

// markLoginVerdict records, on ctx's LoginVerdict if it carries one, that the
// credential has been evaluated. It must run BEFORE the first storage call
// that follows the evaluation, or a panic in that call would still read as
// pre-verdict.
func markLoginVerdict(ctx context.Context) {
	if v, ok := ctx.Value(loginVerdictKey{}).(*LoginVerdict); ok {
		v.reached.Store(true)
	}
}
