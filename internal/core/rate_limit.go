// rate_limit.go — cluster-wide login brute-force rate limiting (ADR-040). A
// windowed count of failed attempts per IP, persisted in the DB so the limit holds
// across HA replicas (the old limiter was a per-process in-memory map). Rate
// limiting is a backstop on top of the real password/passkey checks, so a storage
// error fails OPEN (allow) rather than locking everyone out on a DB hiccup.
package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// CanonicalIP returns addr's IP address in canonical (net.IP.String()) form,
// stripping any ":port" suffix first when present — via net.SplitHostPort,
// which correctly handles bracketed IPv6 ("[::1]:8080") as well as plain
// "host:port" forms, falling back to treating addr itself as a bare
// host/IP when SplitHostPort finds no port (including a bare, unbracketed
// IPv6 address, which SplitHostPort always rejects as ambiguous). If the
// resulting host doesn't parse as an IP at all, it is returned unchanged.
//
// #G20: a rate-limit key built from an uncanonicalized source string lets
// trivially different textual representations of the SAME source — an
// alternate compressed/expanded IPv6 form, a bracketed vs. bare address, a
// fresh ephemeral TCP port from simply reconnecting — land in different
// buckets, defeating the shared budget entirely and growing the limiter map
// without bound. Used as the single shared canonicalization point for every
// per-source rate limiter in this codebase (HTTP login/password-reset/SSO
// limiters here, the gRPC per-principal limiter's IP fallback, and the HTTP
// handlers that derive a rate-limit key from r.RemoteAddr directly).
func CanonicalIP(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

const (
	// LoginMaxAttempts is the failed-attempt budget per IP within LoginWindow.
	LoginMaxAttempts = 10
	// LoginWindow is the sliding window over which attempts are counted.
	LoginWindow = 15 * time.Minute
)

// IsLoginRateLimited reports whether an IP has reached the failed-login budget
// within the window. Fails open (false) on an empty IP or a storage error.
func (c *KeyorixCore) IsLoginRateLimited(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	ip = CanonicalIP(ip)
	n, err := c.storage.CountRecentLoginAttempts(ctx, ip, c.now().Add(-LoginWindow))
	if err != nil {
		return false
	}
	return n >= LoginMaxAttempts
}

// RecordFailedLogin records a failed authentication attempt from an IP.
// Best-effort: a storage error does not block the response path.
func (c *KeyorixCore) RecordFailedLogin(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	_ = c.storage.RecordLoginAttempt(ctx, CanonicalIP(ip), c.now())
}

// ReserveLoginAttempt is RecordFailedLogin's releasable counterpart: it
// reserves a login-attempt slot up front (same race-closing placement F2
// documents on reserveLoginAttempt — before the slow credential check runs,
// not after), but returns a handle the caller can use to undo the write via
// ReleaseLoginAttempt if that check turns out to be a storage/internal error
// rather than a confirmed result. Returns ok=false (no handle) on an empty IP
// or a storage error — same fail-open posture as every sibling limiter in
// this file; a caller that gets ok=false has nothing to release and should
// not call ReleaseLoginAttempt.
func (c *KeyorixCore) ReserveLoginAttempt(ctx context.Context, ip string) (id uint, ok bool) {
	if ip == "" {
		return 0, false
	}
	id, err := c.storage.ReserveLoginAttempt(ctx, CanonicalIP(ip), c.now())
	if err != nil {
		return 0, false
	}
	return id, true
}

// ReleaseLoginAttempt undoes a ReserveLoginAttempt reservation. Best-effort,
// mirroring RecordFailedLogin: a storage error here does not surface to the
// caller, it just leaves the reservation counted as if release had never been
// attempted.
//
// Through besteffort.Run, which also recovers a PANIC: since #2936 this runs
// on the SUCCESS path of every login-family handler (a delivered session
// returns its slot), after the session is already minted, so an escaping
// panic would report a completed login as a 500 -- the post-commit
// best-effort class besteffort exists for. A recovered panic leaves the slot
// counted, the same strict-side outcome as a returned error.
func (c *KeyorixCore) ReleaseLoginAttempt(ctx context.Context, id uint) {
	besteffort.Run(ctx, "rate_limit.ReleaseLoginAttempt", func() error {
		return c.storage.ReleaseLoginAttempt(ctx, id)
	})
}

// ErrInvalidLoginAttemptKey is returned by RecordLoginAttemptRelay when the
// caller-supplied key is neither a valid IP address nor a known namespace
// prefix followed by one.
var ErrInvalidLoginAttemptKey = errors.New("ip must be a valid IP address, optionally prefixed with a known rate-limit namespace")

// ErrFutureLoginAttemptTimestamp is returned by RecordLoginAttemptRelay when
// the caller-supplied `at` is later than this server's own clock. See that
// function's doc for why this is a hard rejection, not a silent clamp.
var ErrFutureLoginAttemptTimestamp = errors.New("at must not be later than the current time")

// loginAttemptRelayPrefixes are the only namespace prefixes a legitimate relay
// (RecordLoginAttemptRelay's caller) ever needs to report: the same two
// RecordPasswordResetAttempt/RecordSSOBeginAttempt apply before writing to the
// shared login_attempts table. Anything else is not a real rate-limit key this
// codebase produces.
var loginAttemptRelayPrefixes = []string{passwordResetRateLimitPrefix, ssoRateLimitPrefix}

// RecordLoginAttemptRelay persists a login/password-reset/SSO-begin attempt
// relayed from a downstream server's own RecordFailedLogin/
// RecordPasswordResetAttempt/RecordSSOBeginAttempt call
// (server/http/handlers/login_attempts_proxy.go's RecordLoginAttemptProxy is
// the only caller — an attacker-influenced HTTP body, not a value this
// process derived itself). Two gaps closed here (G80 documented-exception
// re-verification sweep, found six weeks after PruneLoginAttemptsProxy's
// sibling CORE-RATE-003 fix in this same file — the "record" endpoint's own
// fields were never given the equivalent scrutiny at the time):
//
//  1. The wire "ip" field was never validated to actually BE an IP, or a
//     known-prefix + IP. A caller holding only system.write could submit the
//     LITERAL string "pwreset:<victim-ip>" or "sso:<victim-ip>" as the whole
//     key, corrupting a DIFFERENT rate limiter's bucket for a victim IP the
//     caller doesn't control — e.g. ten such calls lock that victim out of
//     password-reset or SSO/SAML login initiation, without ever touching the
//     ordinary login limiter at all.
//  2. `at` was accepted completely unbounded. PruneLoginAttempts (this file)
//     can only ever delete rows with `attempted_at < now-LoginWindow` — a
//     caller setting `at` to a far-future value (e.g. year 2099) creates a
//     row NO maintenance sweep can ever become eligible to remove: a
//     PERMANENT, unrecoverable lockout of whatever key it targets, strictly
//     worse than the bounded-window abuse case CORE-RATE-003 closed for prune.
//
// A KNOWN prefix is stripped if present and the remainder is canonicalized
// via CanonicalIP and REQUIRED to parse as a real IP — an unprefixed,
// non-IP key is rejected outright rather than persisted verbatim. `at` in
// the future is REJECTED outright (ErrFutureLoginAttemptTimestamp), not
// silently clamped to now: a relay reports an event that already happened on
// the downstream server's own clock, so a future `at` is either a clock
// skew large enough to be worth surfacing, or a caller deliberately probing
// how far the field is trusted — a silent substitution answers that
// question for them with no signal on this end that anything was rejected,
// and (independent verification session, 2026-08-25) is untestable as a
// rejection: a test asserting "the write succeeded with some clamped value"
// cannot distinguish "correctly clamped" from "accepted verbatim and just
// happens to look right," which is exactly how this gap went unnoticed the
// first time.
func (c *KeyorixCore) RecordLoginAttemptRelay(ctx context.Context, key string, at time.Time) error {
	prefix, remainder := "", key
	for _, p := range loginAttemptRelayPrefixes {
		if rest, ok := strings.CutPrefix(key, p); ok {
			prefix, remainder = p, rest
			break
		}
	}
	canon := CanonicalIP(remainder)
	if net.ParseIP(canon) == nil {
		return ErrInvalidLoginAttemptKey
	}
	if at.After(c.now()) {
		return ErrFutureLoginAttemptTimestamp
	}
	if err := c.storage.RecordLoginAttempt(ctx, prefix+canon, at); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// PruneLoginAttempts removes login/password-reset rate-limit rows older than
// `before`. `before` is clamped so the effective cutoff can never be LATER
// than `now - LoginWindow` — the maintenance sweep's own invariant (server/
// main.go always calls this with a zero `before`, which resolves to exactly
// that cutoff) — so a caller can only narrow the deletion window, never widen
// it into an unbounded wipe. This is the sole enforcement point for the
// bound: server/http/handlers/login_attempts_proxy.go's PruneLoginAttemptsProxy
// (the only other caller, decoding an attacker-influenced `before` from an
// HTTP request body) routes through this method rather than calling
// c.storage.PruneLoginAttempts directly, specifically so it cannot bypass the
// clamp (CORE-RATE-003: an unbounded `before` let any principal holding
// system.write wipe the entire login_attempts table on demand — every IP's
// failed-attempt count and the only record a brute-force campaign was ever
// attempted from any address — with no trace).
//
// actorID is the acting principal's user ID (0 for the scheduler / a
// non-user principal — e.g. a node/machine credential — matching
// writeRBACAudit's "0 = no authenticated principal" convention; the
// context's ActorType tag, set by the caller, still distinguishes
// system/machine/user attribution on the emitted event). Returns the number
// of rows removed. When anything is actually removed, emits a
// `data.login_attempts_pruned` audit event recording the actor, row count,
// and effective cutoff — mirroring PurgeExpiredSoftDeletes/
// PurgeExpiredComplianceRecords, which this primitive previously had no
// equivalent of at all.
func (c *KeyorixCore) PruneLoginAttempts(ctx context.Context, before time.Time, actorID uint) (int64, error) {
	cutoff := c.now().Add(-LoginWindow)
	if !before.IsZero() && before.Before(cutoff) {
		cutoff = before
	}

	n, err := c.storage.PruneLoginAttempts(ctx, cutoff)
	if err != nil {
		return n, err
	}
	if n > 0 {
		var actor *uint
		if actorID != 0 {
			actor = &actorID
		}
		c.writeAuditEvent(ctx, "data.login_attempts_pruned", actor, nil,
			fmt.Sprintf("login-attempts prune removed %d row(s) older than %s", n, cutoff.UTC().Format(time.RFC3339)))
	}
	return n, nil
}

// passwordResetRateLimitPrefix namespaces password-reset attempts within the
// SAME LoginAttempt table the login rate limiter uses (ADR-040), so a
// password-reset flood budget is tracked per-IP separately from — but reuses
// the identical cluster-wide, DB-backed limiter as — failed login attempts.
// POST /auth/password-reset (#249) is fully unauthenticated and had zero
// rate-limiting of any kind before this; composing the key this way (rather
// than a second table/migration) matches the codebase's existing convention
// for "per-IP request budget" and needs no schema change.
const passwordResetRateLimitPrefix = "pwreset:" // NOSONAR

const (
	// PasswordResetMaxAttempts is the request budget per IP within
	// PasswordResetWindow. Deliberately tighter than LoginMaxAttempts: each
	// request potentially triggers a real outbound email, so the budget is a
	// mail-bombing defense, not just a guess-throttle.
	PasswordResetMaxAttempts = 5
	// PasswordResetWindow is the sliding window over which attempts are counted.
	PasswordResetWindow = 15 * time.Minute
)

// IsPasswordResetRateLimited reports whether an IP has reached the
// password-reset request budget within the window. Fails open (false) on an
// empty IP or a storage error — this is a defense-in-depth backstop on top of
// the per-email checkResendThrottle (ADR-028), not the sole abuse control.
func (c *KeyorixCore) IsPasswordResetRateLimited(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, passwordResetRateLimitPrefix+CanonicalIP(ip), c.now().Add(-PasswordResetWindow))
	if err != nil {
		return false
	}
	return n >= PasswordResetMaxAttempts
}

// RecordPasswordResetAttempt records a password-reset request from an IP.
// Unlike RecordFailedLogin (recorded only on a WRONG password), this is
// recorded on EVERY request regardless of outcome: the endpoint always returns
// success (enumeration-safe) and never signals which email is registered, so
// the request itself — not a distinguishable "failure" — is the abuse signal
// to budget against. Best-effort: a storage error does not block the response.
func (c *KeyorixCore) RecordPasswordResetAttempt(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	_ = c.storage.RecordLoginAttempt(ctx, passwordResetRateLimitPrefix+CanonicalIP(ip), c.now())
}

// ssoRateLimitPrefix namespaces SSO/SAML login-initiation attempts within the
// SAME LoginAttempt table (ADR-040), mirroring passwordResetRateLimitPrefix.
// #G82: BeginSSO/BeginSAML are both fully unauthenticated and each write a
// SSOLoginState row per call with no rate limit of any kind — an unbounded
// flood grows that table without limit and, since every SSOLoginState carries
// a fresh CSRF-protecting state/nonce, also churns through randomness/storage
// for no legitimate purpose. Shared between SSO and SAML since both are the
// same "pre-login state write" abuse shape against the same table.
const ssoRateLimitPrefix = "sso:" // NOSONAR

// SSOBeginMaxAttempts is the request budget per IP within SSOBeginWindow.
const SSOBeginMaxAttempts = 20

// SSOBeginWindow is the sliding window over which attempts are counted.
const SSOBeginWindow = 15 * time.Minute

// IsSSOBeginRateLimited reports whether an IP has reached the SSO/SAML
// login-initiation budget within the window. Fails open (false) on an empty
// IP or a storage error, matching the login/password-reset limiters' backstop
// (not the sole abuse control) design.
func (c *KeyorixCore) IsSSOBeginRateLimited(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, ssoRateLimitPrefix+CanonicalIP(ip), c.now().Add(-SSOBeginWindow))
	if err != nil {
		return false
	}
	return n >= SSOBeginMaxAttempts
}

// RecordSSOBeginAttempt records an SSO/SAML login-initiation request from an
// IP. Recorded on every call regardless of outcome (unknown-provider or
// success) — the request itself is the abuse signal. Best-effort: a storage
// error does not block the response.
func (c *KeyorixCore) RecordSSOBeginAttempt(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	_ = c.storage.RecordLoginAttempt(ctx, ssoRateLimitPrefix+CanonicalIP(ip), c.now())
}
