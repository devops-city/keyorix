// login_budget_fallback.go — the per-IP login budget's behaviour when its
// LoginAttempt storage fails (Andrei, 2026-10-10, AUTH-AUDIT-1).
//
// The budget used to fail OPEN on a storage error (IsLoginRateLimited answered
// "not limited", RecordFailedLogin/ReserveLoginAttempt recorded nothing), so a
// database fault, or an attacker able to provoke one, removed the brute-force
// backstop entirely. Failing CLOSED instead would lock every user out on a DB
// hiccup. The decision is neither: on a storage error the budget falls back to
// this in-memory limiter, with the SAME limit (LoginMaxAttempts) and window
// (LoginWindow), keyed by the same canonical client IP the stored budget uses
// (CanonicalIP of the address the transport's trusted-proxy logic resolved).
//
// What it is and is not:
//   - per process. In HA each replica enforces its own copy during an outage,
//     so the effective cluster-wide limit is up to LoginMaxAttempts per replica
//     the attacker can reach. Still a bound, where fail-open was none.
//   - bounded: at most loginFallbackMaxIPs addresses (least recently used is
//     evicted), and per address only the attempts inside the window, capped,
//     are kept. Many distinct (spoofed or rotating) addresses evict each other
//     rather than exhaust memory; rotating addresses already defeats any per-IP
//     limit, stored or not.
//   - consulted IN ADDITION to the stored count: the attempts added to it are
//     those whose stored write failed, so adding them never double-counts,
//     and leftover entries age out with the window after storage recovers. The
//     counts are never merged into storage.
//   - mirrored while degraded (#3023 review): a write that SUCCEEDS while the
//     budget is on its fallback (any fallback within LoginWindow) is also
//     noted in memory, flagged as mirrored. A COUNT that fails is then judged
//     on memory including the mirrored attempts, so a budget whose count query
//     fails while its inserts succeed still binds (it used to fail open:
//     memory stayed empty and the IP was never limited). A count that works
//     ignores mirrored attempts: they are in the stored count already.
//   - releasable: a reservation taken here gets an id with loginFallbackIDBit
//     set, which no stored row id can carry, so ReleaseLoginAttempt (a
//     delivered login, #2936) refunds it here instead of in storage. Such an
//     id is meaningful only inside this process: it is never persisted to a
//     row other replicas read (sharedLoginSlot), so a fallback slot held by an
//     MFA challenge or a WebAuthn ceremony stays counted until it ages out.
//
// Every fallback is audited (EventLoginBudgetFallback, Success=false) and
// counted (keyorix_login_budget_fallback_total). The client sees no
// difference: a refusal from memory is the same 429 a stored refusal is.
package core

import (
	"container/list"
	"context"
	"fmt"
	"math/bits"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EventLoginBudgetFallback is the error event written each time the login
// budget had to use the in-memory fallback because LoginAttempt storage failed.
const EventLoginBudgetFallback = "auth.rate_limit_error"

// loginFallbackMaxIPs bounds the fallback's memory: at most this many client
// addresses are tracked, least recently used evicted first.
const loginFallbackMaxIPs = 10_000

// loginFallbackMaxPerIP caps the attempts kept per address. Anything at or
// above LoginMaxAttempts already refuses; the headroom lets releases (delivered
// logins) refund without dropping a still-counted failure below the limit.
const loginFallbackMaxPerIP = 4 * LoginMaxAttempts

// loginFallbackIDBit marks a reservation id as the fallback's own. Stored
// LoginAttempt ids are database sequence values that never reach the top bit.
const loginFallbackIDBit uint = 1 << (bits.UintSize - 1)

var loginBudgetFallbackTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_login_budget_fallback_total",
	Help: "Count of per-IP login budget operations that fell back to the in-memory limiter because LoginAttempt storage failed.",
})

type loginFallbackAttempt struct {
	id uint
	at time.Time
	// mirrored marks an attempt whose stored write succeeded: counted only
	// when the stored count cannot be read (IsLoginRateLimited).
	mirrored bool
	// storedID is the stored reservation a mirrored attempt belongs to (0 if
	// none), so releasing that reservation releases the mirror.
	storedID uint
}

type loginFallbackEntry struct {
	ip       string
	attempts []loginFallbackAttempt
}

// loginFallbackLimiter is the bounded in-memory per-IP window. Safe for
// concurrent use.
type loginFallbackLimiter struct {
	mu     sync.Mutex
	maxIPs int
	lru    *list.List               // front = most recently used; values *loginFallbackEntry
	byIP   map[string]*list.Element // ip -> element in lru
	byID   map[uint]string          // reservation id -> ip, for release
	// byStored maps a mirrored attempt's stored reservation id to its own id.
	byStored map[uint]uint
	nextID   uint
	// lastFallback is when the budget last fell back (zero: never); the
	// budget counts as degraded while that lies within LoginWindow.
	lastFallback time.Time
}

func newLoginFallbackLimiter(maxIPs int) *loginFallbackLimiter {
	return &loginFallbackLimiter{
		maxIPs:   maxIPs,
		lru:      list.New(),
		byIP:     map[string]*list.Element{},
		byID:     map[uint]string{},
		byStored: map[uint]uint{},
	}
}

// sharedLoginSlot is slotID as it may be persisted on a row every replica
// reads and that outlives this process (mfa_challenges / web_authn_sessions
// login_attempt_id): a stored reservation id as is, a fallback id never
// (#3023 review). A fallback id names a per-process counter value: another
// replica, or this one after a restart, releasing it would refund an unrelated
// reservation of its own, and with the top bit set it does not fit a signed
// 64-bit column (SQLite stores it negative and cannot read it back into a
// uint; the MFA or passkey login then fails during the very outage the
// fallback exists for). The fallback reservation simply stays counted until
// it ages out of the window: the strict side.
func sharedLoginSlot(slotID *uint) *uint {
	if slotID == nil || *slotID&loginFallbackIDBit != 0 {
		return nil
	}
	return slotID
}

// markDegraded notes that the budget fell back at now.
func (f *loginFallbackLimiter) markDegraded(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastFallback = now
}

// degraded reports whether the budget fell back within LoginWindow of now.
func (f *loginFallbackLimiter) degraded(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.lastFallback.IsZero() && now.Sub(f.lastFallback) <= LoginWindow
}

// mirrorIfDegraded notes a SUCCESSFUL stored write for ip in memory too while
// the budget is degraded, so a count that fails can still be judged (see
// IsLoginRateLimited). storedID, when non-zero, is the stored reservation the
// mirror belongs to: releasing it releases the mirror as well.
func (f *loginFallbackLimiter) mirrorIfDegraded(ip string, now time.Time, storedID uint) {
	if !f.degraded(now) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(ip)
	f.prune(e, now.Add(-LoginWindow))
	a := f.add(e, now)
	a.mirrored = true
	if storedID != 0 {
		a.storedID = storedID
		f.byStored[storedID] = a.id
	}
}

// loginBudgetFallback returns c's fallback limiter, created on first use so
// every way of constructing a KeyorixCore gets one.
func (c *KeyorixCore) loginBudgetFallback() *loginFallbackLimiter {
	c.loginFallbackOnce.Do(func() { c.loginFallback = newLoginFallbackLimiter(loginFallbackMaxIPs) })
	return c.loginFallback
}

// reserve records one attempt for ip at now and returns its id.
func (f *loginFallbackLimiter) reserve(ip string, now time.Time) uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(ip)
	f.prune(e, now.Add(-LoginWindow))
	return f.add(e, now).id
}

// add appends one attempt at now to e, keeping at most loginFallbackMaxPerIP,
// and returns it. Caller holds f.mu.
func (f *loginFallbackLimiter) add(e *loginFallbackEntry, now time.Time) *loginFallbackAttempt {
	f.nextID++
	id := f.nextID | loginFallbackIDBit
	e.attempts = append(e.attempts, loginFallbackAttempt{id: id, at: now})
	f.byID[id] = e.ip
	if len(e.attempts) > loginFallbackMaxPerIP {
		f.forget(e.attempts[0])
		e.attempts = e.attempts[1:]
	}
	return &e.attempts[len(e.attempts)-1]
}

// forget drops a's index entries. Caller holds f.mu.
func (f *loginFallbackLimiter) forget(a loginFallbackAttempt) {
	delete(f.byID, a.id)
	if a.storedID != 0 {
		delete(f.byStored, a.storedID)
	}
}

// count returns how many attempts ip has at or after since, mirrored ones
// only when withMirrored is set.
func (f *loginFallbackLimiter) count(ip string, since time.Time, withMirrored bool) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.byIP[ip]
	if !ok {
		return 0
	}
	e := el.Value.(*loginFallbackEntry)
	f.prune(e, since)
	n := 0
	for _, a := range e.attempts {
		if withMirrored || !a.mirrored {
			n++
		}
	}
	return n
}

// release removes the reservation id, if this limiter still holds it.
func (f *loginFallbackLimiter) release(id uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.byID[id]
	if !ok {
		return
	}
	delete(f.byID, id)
	el, ok := f.byIP[ip]
	if !ok {
		return
	}
	e := el.Value.(*loginFallbackEntry)
	for i, a := range e.attempts {
		if a.id == id {
			f.forget(a)
			e.attempts = append(e.attempts[:i], e.attempts[i+1:]...)
			break
		}
	}
}

// releaseMirror removes the mirrored attempt bound to the stored reservation
// storedID, if this limiter holds one.
func (f *loginFallbackLimiter) releaseMirror(storedID uint) {
	f.mu.Lock()
	id, ok := f.byStored[storedID]
	f.mu.Unlock()
	if ok {
		f.release(id)
	}
}

// size is the number of addresses currently tracked.
func (f *loginFallbackLimiter) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lru.Len()
}

// touch returns ip's entry, creating it (and evicting the least recently used
// address when full) as needed. Caller holds f.mu.
func (f *loginFallbackLimiter) touch(ip string) *loginFallbackEntry {
	if el, ok := f.byIP[ip]; ok {
		f.lru.MoveToFront(el)
		return el.Value.(*loginFallbackEntry)
	}
	for f.lru.Len() >= f.maxIPs {
		oldest := f.lru.Back()
		oe := oldest.Value.(*loginFallbackEntry)
		for _, a := range oe.attempts {
			f.forget(a)
		}
		delete(f.byIP, oe.ip)
		f.lru.Remove(oldest)
	}
	e := &loginFallbackEntry{ip: ip}
	f.byIP[ip] = f.lru.PushFront(e)
	return e
}

// prune drops ip's attempts older than since. Caller holds f.mu.
func (f *loginFallbackLimiter) prune(e *loginFallbackEntry, since time.Time) {
	keep := e.attempts[:0]
	for _, a := range e.attempts {
		if a.at.Before(since) {
			f.forget(a)
			continue
		}
		keep = append(keep, a)
	}
	e.attempts = keep
}

// noteLoginBudgetFallback audits and counts one fallback. The audit write is
// best-effort like every audit write on this path; during a full outage it
// will usually fail too, which is why the metric exists.
func (c *KeyorixCore) noteLoginBudgetFallback(ctx context.Context, op, ip string, err error) {
	loginBudgetFallbackTotal.Inc()
	c.loginBudgetFallback().markDegraded(c.now())
	c.writeAuditEventFailed(ctx, EventLoginBudgetFallback, nil, nil, ip,
		fmt.Sprintf("login rate limit %s for %s fell back to the in-memory limiter: LoginAttempt storage error: %v", op, ip, err))
}
