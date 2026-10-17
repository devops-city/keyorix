// mfa_upgrade_grace.go: ADR-112's security.require_mfa upgrade grace period at
// runtime (#2923).
//
// An upgraded deployment that never set security.require_mfa does not enforce
// MFA straight away: server/adr112_grace.go decides at boot that this deployment
// is in the grace period, records its start durably in system_metadata (first
// boot on the version that introduced it) and installs the window here. The
// grace period then ends at whichever comes first:
//
//   - the first global admin-tier holder with a second factor (TOTP or passkey):
//     from then on an admin exists who can enrol or reset everyone else;
//   - the deadline, 30 days after the recorded start.
//
// Once ended it is ended for good: the enforcement marker is written, the latch
// below never reopens, and server/adr112_grace.go never grants the grace period
// to a deployment that carries the marker.
//
// The clock never extends the grace period. The window's floor is the latest
// time any boot recorded (the clock high-water mark); within a process the
// grace clock is the larger of the wall clock and floor plus the monotonic time
// elapsed since install. A wall clock stepped backwards is therefore ignored,
// and a wall clock stepped forwards only ends the grace period sooner.
//
// Fails closed: while the facts cannot be read (admin set, marker), the grace
// period is not in effect for that check, so MFA is enforced.
package core

import (
	"context"
	"log"
	"sync"
	"time"
)

// mfaGraceRecheck is how long one evaluation of the grace period is reused. It
// bounds how long the grace period can outlive the first admin enrolment (or a
// marker written by another replica) on this process.
const mfaGraceRecheck = 15 * time.Second

// mfaGraceClockPersistEvery is how often the grace clock's high-water mark is
// written back, so a restart after a backward clock step resumes from at most
// this much earlier.
const mfaGraceClockPersistEvery = time.Minute

// MFAUpgradeGraceWindow is what server/adr112_grace.go read and recorded at boot.
type MFAUpgradeGraceWindow struct {
	// Start is the durable grace start (first boot on the version that
	// introduced the bounded grace period); Deadline is Start plus the period.
	Start, Deadline time.Time
	// Floor is the latest time any boot recorded for this deployment (never
	// before Start). The grace clock never reads earlier than it.
	Floor time.Time
	// EnforcedMarkerKey is the system_metadata key written when the grace period
	// ends (config.ADR112RequireMFAEnforcedMarker); ClockKey holds the grace
	// clock's high-water mark (config.ADR112RequireMFAGraceClockKey).
	EnforcedMarkerKey, ClockKey string
}

// MFAUpgradeGraceStatus is a running grace period, as reported to clients.
type MFAUpgradeGraceStatus struct {
	EndsAt   time.Time
	DaysLeft int
}

type mfaUpgradeGrace struct {
	w MFAUpgradeGraceWindow
	// wallNow and elapsed are the wall clock and the monotonic time since
	// install; replaced in tests.
	wallNow func() time.Time
	elapsed func() time.Duration
	// base is max(wall clock at install, Floor): the grace clock is never below
	// base + elapsed().
	base time.Time

	mu        sync.Mutex
	ended     bool
	checked   bool
	checkedAt time.Duration // elapsed() at the last evaluation
	active    bool
	persisted time.Time // the last high-water mark written
	loggedDay int       // the days-left count last logged
}

// StartMFAUpgradeGrace installs ADR-112's require_mfa upgrade grace period for
// this process. Only server/adr112_grace.go calls it, at boot, after it decided
// this is an upgraded deployment inside the window.
func (c *KeyorixCore) StartMFAUpgradeGrace(w MFAUpgradeGraceWindow) {
	installed := time.Now()
	c.installMFAUpgradeGrace(w, func() time.Time { return time.Now().Round(0) }, func() time.Duration { return time.Since(installed) })
}

func (c *KeyorixCore) installMFAUpgradeGrace(w MFAUpgradeGraceWindow, wallNow func() time.Time, elapsed func() time.Duration) {
	w.Floor = maxTime(w.Floor, w.Start)
	c.mfaGrace = &mfaUpgradeGrace{
		w: w, wallNow: wallNow, elapsed: elapsed,
		base:      maxTime(wallNow(), w.Floor),
		persisted: w.Floor,
		loggedDay: -1,
	}
}

// MFARequired reports whether security.require_mfa is in force right now: the
// deployment requires MFA and ADR-112's upgrade grace period is not running.
// Every MFA gate reads this (session issuance here, the HTTP setup gate, the
// gRPC interceptors), so they agree for the whole life of the process.
func (c *KeyorixCore) MFARequired() bool {
	return c.deploymentRequiresMFA && !c.MFAUpgradeGraceActive()
}

// MFAUpgradeGraceActive reports whether ADR-112's require_mfa upgrade grace
// period is running. False when none was installed, once it has ended, and for
// any evaluation that could not read its facts (fail closed).
func (c *KeyorixCore) MFAUpgradeGraceActive() bool {
	_, ok := c.MFAUpgradeGraceStatus()
	return ok
}

// MFAUpgradeGraceEnded reports whether this process saw the grace period end
// for good (deadline, admin enrolment or the marker). A failed evaluation does
// not count: it suspends the grace period for one check, it does not end it.
func (c *KeyorixCore) MFAUpgradeGraceEnded() bool {
	g := c.mfaGrace
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ended
}

// MFAUpgradeGraceStatus returns the running grace period's end and the whole
// days left (rounded up), and false when it is not running.
func (c *KeyorixCore) MFAUpgradeGraceStatus() (MFAUpgradeGraceStatus, bool) {
	g := c.mfaGrace
	if g == nil {
		return MFAUpgradeGraceStatus{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.evaluate(c) {
		return MFAUpgradeGraceStatus{}, false
	}
	return MFAUpgradeGraceStatus{EndsAt: g.w.Deadline, DaysLeft: graceDaysLeft(g.now(), g.w.Deadline)}, true
}

// recheckMFAUpgradeGrace drops the cached evaluation, so the next MFA check
// re-reads the facts. Called after a second factor was enrolled: if it was the
// first administrator's, the grace period ends at that check rather than up to
// mfaGraceRecheck later.
func (c *KeyorixCore) recheckMFAUpgradeGrace() {
	g := c.mfaGrace
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.checked = false
}

// now is the grace clock: never earlier than base plus the monotonic time
// since install, so a backward wall-clock step does not move it back.
func (g *mfaUpgradeGrace) now() time.Time {
	return maxTime(g.wallNow(), g.base.Add(g.elapsed()))
}

// evaluate answers "is the grace period running", reusing the last answer for
// mfaGraceRecheck. Called with g.mu held.
func (g *mfaUpgradeGrace) evaluate(c *KeyorixCore) bool {
	if g.ended {
		return false
	}
	if g.checked && g.elapsed()-g.checkedAt < mfaGraceRecheck {
		return g.active
	}
	g.checked, g.checkedAt = true, g.elapsed()
	g.active = false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := g.now()
	if !now.Before(g.w.Deadline) {
		g.end(ctx, c, now, "its 30-day period ended at "+g.w.Deadline.UTC().Format(time.RFC3339))
		return false
	}
	if _, found, err := c.storage.GetSystemMetadata(ctx, g.w.EnforcedMarkerKey); err != nil {
		log.Printf("WARNING: ADR-112 grace period: could not read the %s marker (%v); enforcing security.require_mfa until the next check", g.w.EnforcedMarkerKey, err)
		return false
	} else if found {
		g.end(ctx, c, now, "another server of this deployment already ended it")
		return false
	}
	enrolled, err := c.AnyAdminHasSecondFactor(ctx)
	if err != nil {
		log.Printf("WARNING: ADR-112 grace period: could not tell whether an administrator has enrolled MFA (%v); enforcing security.require_mfa until the next check", err)
		return false
	}
	if enrolled {
		g.end(ctx, c, now, "an administrator has enrolled a second factor")
		return false
	}

	g.active = true
	if now.Sub(g.persisted) >= mfaGraceClockPersistEvery {
		if err := c.storage.SetSystemMetadata(ctx, g.w.ClockKey, now.UTC().Format(time.RFC3339)); err != nil {
			log.Printf("WARNING: ADR-112 grace period: could not record the grace clock (%v); continuing", err)
		} else {
			g.persisted = now
		}
	}
	if days := graceDaysLeft(now, g.w.Deadline); days != g.loggedDay {
		g.loggedDay = days
		log.Printf("WARNING: ADR-112 grace period: security.require_mfa is NOT enforced yet on this upgraded deployment: %d day(s) left (until %s, or until the first administrator enrols a second factor). Users without MFA can still sign in; after that they are sent to MFA enrolment.", days, g.w.Deadline.UTC().Format(time.RFC3339))
	}
	return true
}

// end latches the grace period closed and writes the enforcement marker, so no
// later boot grants it again. The latch holds even if the write fails: the next
// boot re-derives the same end from the deadline or the enrolled admin.
func (g *mfaUpgradeGrace) end(ctx context.Context, c *KeyorixCore, now time.Time, why string) {
	g.ended = true
	log.Printf("WARNING: ADR-112 grace period for security.require_mfa has ended (%s). MFA is now enforced: users without a second factor are sent to MFA enrolment when they sign in (keyorix mfa enroll, or Profile -> Security in the web UI); PAT and machine credentials are unaffected.", why)
	if _, found, err := c.storage.GetSystemMetadata(ctx, g.w.EnforcedMarkerKey); err == nil && found {
		return
	}
	// Audited once per deployment: the replica that writes the marker. The
	// start-to-start settings diff records the same transition at the next boot.
	c.writeAuditEventFull(ctx, "security.require_mfa_grace_ended", nil, nil, nil, "",
		"ADR-112 require_mfa upgrade grace period ended ("+why+"); MFA is now enforced for interactive logins")
	if err := c.storage.SetSystemMetadata(ctx, g.w.EnforcedMarkerKey, now.UTC().Format(time.RFC3339)); err != nil {
		log.Printf("WARNING: ADR-112: could not record the %s marker (%v); MFA stays enforced on this server, and the next boot re-derives the end", g.w.EnforcedMarkerKey, err)
	}
}

// graceDaysLeft is the whole days from now to deadline, rounded up (1 on the
// last day), and 0 once it has passed.
func graceDaysLeft(now, deadline time.Time) int {
	left := deadline.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + 24*time.Hour - 1) / (24 * time.Hour))
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
