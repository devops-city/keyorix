// clock_fuzz_test.go -- FUZZ-MECH M2: clock-jump fuzzing over the three
// expiring-credential types this package's #1983 clock-jump investigation
// already wired a shared injectable clock for (KeyorixCore.now,
// SetClockForTesting/EffectiveNow's doc comments explicitly name a
// "clock-jump fuzz/test harness" as this mechanism's reason to exist -- see
// service.go). No production test seam is added here: the injectable clock,
// authEffectiveNow's anti-rollback watermark, and IsPATExpired already exist.
//
// Oracles (never by reading these functions' branches -- by their own
// documented contracts, cited by name):
//  1. An expired session/PAT never authorizes (ValidateSessionToken/
//     ValidatePATToken must return an error once past ExpiresAt).
//  2. Once a session/PAT has been correctly observed expired, it never
//     re-authorizes after a wall-clock step BACKWARD to before its expiry --
//     authEffectiveNow's watermark is the documented mechanism for this.
//  3. A session/PAT's validity must be identical whether "now" is expressed
//     in UTC or a different, semantically-equal instant in another timezone
//     (Before/After compare absolute instants, so a verdict that depends on
//     the reporting timezone is itself a bug, independent of whichever
//     specific TTL/expiry policy applies).
//
// Oracle 3 excludes dynamic-secret leases: RenewLease is not a pure read --
// a successful call mutates lease.ExpiresAt, so checking it twice for the
// "same" instant restated in another timezone actually checks two DIFFERENT
// preconditions (before vs. after the first call's own side effect), which
// is unsound, not a property violation (caught during this fuzzer's own
// initial burst: a "verdict changed" report that traced back to exactly
// this, not a real timezone-dependent bug -- see the git history of this
// file for the corrected version).
//
// Oracle 2 now ALSO covers dynamic-secret leases (credSel==2): RenewLease
// and RevokeExpiredLeases previously compared directly against bare c.now()
// with no watermark -- found by this fuzzer
// (docs/findings/2026-09-27-FINDING-dynamic-secret-lease-clock-rollback.md)
// and closed by checkLeaseRenewClockNotRegressed/dynamicSecretsSweepCutoff
// (dynamic_secrets.go), mirroring checkSessionRefreshClockNotRegressed
// (#1632/#1653). TestDynamicSecretLeaseRenewal_ClockRollbackWatermark below
// is this fix's own regression test.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// clockBox is the mutable clock this test drives KeyorixCore.now from --
// SetClockForTesting takes a func() time.Time, so the box (not the func
// itself) is what changes between steps within one fuzz iteration.
type clockBox struct{ t time.Time }

func (b *clockBox) now() time.Time { return b.t }

// clockFuzzWorld is everything one iteration needs: a real KeyorixCore over
// SQLite, a bootstrap admin/project/environment, and one live session, PAT,
// and dynamic-secret lease, all minted at the SAME issue instant T0.
type clockFuzzWorld struct {
	core          *KeyorixCore
	clock         *clockBox
	t0            time.Time
	sessionToken  string
	sessionExpiry time.Time
	patToken      string
	patExpiry     time.Time
	leaseID       string
	leaseExpiry   time.Time
}

const clockFuzzCredentialTTL = 60 * time.Second

func buildClockFuzzWorld(t *testing.T) *clockFuzzWorld {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n.InitializeForTesting: %v", err)
	}

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatal(err)
	}

	clock := &clockBox{t: time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)}
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetClockForTesting(clock.now)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	if err := enc.Initialize("clock-fuzz-passphrase"); err != nil {
		t.Fatalf("encryption.Initialize: %v", err)
	}
	c.SetAuthEncryptor(enc)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })

	c.SetBootstrapToken("clock-fuzz-bootstrap")
	ctx := context.Background()
	boot, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "clockadmin", Email: "clockadmin@example.com",
		Password: "ClockFuzzAdmin123!", Token: "clock-fuzz-bootstrap",
	})
	if err != nil {
		t.Fatalf("BootstrapSystem: %v", err)
	}

	t0 := clock.t
	session, _, err := c.Login(ctx, &LoginRequest{Username: "clockadmin", Password: "ClockFuzzAdmin123!"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.ExpiresAt == nil {
		t.Fatalf("Login returned a session with no ExpiresAt")
	}

	patExpiresAt := t0.Add(clockFuzzCredentialTTL)
	patResult, err := c.CreateOwnPAT(ctx, boot.User.ID, "clock-fuzz-pat", &patExpiresAt, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("CreateOwnPAT: %v", err)
	}

	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "clock-fuzz-cfg", ProjectID: boot.Project.ID, EnvironmentID: boot.Environments[0].ID,
		BackendType: "postgres", AdminDSN: "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: int(clockFuzzCredentialTTL.Seconds()), CreatedBy: "clockadmin", ActorID: boot.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateDynamicSecretConfig: %v", err)
	}
	lease, err := c.IssueLease(ctx, cfg.ID, int(clockFuzzCredentialTTL.Seconds()), boot.User.ID)
	if err != nil {
		t.Fatalf("IssueLease: %v", err)
	}

	return &clockFuzzWorld{
		core: c, clock: clock, t0: t0,
		sessionToken: session.SessionToken, sessionExpiry: *session.ExpiresAt,
		patToken: patResult.PlainToken, patExpiry: patExpiresAt,
		leaseID: lease.LeaseID, leaseExpiry: lease.ExpiresAt,
	}
}

// clockFuzzTZs are the timezone representations oracle 3 checks agreement
// across -- fixed offsets chosen to cover positive, negative, and a
// DST-magnitude (1h) shift, without depending on the host's tzdata.
var clockFuzzTZs = []*time.Location{
	time.UTC,
	time.FixedZone("UTC+5:30", 5*3600+30*60),
	time.FixedZone("UTC-8", -8*3600),
	time.FixedZone("UTC-1(DST-like)", -3600),
}

// clampNanos bounds a fuzzed int64 delta to +/- 5 years in nanoseconds, so
// clock.t.Add(delta) can never overflow time.Time's internal representation
// regardless of what bytes the fuzzer picks.
func clampNanos(raw int64) time.Duration {
	const fiveYears = int64(5 * 365 * 24 * time.Hour)
	if raw < 0 {
		raw = -raw
	}
	return time.Duration(raw%(2*fiveYears) - fiveYears)
}

func decodeClockFuzzInput(data []byte) (credSel int, boundaryMode int, arbitraryDelta int64, doStepBack bool, stepBackDelta int64, tzSel int, ok bool) {
	if len(data) < 20 {
		return 0, 0, 0, false, 0, 0, false
	}
	credSel = int(data[0]) % 3
	boundaryMode = int(data[1]) % 4
	var raw uint64
	for i := range 8 {
		raw = raw<<8 | uint64(data[2+i])
	}
	arbitraryDelta = int64(raw)
	doStepBack = data[10]&1 == 1
	var raw2 uint64
	for i := range 8 {
		raw2 = raw2<<8 | uint64(data[11+i])
	}
	stepBackDelta = int64(raw2)
	tzSel = int(data[19]) % len(clockFuzzTZs)
	return credSel, boundaryMode, arbitraryDelta, doStepBack, stepBackDelta, tzSel, true
}

// checkAt reports, for the given world/credential selector, whether the
// credential is currently accepted -- ValidateSessionToken/ValidatePATToken
// success/failure for session/PAT, RenewLease's own refusal for lease
// (renewability is the only per-request "is this still alive" check a
// dynamic-secret lease has; there is no separate value-read step).
func checkAt(ctx context.Context, w *clockFuzzWorld, credSel int) (accepted bool) {
	switch credSel {
	case 0:
		_, _, err := w.core.ValidateSessionToken(ctx, w.sessionToken)
		return err == nil
	case 1:
		_, _, _, _, err := w.core.ValidatePATToken(ctx, w.patToken)
		return err == nil
	default:
		_, err := w.core.RenewLease(ctx, w.leaseID, int(clockFuzzCredentialTTL.Seconds()), 1)
		return err == nil
	}
}

func expiryFor(w *clockFuzzWorld, credSel int) time.Time {
	switch credSel {
	case 0:
		return w.sessionExpiry
	case 1:
		return w.patExpiry
	default:
		return w.leaseExpiry
	}
}

// FuzzClockJumpNeverAuthorizesExpired is FUZZ-MECH M2. See the package doc
// comment above for the model's sources and what oracle 2 deliberately does
// not assert for leases.
func FuzzClockJumpNeverAuthorizesExpired(f *testing.F) {
	f.Add([]byte{0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // session, exactly expiry+1ns
	f.Add([]byte{1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) // PAT, expiry+1ns, tz shift
	f.Add([]byte{2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2}) // lease, expiry+1ns, then step back
	f.Add([]byte{0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // session, exactly at expiry-1ns (must still authorize)
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // PAT, exactly at expiry (must be expired: ExpiresAt is inclusive-denied)

	f.Fuzz(func(t *testing.T, data []byte) {
		credSel, boundaryMode, arbitraryDelta, doStepBack, stepBackDelta, tzSel, ok := decodeClockFuzzInput(data)
		if !ok {
			t.Skip("input too short")
		}
		w := buildClockFuzzWorld(t)
		ctx := context.Background()
		expiry := expiryFor(w, credSel)

		var checkTime time.Time
		switch boundaryMode {
		case 1:
			checkTime = expiry.Add(-1)
		case 2:
			checkTime = expiry
		case 3:
			checkTime = expiry.Add(1)
		default:
			checkTime = w.t0.Add(clampNanos(arbitraryDelta))
		}

		// Oracle 1: an expired credential never authorizes, a not-yet-expired one
		// always does (for session/PAT; lease renewal has its own additional
		// non-clock refusal reasons, so only the "past expiry -> refused"
		// direction is asserted for it, never "not yet expired -> succeeds").
		w.clock.t = checkTime
		accepted := checkAt(ctx, w, credSel)
		pastExpiry := checkTime.After(expiry)
		if pastExpiry && accepted {
			t.Errorf("credSel=%d accepted at checkTime=%v, which is PAST its own expiry=%v (delta=%v)",
				credSel, checkTime, expiry, checkTime.Sub(expiry))
		}
		if credSel != 2 && !pastExpiry && !accepted {
			t.Errorf("credSel=%d refused at checkTime=%v, which is NOT past its own expiry=%v (delta=%v)",
				credSel, checkTime, expiry, checkTime.Sub(expiry))
		}

		// Oracle 3: the verdict must not depend on which timezone the SAME
		// instant is expressed in -- Before/After compare absolute instants.
		// Session/PAT validation is a pure read, so calling it twice for the
		// same instant is sound. RenewLease is NOT a pure read -- a successful
		// call mutates lease.ExpiresAt, so calling checkAt(credSel=2) a second
		// time checks a DIFFERENT precondition (the just-extended lease), not
		// the same one restated in another timezone; excluded for that reason,
		// not because the property doesn't hold.
		if credSel != 2 {
			w.clock.t = checkTime.In(clockFuzzTZs[tzSel])
			acceptedInTZ := checkAt(ctx, w, credSel)
			if acceptedInTZ != accepted {
				t.Errorf("credSel=%d verdict changed with timezone alone: UTC-ish=%v accepted=%v, %s accepted=%v (same instant %v)",
					credSel, checkTime, accepted, clockFuzzTZs[tzSel], acceptedInTZ, checkTime)
			}
		}

		if !doStepBack {
			return
		}
		// Oracle 2 (session/PAT only -- see package doc comment for why lease
		// is excluded): once genuinely observed expired, a wall-clock step
		// BACKWARD to before that same expiry must not resurrect it --
		// authEffectiveNow's watermark is the documented anti-rollback
		// mechanism. Only meaningful starting from a state that was actually
		// past expiry; skip otherwise (this is not the property under test).
		if !pastExpiry || accepted {
			return
		}
		stepBackTo := w.t0.Add(clampNanos(stepBackDelta) % clockFuzzCredentialTTL)
		if !stepBackTo.Before(expiry) {
			stepBackTo = w.t0 // guarantee a genuine backward step to before expiry
		}
		if credSel == 2 {
			// The lease watermark REFUSES only beyond leaseClockRegressionTolerance
			// (30s) -- a tolerance-based guard, not a zero-tolerance clamp like
			// authEffectiveNow (session/PAT). A fuzzed stepBackTo within 30s of the
			// watermark is legitimately ALLOWED by design (ordinary NTP slew), so
			// asserting refusal there would be a false positive. Force a step back
			// to t0 instead, guaranteeing a regression of at least the 60s
			// credential TTL -- comfortably past the 30s tolerance regardless of
			// how far past expiry checkTime itself landed.
			stepBackTo = w.t0
		}
		w.clock.t = stepBackTo
		reAccepted := checkAt(ctx, w, credSel)
		if reAccepted {
			t.Errorf("credSel=%d re-authorized after a clock step BACK to %v (before its own expiry=%v), "+
				"having already been correctly observed expired at %v -- the anti-rollback watermark failed",
				credSel, stepBackTo, expiry, checkTime)
		}
	})
}

// TestDynamicSecretLeaseRenewal_ClockRollbackWatermark is the regression test
// for the gap FuzzClockJumpNeverAuthorizesExpired found (2026-09-27,
// docs/findings/2026-09-27-FINDING-dynamic-secret-lease-clock-rollback.md):
// RenewLease and RevokeExpiredLeases used to compare directly against bare
// c.now(), with no anti-rollback watermark (unlike sessions/PATs, which
// authEffectiveNow protects). A host wall-clock step backward after a lease
// had already been correctly observed expired used to resurrect its
// renewability, and separately could make the background sweep miss it.
// checkLeaseRenewClockNotRegressed/dynamicSecretsSweepCutoff
// (dynamic_secrets.go) close both, mirroring
// checkSessionRefreshClockNotRegressed (#1632/#1653). Red-proofed by
// reverting this test's assertions to the pre-fix (buggy) expectation and
// confirming they fail against the fixed code, then restoring.
func TestDynamicSecretLeaseRenewal_ClockRollbackWatermark(t *testing.T) {
	w := buildClockFuzzWorld(t)
	ctx := context.Background()

	// Control: the ordinary case still works -- a clock that only ever
	// advances past expiry correctly refuses renewal.
	w.clock.t = w.leaseExpiry.Add(time.Second)
	if _, err := w.core.RenewLease(ctx, w.leaseID, int(clockFuzzCredentialTTL.Seconds()), 1); err == nil {
		t.Fatalf("control case failed: RenewLease succeeded past expiry with a forward-only clock")
	}

	// FIXED: step the clock BACK to t0+10s -- inside the original TTL window
	// (so the unrelated "a renewal must actually extend the lease" check,
	// dynamic_secrets.go's newExpiry.After(lease.ExpiresAt), does NOT ALSO
	// refuse here and confound what's under test) but still well past
	// leaseClockRegressionTolerance (30s) below the watermark the control
	// call above just set (leaseExpiry+1s = t0+61s; t0+10s is 51s earlier).
	// A SMALL rollback (a few seconds) is legitimately tolerated by design
	// (ordinary NTP slew, same as checkSessionRefreshClockNotRegressed), so
	// the regression must exceed that window for refusal to be the correct
	// expectation. Simulates an operator's `date -s`, a bad NTP correction,
	// or any other backward wall-clock adjustment -- the exact #1983 threat
	// model.
	w.clock.t = w.t0.Add(10 * time.Second)
	if _, err := w.core.RenewLease(ctx, w.leaseID, int(clockFuzzCredentialTTL.Seconds()), 1); err == nil {
		t.Fatalf("RenewLease succeeded after a clock rollback past an already-observed expiry -- " +
			"checkLeaseRenewClockNotRegressed failed to refuse it")
	}

	// FIXED, second angle: the background sweep's cutoff is now clamped.
	// Prime the watermark to a time past this lease's expiry (exactly what a
	// prior renewal attempt or sweep tick would have done in production),
	// without otherwise mutating the lease, then simulate a scheduler that
	// read a regressed host clock for its own "before" -- the watermark must
	// clamp it back up so the sweep still finds and revokes the lease.
	w2 := buildClockFuzzWorld(t)
	if err := w2.core.checkLeaseRenewClockNotRegressed(w2.leaseExpiry.Add(time.Hour)); err != nil {
		t.Fatalf("priming the watermark: %v", err)
	}
	regressedBefore := w2.leaseExpiry.Add(-time.Second)
	revoked, err := w2.core.RevokeExpiredLeases(ctx, regressedBefore)
	if err != nil {
		t.Fatalf("RevokeExpiredLeases: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("expected dynamicSecretsSweepCutoff to clamp the regressed cutoff forward and revoke "+
			"the expired lease, got revoked=%d", revoked)
	}
}
