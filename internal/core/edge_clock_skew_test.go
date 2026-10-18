package core

// edge_clock_skew_test.go -- EDGE-1 "no NTP" review: what a clock that is wrong,
// or that gets corrected, does to the time-dependent decisions an unattended
// device makes, driven off the injected clock (KeyorixCore.now).
//
// This file pins OBSERVED, documented behaviour so that docs/edge-deployment.md
// ("No NTP: what a bad clock does") stays true and so nobody changes it by
// accident. Several results are limits an operator must know about rather than
// properties anyone wants; each such test says so in its name. The deeper
// session/PAT/lease clock-jump properties (an expired credential never
// re-authorizes after a step backward, timezone independence) are FUZZED in
// clock_fuzz_test.go; the cases here are the deterministic, operator-facing
// ones. Not covered here: audit timestamps (written from the real clock, see
// internal/auditverify/edge_clock_audit_test.go), and TLS certificate windows
// (internal/clockcheck, server/clock_warnings_test.go).

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// edgeClock is a settable clock.
type edgeClock struct{ t time.Time }

func (c *edgeClock) now() time.Time { return c.t }

// edgeMFAWorld: alice with TOTP enrolled and activated at t0, on a settable
// clock. Returns the secret, a recovery code, and the clock.
func edgeMFAWorld(t *testing.T) (c *KeyorixCore, secret, recovery string, clk *edgeClock, t0 time.Time) {
	t.Helper()
	core, _, fixed := newMFATestCore(t)
	clk = &edgeClock{t: fixed}
	core.now = clk.now
	ctx := context.Background()
	_, secret, err := core.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	act, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	codes, err := core.ActivateMFA(ctx, 1, act, mfaTestPassword, "")
	require.NoError(t, err)
	require.NotEmpty(t, codes)
	return core, secret, codes[0], clk, fixed
}

// edgeRestart is a server restart: the same database, new process state (every
// in-memory clock watermark is gone), the same clock.
func edgeRestart(c *KeyorixCore, clk *edgeClock) *KeyorixCore {
	r := &KeyorixCore{storage: store.NewLocalStorage(c.storage.(*store.LocalStorage).DB()), now: clk.now, passwordPolicy: DefaultPasswordPolicy()}
	r.SetAuthEncryptor(c.authEncryptor)
	return r
}

// mfaLogin is one complete second-factor attempt with `code` on the current
// device clock: fresh challenge, then VerifyMFALogin.
func mfaLogin(t *testing.T, c *KeyorixCore, code string) error {
	t.Helper()
	ctx := context.Background()
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, _, err = c.VerifyMFALogin(ctx, ch, code, "ua", "1.2.3.4")
	return err
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	require.NoError(t, err)
	return code
}

// A device clock is only usable for TOTP while it agrees with the
// authenticator to within one 30 s step either way. Outside that, every code
// fails; the operator-visible symptom of an unset or drifting clock.
func TestEdgeClock_TOTPAcceptedOnlyWithinOneStepOfTheDeviceClock(t *testing.T) {
	for _, c := range []struct {
		name   string
		offset time.Duration // authenticator's time minus the device's
		want   bool
	}{
		{"in step", 0, true},
		{"authenticator one step ahead", 30 * time.Second, true},
		{"authenticator one step behind", -30 * time.Second, true},
		{"authenticator two steps ahead", 60 * time.Second, false},
		{"authenticator two steps behind", -60 * time.Second, false},
		{"five minutes off", 5 * time.Minute, false},
		{"an hour off (unset clock, wrong timezone)", time.Hour, false},
		{"epoch device clock", -56 * 365 * 24 * time.Hour, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			core, secret, _, clk, t0 := edgeMFAWorld(t)
			clk.t = t0.Add(10 * time.Minute) // well past the enrolment step
			err := mfaLogin(t, core, codeAt(t, secret, clk.t.Add(c.offset)))
			if c.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Safe direction: a small correction backwards (NTP stepping a drifted clock)
// must not let the code that was just used be used again.
func TestEdgeClock_TOTPReplayRefusedAfterASmallBackwardCorrection(t *testing.T) {
	core, secret, _, clk, t0 := edgeMFAWorld(t)
	clk.t = t0.Add(10 * time.Minute)
	used := codeAt(t, secret, clk.t)
	require.NoError(t, mfaLogin(t, core, used))

	clk.t = clk.t.Add(-20 * time.Second) // corrected backwards, same code still inside the window
	require.Error(t, mfaLogin(t, core, used), "a TOTP code that was accepted must never be accepted twice, whatever the clock does")
}

// A LIMIT, not a goal. Two independent guards leave every second-factor login
// refused after the clock has been stepped BACKWARD by more than 30 s:
//
//   - the single-use-token guard (store.consumeClockLooksRegressed, #1632)
//     refuses to consume ANY login challenge while the clock reads earlier than
//     one this process has already seen -- TOTP and recovery codes alike;
//   - the TOTP replay guard keeps the highest accepted time-step and refuses
//     anything not above it, so a code for the corrected time is refused until
//     the corrected clock passes that step.
//
// Both clear without operator action once real time passes the highest time
// the server has seen; a restart clears the first at once (it is in memory),
// after which a recovery code works but TOTP still waits for the second.
// docs/edge-deployment.md tells operators to restart after stepping a clock
// backward.
func TestEdgeClock_MFARefusedAfterALargeBackwardStepUntilRestartOrCatchUp(t *testing.T) {
	core, secret, recovery, clk, t0 := edgeMFAWorld(t)

	ahead := t0.Add(2 * time.Hour) // the device clock had run ahead, and the authenticator agreed with it
	clk.t = ahead
	require.NoError(t, mfaLogin(t, core, codeAt(t, secret, ahead)))

	clk.t = t0.Add(10 * time.Minute) // corrected backwards by about 1h50
	require.Error(t, mfaLogin(t, core, codeAt(t, secret, clk.t)),
		"EXPECTED LIMIT: a correct code for the corrected clock is refused")
	require.Error(t, mfaLogin(t, core, recovery),
		"EXPECTED LIMIT: even a recovery code is refused while the in-memory clock guard remembers a later time")

	restarted := edgeRestart(core, clk)
	require.Error(t, mfaLogin(t, restarted, codeAt(t, secret, clk.t)),
		"after a restart TOTP is still refused: the stored time-step is above the corrected clock's")
	require.NoError(t, mfaLogin(t, restarted, recovery),
		"after a restart a recovery code logs in: it does not depend on the TOTP step")

	clk.t = ahead.Add(2 * time.Minute) // real time finally passes what was accepted
	require.NoError(t, mfaLogin(t, restarted, codeAt(t, secret, clk.t)),
		"once the clock passes the stored step TOTP works again with no operator action")
}

// The single-use-token guard tolerates a backward step of up to 30 s, so NTP
// slewing a few seconds never shows up. Recovery code, so that the TOTP step
// guard (which has no tolerance) does not mask what is being tested.
func TestEdgeClock_MFAChallengeNotAffectedByASmallBackwardStep(t *testing.T) {
	core, secret, recovery, clk, t0 := edgeMFAWorld(t)
	clk.t = t0.Add(10 * time.Minute)
	require.NoError(t, mfaLogin(t, core, codeAt(t, secret, clk.t)))
	clk.t = clk.t.Add(-5 * time.Second)
	require.NoError(t, mfaLogin(t, core, recovery), "a 5 s backward step must not refuse a login challenge")
}

// A LIMIT. After the clock is stepped backward by more than 30 s, EVERY secret
// value read is refused -- including secrets that never expire -- with the
// ordinary "expired" answer, until the clock passes the latest time the
// process has seen or the service restarts (secret-read guard #1632:
// checkSecretExpiryClockNotRegressed). The guard cannot tell a stepped-back
// clock from an attacker's; it fails closed. The only existing test of this
// path (secret_value_clock_regression_test.go) covers an EXPIRED secret and a
// 5 s step. This pins the consequence an operator meets: a device whose clock
// runs ahead and is then corrected serves no secrets until restarted.
func TestEdgeClock_EverySecretReadRefusedAfterALargeBackwardStepUntilRestartOrCatchUp(t *testing.T) {
	c, db := newClockRegressionCore(t)
	ctx := context.Background()
	never := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	secret := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "edge-clock-target", IsSecret: true, Status: "active", Type: "generic", Expiration: &never}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("v")}).Error)

	clk := &edgeClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	c.now = clk.now
	read := func(c *KeyorixCore) error { _, err := c.GetSecretValueByVersion(ctx, secret.ID, 1); return err }

	clk.t = clk.t.Add(2 * time.Hour) // the clock had run ahead
	require.NoError(t, read(c), "sanity: a never-expiring secret reads fine")

	clk.t = clk.t.Add(-2 * time.Hour) // corrected
	require.Error(t, read(c), "EXPECTED LIMIT: a secret that never expires is refused after a 2 h backward step")

	require.NoError(t, read(edgeRestartSecrets(c, clk)), "a restart clears it at once")

	clk.t = clk.t.Add(2*time.Hour + time.Minute) // or real time passes the latest time seen
	require.NoError(t, read(c), "and it clears by itself once the clock passes what the process has seen")
}

// edgeRestartSecrets: new process state over the same database, for the
// minimal core newClockRegressionCore builds.
func edgeRestartSecrets(c *KeyorixCore, clk *edgeClock) *KeyorixCore {
	return &KeyorixCore{storage: store.NewLocalStorage(c.storage.(*store.LocalStorage).DB()), now: clk.now}
}

// Session, PAT and dynamic-secret lease, minted at t0 with a 60 s lifetime:
// what the clock does to "is it still valid". The authoritative property
// tests are clock_fuzz_test.go; this pins the cases an operator meets.
func TestEdgeClock_CredentialExpiryAcrossJumps(t *testing.T) {
	ctx := context.Background()
	for _, cred := range []struct {
		name string
		sel  int
	}{{"session", 0}, {"PAT", 1}, {"dynamic-secret lease", 2}} {
		t.Run(cred.name, func(t *testing.T) {
			t.Run("forward past expiry: refused", func(t *testing.T) {
				w := buildClockFuzzWorld(t)
				w.clock.t = expiryFor(w, cred.sel).Add(time.Second)
				require.False(t, checkAt(ctx, w, cred.sel))
			})
			t.Run("forward by years (a clock set far ahead): refused", func(t *testing.T) {
				w := buildClockFuzzWorld(t)
				w.clock.t = w.t0.Add(5 * 365 * 24 * time.Hour)
				require.False(t, checkAt(ctx, w, cred.sel))
			})
			t.Run("expiry observed, then the clock steps back before it: still refused", func(t *testing.T) {
				w := buildClockFuzzWorld(t)
				w.clock.t = expiryFor(w, cred.sel).Add(time.Minute)
				require.False(t, checkAt(ctx, w, cred.sel), "premise: expired on the forward clock")
				w.clock.t = w.t0.Add(time.Second) // stepped back to just after issue
				require.False(t, checkAt(ctx, w, cred.sel), "an expiry the server has already seen must not be undone by a backward step")
			})
		})
	}
	// Sessions and PATs only (a lease renewal has other refusal reasons, which
	// is why the fuzzer asserts one direction only for it): stepped back
	// before the server ever saw the expiry, the credential is judged on the
	// device's (wrong) clock and lives as long as the step back. Absolute
	// expiry timestamps cannot tell a stepped-back clock from an early one;
	// ADR-094 Task 3 names this and the mitigation is operational.
	for _, cred := range []struct {
		name string
		sel  int
	}{{"session", 0}, {"PAT", 1}} {
		t.Run(cred.name+": LIMIT stepped back before ever observing expiry: valid on the device clock", func(t *testing.T) {
			w := buildClockFuzzWorld(t)
			w.clock.t = w.t0.Add(-time.Hour)
			require.True(t, checkAt(ctx, w, cred.sel))
		})
	}
}
