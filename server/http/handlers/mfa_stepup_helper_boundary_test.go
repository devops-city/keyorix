// mfa_stepup_helper_boundary_test.go — proves activateMFAForStepUpTest survives a TOTP
// step boundary passing between generating the activation code and submitting it (#3352).
package handlers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stepClock is a fake clock the test can push across a TOTP step boundary.
type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stepClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// forceBoundary returns a fake clock mounted on the core, plus a hook that moves it one
// full 30 s step forward between generate and submit on the first attempt only.
func forceBoundary(t *testing.T) (*stepClock, func(attempt int)) {
	t.Helper()
	// Aligned to a step start so "one step later" is unambiguous.
	clk := &stepClock{t: time.Unix(1_800_000_000/30*30, 0).UTC()}
	return clk, func(attempt int) {
		if attempt == 1 {
			clk.Advance(30 * time.Second)
		}
	}
}

// TestActivateMFAForStepUpTest_SingleAttemptFailsAcrossBoundary documents the flake: with
// a boundary between generate and submit, one attempt (the pre-#3352 helper) is rejected.
func TestActivateMFAForStepUpTest_SingleAttemptFailsAcrossBoundary(t *testing.T) {
	_, coreService, _ := setupMFAStepUpTest(t)
	clk, hook := forceBoundary(t)
	coreService.SetClockForTesting(clk.Now)

	_, _, err := activateMFAWithRetry(context.Background(), coreService, clk.Now, hook, 1)
	require.EqualError(t, err, "invalid code")
}

// TestActivateMFAForStepUpTest_RecoversAcrossBoundary is the #3352 proof: the same forced
// boundary no longer fails the helper, which retries on a fresh step.
func TestActivateMFAForStepUpTest_RecoversAcrossBoundary(t *testing.T) {
	_, coreService, _ := setupMFAStepUpTest(t)
	clk, hook := forceBoundary(t)
	coreService.SetClockForTesting(clk.Now)

	secret, codes, err := activateMFAWithRetry(context.Background(), coreService, clk.Now, hook, stepUpActivateAttempts)
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.NotEmpty(t, codes)
}
