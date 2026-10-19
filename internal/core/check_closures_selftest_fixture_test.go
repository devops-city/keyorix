package core

import (
	"os"
	"testing"
)

// This file exists ONLY to give scripts/check-closures.sh --self-test real,
// stable test names to point calibration ledger rows at, so it can prove its
// pg-gated verification logic actually rejects a bad row and accepts a good
// one — not just the pre-existing "test does not exist" case. None of these
// are, or should ever become, a real closure's proving test: they assert
// nothing about product behavior, only about their own skip/pass shape.
// Never delete or rename one without updating the matching case in
// check-closures.sh's --self-test block.

// TestCheckClosuresSelfTestFixture_AlwaysSkip always skips, unconditionally.
// Used to prove: (1) a default-ci row naming a test that skips is rejected,
// and (2) a pg-gated row is ALSO rejected once KEYORIX_TEST_PG_DSN is set —
// "gated" stops being an excuse the moment the gate condition the row itself
// claims is actually met.
func TestCheckClosuresSelfTestFixture_AlwaysSkip(t *testing.T) {
	t.Parallel()
	t.Skip("check-closures.sh self-test fixture -- this test is SUPPOSED to skip")
}

// TestCheckClosuresSelfTestFixture_SkipsWithoutPGDSN mirrors the real
// pg-gated tests' own gate (KEYORIX_TEST_PG_DSN presence, see
// postgres_contention_helpers_test.go's pgTestDSN) without actually opening a
// connection, so the self-test stays hermetic and fast in every environment.
// Used to prove a pg-gated row honestly declaring its gate is NOT rejected
// when the DSN genuinely isn't available in this environment — the one
// behavior this whole ledger change exists to add.
func TestCheckClosuresSelfTestFixture_SkipsWithoutPGDSN(t *testing.T) {
	t.Parallel()
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		t.Skip("check-closures.sh self-test fixture -- SUPPOSED to skip without a DSN")
	}
}

// TestCheckClosuresSelfTestFixture_AlwaysPasses always passes. Paired with
// _FailsWhenAsked in one package to prove a failing package still reports each
// OTHER row's own verdict (a per-row `ok` line), not one blanket package failure.
func TestCheckClosuresSelfTestFixture_AlwaysPasses(t *testing.T) {
	t.Parallel()
}

// TestCheckClosuresSelfTestFixture_FailsWhenAsked fails only when the self-test
// sets CHECK_CLOSURES_SELFTEST_FAIL=1 for its sub-invocation, and skips otherwise,
// so a plain `go test ./internal/core` is unaffected. It makes the package's
// `go test` exit non-zero while _AlwaysPasses still passes.
func TestCheckClosuresSelfTestFixture_FailsWhenAsked(t *testing.T) {
	t.Parallel()
	if os.Getenv("CHECK_CLOSURES_SELFTEST_FAIL") != "1" {
		t.Skip("check-closures.sh self-test fixture -- fails only when CHECK_CLOSURES_SELFTEST_FAIL=1")
	}
	t.Fatal("check-closures.sh self-test fixture -- this test is SUPPOSED to fail")
}
