package securefiles

import "testing"

// This file exists ONLY to give scripts/check-closures.sh --self-test a real,
// stable test in the cli module (its own go.mod) to point a calibration row at,
// so it can prove a ./cli/... row is run inside cli/ and accepted when the test
// passes. It is not, and should never become, a real closure's proving test: it
// asserts nothing about product behaviour. Never delete or rename it without
// updating the matching case in check-closures.sh's --self-test block.

// TestCheckClosuresSelfTestFixture_CLIModulePasses always passes.
func TestCheckClosuresSelfTestFixture_CLIModulePasses(t *testing.T) {
	t.Parallel()
}
