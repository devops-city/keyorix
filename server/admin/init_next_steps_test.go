package admin

// init_next_steps_test.go: FIRST-RUN-1. The "next steps" `admin init` prints are the only
// instructions a first-time user is sure to read, so they must list the commands in an order
// that works (keys, then schema, then validate) and must not leave out the recovery key.

import (
	"strings"
	"testing"
)

func TestPrintInitNextSteps_OrderAndRecoveryKey(t *testing.T) {
	out, err := captureStdout(t, func() error { printInitNextSteps(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var last int
	for _, cmd := range []string{
		"admin encryption init",
		"admin migrate",
		"admin validate --posture",
		"admin recovery-key rotate",
	} {
		i := strings.Index(out, cmd)
		if i < 0 {
			t.Fatalf("next steps do not mention %q:\n%s", cmd, out)
		}
		if i < last {
			t.Fatalf("%q is listed out of order:\n%s", cmd, out)
		}
		last = i
	}
}
