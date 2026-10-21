package main

import (
	"go/ast"
	"strconv"
	"testing"
)

// TestAnomalyScheduler_FirstPassIsDeferred is the structural guard for the
// C-PERF-FIXES anomaly startup fix: startSchedulers must start "anomaly_detection"
// through runSchedulerAfter with a delay computed by anomalyFirstPassDelay, never
// through runScheduler (which runs the first full pass the instant the process
// starts). It walks every call in the package's non-test files (the job lives in
// its own scheduler_anomaly_detection.go), so it also fails if the job is renamed
// away or registered twice.
func TestAnomalyScheduler_FirstPassIsDeferred(t *testing.T) {
	fset, files := parseServerPackage(t)
	var found int
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || (fn.Name != "runScheduler" && fn.Name != "runSchedulerAfter") {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok {
				return true
			}
			if name, _ := strconv.Unquote(lit.Value); name != "anomaly_detection" {
				return true
			}
			found++
			if fn.Name != "runSchedulerAfter" {
				t.Errorf("%s: anomaly_detection is started with %s, which runs the first sweep at process start; use runSchedulerAfter with anomalyFirstPassDelay", fset.Position(call.Pos()), fn.Name)
				return true
			}
			delay, ok := call.Args[3].(*ast.Ident)
			if !ok || delay.Name != "firstDelay" {
				t.Errorf("%s: anomaly_detection's first delay must be the firstDelay computed by anomalyFirstPassDelay", fset.Position(call.Pos()))
			}
			return true
		})
	}
	if found != 1 {
		t.Fatalf("expected exactly one anomaly_detection scheduler in package main (server/*.go), found %d", found)
	}
}
