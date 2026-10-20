// config_change_audit_guard_test.go — choke-point guard, in the same family
// as internal/cli/writeguard's raw-file-open sweep and
// account_state_exhaustiveness_guard_test.go's switch-exhaustiveness check:
// statically proves every enumerated admin config-mutation function below
// actually calls the shared writeConfigChangeAuditEvent helper
// (config_change_audit.go) somewhere in its body, by AST inspection of the
// function's own source -- not by convention, and not by running the
// function and hoping a test happens to assert on it.
//
// This is a small, explicit allowlist (not a repo-wide sweep): it enumerates
// the two mutation surfaces this fix closes (notification channels +
// anomaly config), the same shape as writeguard's own reviewed allowlist. A
// future admin-only config mutation elsewhere in the package is NOT
// automatically covered -- add it to guardedConfigMutations below with a
// written reason, the same discipline writeguard's allowlist enforces for its
// own entries.
//
// Verified red-then-green during development: temporarily removing the
// writeConfigChangeAuditEvent call from UpdateNotificationChannel (and,
// separately, from UpdateAnomalyConfig) made
// TestGuardedConfigMutations_CallSharedAuditHelper fail for exactly that
// function, restoring it made the test pass again -- confirming the guard
// actually detects a reverted audit call, not just a hypothetical one.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// configMutationSpec names the file a guarded function lives in and the
// reason it must call writeConfigChangeAuditEvent.
type configMutationSpec struct {
	file   string
	reason string
}

// guardedConfigMutations is the enumerated, reviewed set of admin-only
// (system.write-gated) config-mutation functions that must route through
// writeConfigChangeAuditEvent. See the package doc comment above for why this
// is a small explicit list rather than a full-package AST sweep.
var guardedConfigMutations = map[string]configMutationSpec{
	"CreateNotificationChannel": {
		file: "notification_channels.go",
		reason: "creates a channel that receives anomaly/rotation/breach alerts -- an admin " +
			"pointing delivery at an attacker-controlled endpoint from creation must be on the record",
	},
	"UpdateNotificationChannel": {
		file: "notification_channels.go",
		reason: "the URL/enabled state of an alert-delivery channel is exactly what an admin " +
			"would silently change to intercept or suppress alerts",
	},
	"DeleteNotificationChannel": {
		file:   "notification_channels.go",
		reason: "deleting the channel is the most complete way to silence alert delivery",
	},
	"UpdateAnomalyConfig": {
		file: "anomaly_config.go",
		reason: "disables ML/off-hours anomaly detection deployment-wide; the pre-existing " +
			"ApplyAnomalyConfig audit only covers the off-hours band as applied at scheduler-tick " +
			"time (change-deduped), never the raw admin PUT or the ML enable/disable flag",
	},
}

// TestGuardedConfigMutations_CallSharedAuditHelper is the guard itself: every
// function named in guardedConfigMutations must call writeConfigChangeAuditEvent
// somewhere in its body.
func TestGuardedConfigMutations_CallSharedAuditHelper(t *testing.T) {
	t.Parallel()
	for name, spec := range guardedConfigMutations {
		t.Run(name, func(t *testing.T) {
			if !funcBodyCallsHelper(t, spec.file, name, "writeConfigChangeAuditEvent") {
				t.Errorf("%s (%s) must call writeConfigChangeAuditEvent -- %s", name, spec.file, spec.reason)
			}
		})
	}
}

// TestGuardedConfigMutations_EntriesStillExist is the flip side (mirroring
// writeguard's TestAllowlistEntriesStillExist): an entry naming a function
// that no longer exists in the stated file (renamed, deleted, or moved) would
// silently stop being checked. A stale entry doesn't fail the guard above (it
// only checks found functions), so it's checked here explicitly.
func TestGuardedConfigMutations_EntriesStillExist(t *testing.T) {
	t.Parallel()
	for name, spec := range guardedConfigMutations {
		t.Run(name, func(t *testing.T) {
			if !funcExists(t, spec.file, name) {
				t.Errorf("guardedConfigMutations entry %q claims to live in %s but no such function was found there "+
					"-- update or remove this entry", name, spec.file)
			}
		})
	}
}

// TestGuardedConfigMutations_ReasonsAreNonEmpty guards against an entry added
// with an empty/placeholder justification -- same discipline as writeguard's
// TestAllowlistJustificationsAreNonEmpty.
func TestGuardedConfigMutations_ReasonsAreNonEmpty(t *testing.T) {
	t.Parallel()
	for name, spec := range guardedConfigMutations {
		if spec.reason == "" {
			t.Errorf("guardedConfigMutations entry %q has no written justification", name)
		}
	}
}

// TestFuncBodyCallsHelper_SelfCheck proves the AST scanner itself actually
// distinguishes "calls the helper" from "doesn't call the helper" -- a guard
// that has never been observed to fail on a genuinely bad input is not a
// guard. GetAnomalyConfig is a read-only accessor in the same file as
// UpdateAnomalyConfig and must NOT be detected as calling
// writeConfigChangeAuditEvent; UpdateAnomalyConfig (checked above) must.
func TestFuncBodyCallsHelper_SelfCheck(t *testing.T) {
	t.Parallel()
	if funcBodyCallsHelper(t, "anomaly_config.go", "GetAnomalyConfig", "writeConfigChangeAuditEvent") {
		t.Fatal("GetAnomalyConfig is a read-only accessor and must not be detected as calling " +
			"writeConfigChangeAuditEvent -- the scanner is vacuously true")
	}
	if !funcBodyCallsHelper(t, "anomaly_config.go", "UpdateAnomalyConfig", "writeConfigChangeAuditEvent") {
		t.Fatal("UpdateAnomalyConfig must be detected as calling writeConfigChangeAuditEvent -- " +
			"the scanner failed to find a call site known to exist")
	}
}

// funcExists reports whether a top-level function named funcName is declared
// in file.
func funcExists(t *testing.T, file, funcName string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../"+file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
			return true
		}
	}
	return false
}

// funcBodyCallsHelper parses file, locates funcName's declaration, and
// reports whether any call expression in its body invokes helperName --
// either as a bare identifier (helperName(...)) or as a method/selector call
// (x.helperName(...), matching c.writeConfigChangeAuditEvent(...)'s shape).
func funcBodyCallsHelper(t *testing.T, file, funcName, helperName string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../"+file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	var fd *ast.FuncDecl
	for _, decl := range f.Decls {
		if cand, ok := decl.(*ast.FuncDecl); ok && cand.Name.Name == funcName {
			fd = cand
			break
		}
	}
	if fd == nil {
		t.Fatalf("function %s not found in %s", funcName, file)
	}
	if fd.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fn.Sel.Name == helperName {
				found = true
				return false
			}
		case *ast.Ident:
			if fn.Name == helperName {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
