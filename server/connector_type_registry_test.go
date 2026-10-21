// connector_type_registry_test.go — regression test for #1476's structural
// concern: initializeCoreService's Connect-wiring switch (main.go, "switch
// cn.Type") dispatches on literal case labels rather than deriving from
// connect.KnownTypes (each case needs a different constructor call, some with
// type-specific side effects that don't reduce to a uniform map[string]func
// lookup — see connect.KnownTypes' own doc comment). Nothing stops that switch's
// case set from silently drifting away from connect.KnownTypes, the list
// internal/config.Validate()'s validateConnectTypes checks a configured
// connector's Type against — a case added to one without the other would
// either make a Validate()-accepted type fall through to the switch's Fatal
// default (a boot-time crash for a config that was supposed to be legal), or
// make the switch accept a type Validate() should have already rejected (dead
// code, but a sign the two have drifted).
//
// Rather than hand-maintain a second literal copy of the case-label set here
// (exactly the duplication this test exists to prevent), this parses
// server/main.go's own source via go/ast and extracts the actual case string
// literals from the switch inside initializeCoreService, then diffs that
// discovered set against connect.KnownTypes.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/connect"
)

// TestConnectorTypeRegistry_SwitchMatchesKnownTypes is the regression test
// described above.
func TestConnectorTypeRegistry_SwitchMatchesKnownTypes(t *testing.T) {
	// The switch lives in wireConnect (wire_connect.go); every non-test file of
	// the package is searched so moving it again cannot make this pass vacuously.
	_, files := parseServerPackage(t)
	discovered := map[string]bool{}
	for _, file := range files {
		maps.Copy(discovered, discoverConnectorTypeSwitchCases(t, file))
	}
	if len(discovered) == 0 {
		t.Fatal("discovered zero case labels on the Connect-wiring switch in package main (server/*.go) — " +
			"the AST walk is almost certainly broken (the switch has 4 cases today), not that the switch was removed")
	}

	known := map[string]bool{}
	for _, typ := range connect.KnownTypes {
		known[typ] = true
	}

	var missingFromRegistry, missingFromSwitch []string
	for c := range discovered {
		if !known[c] {
			missingFromRegistry = append(missingFromRegistry, c)
		}
	}
	for _, k := range connect.KnownTypes {
		if !discovered[k] {
			missingFromSwitch = append(missingFromSwitch, k)
		}
	}
	sort.Strings(missingFromRegistry)
	sort.Strings(missingFromSwitch)

	if len(missingFromRegistry) > 0 {
		t.Errorf("server's Connect-wiring switch (wireConnect) has case(s) not present in connect.KnownTypes: %v\n"+
			"internal/config.Validate() would reject a connector with this Type before boot reaches the switch, "+
			"making the case dead code — add the type to connect.KnownTypes if it's genuinely supported.", missingFromRegistry)
	}
	if len(missingFromSwitch) > 0 {
		t.Errorf("connect.KnownTypes lists type(s) with no matching case in server's Connect-wiring switch (wireConnect): %v\n"+
			"A connector with this Type would pass cfg.Validate() but then hit the switch's Fatal default at boot — "+
			"add a case for it (with the right constructor call), or remove it from connect.KnownTypes.", missingFromSwitch)
	}
}

// TestInitializeCoreService_UnrecognizedConnectorType_FailsBoot is #1476's
// pairing test: before #1475 (cfg.Validate() at the top of
// initializeCoreService) landed, this config booted successfully — nothing
// called Validate() at all. Before THIS commit's validateConnectTypes existed,
// Validate() would run (once #1475 landed) but never inspect connector Type,
// so this would still boot successfully. Both preconditions are required for
// this test to fail as intended — that pairing is the point.
func TestInitializeCoreService_UnrecognizedConnectorType_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "typo-connector", Type: "aws-secrets-mangler", Scope: "platform"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with an unrecognized connector type")
	}
	if !strings.Contains(err.Error(), "typo-connector") {
		t.Fatalf("expected error to name the offending connector, got: %v", err)
	}
}

// TestInitializeCoreService_UnrecognizedConnectorType_AggregatesMultiple
// confirms the boot-time error names every offending connector in one message,
// not just the first, and excludes a validly-typed connector from that list —
// mirroring validateConnectScopes's own aggregation behavior (ADR-082).
func TestInitializeCoreService_UnrecognizedConnectorType_AggregatesMultiple(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "bad1", Type: "bogus-type-1", Scope: "platform"},
			{Name: "bad2", Type: "bogus-type-2", Scope: "platform"},
			{Name: "ok", Type: "vault", Scope: "platform"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot")
	}
	for _, want := range []string{"bad1", "bad2"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to name %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), `"ok"`) {
		t.Fatalf("validly-typed connector must not appear in the error, got: %v", err)
	}
}

// discoverConnectorTypeSwitchCases walks file looking for a *ast.SwitchStmt whose
// tag is exactly `cn.Type` (matching server/main.go's Connect-wiring switch,
// `switch cn.Type { ... }`), and returns the set of string literal values across
// all of its non-default case clauses.
func discoverConnectorTypeSwitchCases(t *testing.T, file *ast.File) map[string]bool {
	t.Helper()
	discovered := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil {
			return true
		}
		sel, ok := sw.Tag.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Type" {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "cn" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range cc.List { // nil List = the `default:` clause, skipped
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				discovered[val] = true
			}
		}
		return true
	})
	return discovered
}

// TestConnectorTypeRegistryScannerDetectsSwitchCases is this guard's
// red-proof.
//
// TestConnectorTypeRegistry_SwitchMatchesKnownTypes asserts today's switch
// matches connect.KnownTypes. That is a claim about main.go, not about the
// walk. discoverConnectorTypeSwitchCases's own zero-case Fatal only catches a
// TOTAL collapse (the switch vanishing, or the cn.Type tag match breaking
// outright). A narrower break — the string-literal extraction losing one
// case, or the tag/selector match becoming too permissive and picking up an
// unrelated switch on a same-named field — would neither hit zero nor look
// wrong. It would silently under- or over-report, and the parity test above
// would compare connect.KnownTypes against whatever partial set survived.
func TestConnectorTypeRegistryScannerDetectsSwitchCases(t *testing.T) {
	// Parsed, never compiled: undefined identifiers (Connector, connectVault,
	// log, etc.) are fine and deliberate — this fixture must not be
	// buildable, or someone will eventually "fix" it into a real file.
	const src = `package fixture

func wireConnector(cn *Connector) {
	switch cn.Type {
	case "vault":
		connectVault(cn)
	case "aws-secrets-manager":
		connectAWS(cn)
	default:
		log.Fatalf("unknown type")
	}
}

// wireOther's switch shares the selector name "Type" but not the "cn"
// receiver — it must contribute nothing, or the walk is matching on the
// selector name alone rather than the specific cn.Type shape it documents.
func wireOther(other *Other) {
	switch other.Type {
	case "should-not-appear":
		doOther()
	}
}

// wireStatus shares the "cn" receiver but switches on a different field —
// mirrors server/main.go's real second switch, "b.Type" at a DIFFERENT
// receiver, but tests the field-name half of the same selectivity
// requirement from the "cn" side: this must contribute nothing either, or
// the walk is matching on the receiver name alone.
func wireStatus(cn *Connector) {
	switch cn.Status {
	case "should-not-appear-2":
		doStatus()
	}
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "connector_fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the synthetic fixture: %v", err)
	}

	discovered := discoverConnectorTypeSwitchCases(t, file)

	for _, want := range []string{"vault", "aws-secrets-manager"} {
		if !discovered[want] {
			t.Errorf("discoverConnectorTypeSwitchCases must find case %q on the cn.Type switch; got %v\n"+
				"If this stops firing, TestConnectorTypeRegistry_SwitchMatchesKnownTypes compares "+
				"connect.KnownTypes against an incomplete set and can silently miss a real drift.", want, discovered)
		}
	}
	if len(discovered) != 2 {
		t.Errorf("expected exactly 2 discovered cases (the default clause must not contribute), got %d: %v",
			len(discovered), discovered)
	}

	// The other half of the proof: a switch that shares only the field name
	// ("other.Type") or only the receiver name ("cn.Status") must not leak
	// into the result, or the scanner over-reports and every future
	// genuinely-missing case gets masked by noise from unrelated switches.
	// server/main.go has exactly this shape for real — a second switch on
	// "b.Type" a few hundred lines below the Connect-wiring one.
	if discovered["should-not-appear"] {
		t.Errorf("discoverConnectorTypeSwitchCases picked up a case from an unrelated other.Type switch — "+
			"it is no longer scoped to the specific cn.Type shape it documents, got %v", discovered)
	}
	if discovered["should-not-appear-2"] {
		t.Errorf("discoverConnectorTypeSwitchCases picked up a case from cn.Status (same receiver, different "+
			"field) — it is matching on the receiver name alone rather than the specific cn.Type shape, got %v",
			discovered)
	}
}
