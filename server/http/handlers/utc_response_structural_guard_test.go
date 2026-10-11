// utc_response_structural_guard_test.go — the structural half of the API's
// "timestamps are UTC" claim (docs/API_REFERENCE.md, "Timestamps"). The runtime
// half is server/faultops TestUTCResponseGuard, which drives every GET route in a
// seeded world under a non-UTC process zone. That catches what the seed
// populates; these tests catch what it cannot, from the code alone:
//
//  1. Every JSON response this package writes goes through encodeJSONResponse
//     (which runs utcTimes). No other json.NewEncoder / json.Marshal /
//     json.MarshalIndent call exists in non-test code here, so a new handler
//     with its own writer fails here, not in production.
//  2. utcTimes can only fix what it can see. It leaves a json.Marshaler alone
//     (its wire format is its own) unless the type is in utcTimesWalkMarshalers,
//     and it cannot rewrite an unexported embedded struct (encoding/json
//     promotes its fields; reflection cannot set them). So for every value that
//     reaches a response writer, the static type is walked and:
//     - every json.Marshaler met (other than time.Time) must be listed in
//     reviewedResponseMarshalers, and a "walk" entry must be in
//     utcTimesWalkMarshalers (and vice versa);
//     - no struct may embed an unexported struct type that can hold a time.
//     Additionally every MarshalJSON method declared anywhere in this module
//     must be reviewed, reachable or not (a module type can reach a response
//     through an interface{} value the static walk cannot see).
//  3. JSON writers outside this package (server/middleware, server/http's
//     router) are error envelopes only: listed in nonHandlerJSONWriters, and
//     nothing they encode has a static type that can hold a time.
//
// What these do NOT see: a value stored in an interface{} (map[string]any,
// SuccessResponse.Data) is opaque to the static walk; the runtime guard covers
// those for the routes it drives. A time rendered to a string before it
// reaches the writer (fmt/Format) is a string to both halves except the
// runtime guard's RFC 3339 scan.
package handlers

import (
	"go/ast"
	"go/types"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const modulePath = "github.com/keyorixhq/keyorix"

// reviewedResponseMarshalers is every json.Marshaler type a response can reach
// (statically) or that this module declares, with how its JSON relates to time.
// "walk": utcTimes converts its exported time fields (must be in
// utcTimesWalkMarshalers). "no-time": its JSON carries no time.Time of its own.
var reviewedResponseMarshalers = map[string]struct{ policy, why string }{
	"gorm.io/gorm.DeletedAt":                                            {"walk", "MarshalJSON emits its Time field when Valid; utcTimes converts that field"},
	"github.com/keyorixhq/keyorix/internal/storage/models.JSON":         {"no-time", "raw stored JSON bytes passed through verbatim (metadata blobs); not a time value"},
	"encoding/json.RawMessage":                                          {"no-time", "raw JSON passed through verbatim; in responses this is the stored, hash-covered audit diff (ADR-029), never rewritten"},
	"github.com/go-webauthn/webauthn/protocol.AuthenticationExtensions": {"no-time", "WebAuthn client extension map (credProps etc.) in a registration/login challenge; no time values"},
	"github.com/go-webauthn/webauthn/protocol.URLEncodedBase64":         {"no-time", "bytes rendered as base64url (challenge, credential ids)"},
	"math/big.Int": {"no-time", "an integer rendered as a JSON number"},
}

func loadTyped(t *testing.T, patterns ...string) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedImports | packages.NeedDeps,
		Dir:  ".",
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("packages %v failed to type-check", patterns)
	}
	return pkgs
}

func enclosingFuncName(file *ast.File, pos ast.Node) string {
	name := ""
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Pos() <= pos.Pos() && pos.End() <= fd.End() {
			name = fd.Name.Name
		}
	}
	return name
}

// 1. One writer.
func TestUTCStructural_EveryResponseEncoderIsEncodeJSONResponse(t *testing.T) {
	pkg := loadTyped(t, ".")[0]
	found := 0
	var violations []string
	for _, file := range pkg.Syntax {
		fname := pkg.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			obj := pkg.TypesInfo.Uses[sel.Sel]
			if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "encoding/json" {
				return true
			}
			switch obj.Name() {
			case "NewEncoder", "Marshal", "MarshalIndent":
			default:
				return true
			}
			if fn := enclosingFuncName(file, call); fn == "encodeJSONResponse" {
				found++
				return true
			}
			violations = append(violations, pkg.Fset.Position(call.Pos()).String()+": json."+obj.Name()+" outside encodeJSONResponse (route the response through encodeJSONResponse so utcTimes runs)")
			return true
		})
	}
	if found != 1 {
		t.Errorf("expected exactly one json.NewEncoder inside encodeJSONResponse, found %d: the guard is no longer looking at the real writer", found)
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
}

// responseWriterFuncs are the calls whose arguments become a response body.
var responseWriterFuncs = map[string]bool{
	"sendSuccess": true, "sendCreated": true, "sendError": true, "encodeJSONResponse": true,
}

// typeWalker walks a static type the way encoding/json would see it.
type typeWalker struct {
	marshaler  *types.Interface
	timeType   types.Type
	seen       map[types.Type]bool
	marshalers map[string]string // full name -> first place seen
	embedded   map[string]string // "Outer embeds inner" -> place
}

func newTypeWalker(t *testing.T, pkg *packages.Package) *typeWalker {
	t.Helper()
	jsonPkg := pkg.Imports["encoding/json"]
	timePkg := pkg.Imports["time"]
	if jsonPkg == nil || timePkg == nil {
		t.Fatal("handlers no longer imports encoding/json and time: guard setup is stale")
	}
	m := jsonPkg.Types.Scope().Lookup("Marshaler").Type().Underlying().(*types.Interface)
	return &typeWalker{
		marshaler: m, timeType: timePkg.Types.Scope().Lookup("Time").Type(),
		seen: map[types.Type]bool{}, marshalers: map[string]string{}, embedded: map[string]string{},
	}
}

func fullName(n *types.Named) string {
	o := n.Obj()
	if o.Pkg() == nil {
		return o.Name()
	}
	return o.Pkg().Path() + "." + o.Name()
}

func (w *typeWalker) implementsMarshaler(t types.Type) bool {
	return types.Implements(t, w.marshaler) || types.Implements(types.NewPointer(t), w.marshaler)
}

// canHoldTime mirrors response_time_utc.go's canHoldTime on static types.
func (w *typeWalker) canHoldTime(t types.Type, depth int) bool {
	if depth > utcTimesMaxDepth {
		return true
	}
	if types.Identical(t, w.timeType) {
		return true
	}
	switch u := t.Underlying().(type) {
	case *types.Interface:
		return true
	case *types.Pointer:
		return w.canHoldTime(u.Elem(), depth+1)
	case *types.Slice:
		return w.canHoldTime(u.Elem(), depth+1)
	case *types.Array:
		return w.canHoldTime(u.Elem(), depth+1)
	case *types.Map:
		return w.canHoldTime(u.Elem(), depth+1)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			f := u.Field(i)
			if (f.Exported() || f.Embedded()) && w.canHoldTime(f.Type(), depth+1) {
				return true
			}
		}
	}
	return false
}

func (w *typeWalker) walk(t types.Type, where string) {
	if w.seen[t] {
		return
	}
	w.seen[t] = true
	if n, ok := t.(*types.Named); ok {
		if types.Identical(t, w.timeType) {
			return
		}
		if w.implementsMarshaler(t) {
			name := fullName(n)
			if _, ok := w.marshalers[name]; !ok {
				w.marshalers[name] = where
			}
			if r, ok := reviewedResponseMarshalers[name]; ok && r.policy == "no-time" {
				return
			}
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		w.walk(u.Elem(), where)
	case *types.Slice:
		w.walk(u.Elem(), where)
	case *types.Array:
		w.walk(u.Elem(), where)
	case *types.Map:
		w.walk(u.Elem(), where)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			f := u.Field(i)
			if f.Embedded() && !f.Exported() && w.canHoldTime(f.Type(), 0) {
				outer := t.String()
				w.embedded[outer+" embeds unexported "+f.Type().String()] = where
			}
			if f.Exported() || f.Embedded() {
				w.walk(f.Type(), where)
			}
		}
	}
}

// 2. Marshalers and unexported embeds reachable from a response writer.
func TestUTCStructural_ResponseTypesAreSeenByUTCTimes(t *testing.T) {
	pkg := loadTyped(t, ".")[0]
	w := newTypeWalker(t, pkg)
	calls := 0
	for _, file := range pkg.Syntax {
		if strings.HasSuffix(pkg.Fset.Position(file.Pos()).Filename, "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if !responseWriterFuncs[name] {
				return true
			}
			calls++
			where := pkg.Fset.Position(call.Pos()).String()
			for _, arg := range call.Args {
				ast.Inspect(arg, func(sub ast.Node) bool {
					if e, ok := sub.(ast.Expr); ok {
						if tv := pkg.TypesInfo.TypeOf(e); tv != nil {
							w.walk(tv, where)
						}
					}
					return true
				})
			}
			return true
		})
	}
	if calls < 500 {
		t.Fatalf("found only %d response-writer calls; the call-name set is stale and this guard would pass vacuously", calls)
	}

	// Every MarshalJSON declared in this module, reachable or not.
	moduleMarshalers := map[string]string{}
	packages.Visit([]*packages.Package{pkg}, nil, func(p *packages.Package) {
		if p.Types == nil || !strings.HasPrefix(p.PkgPath, modulePath+"/") {
			return
		}
		scope := p.Types.Scope()
		for _, nm := range scope.Names() {
			tn, ok := scope.Lookup(nm).(*types.TypeName)
			if !ok {
				continue
			}
			if _, isIface := tn.Type().Underlying().(*types.Interface); isIface {
				continue
			}
			if w.implementsMarshaler(tn.Type()) {
				if n, ok := tn.Type().(*types.Named); ok {
					moduleMarshalers[fullName(n)] = p.PkgPath
				}
			}
		}
	})

	var errs []string
	for name, where := range w.marshalers {
		if _, ok := reviewedResponseMarshalers[name]; !ok {
			errs = append(errs, "json.Marshaler "+name+" reaches a response ("+where+") and is not in reviewedResponseMarshalers: utcTimes leaves it alone, so review whether its JSON can carry a local time (add a \"walk\" entry + utcTimesWalkMarshalers, or \"no-time\" with the reason)")
		}
	}
	for name, p := range moduleMarshalers {
		if _, ok := reviewedResponseMarshalers[name]; !ok {
			errs = append(errs, "module type "+name+" ("+p+") implements json.Marshaler and is not in reviewedResponseMarshalers")
		}
	}
	for desc, where := range w.embedded {
		errs = append(errs, desc+" (reached at "+where+"): utcTimes cannot rewrite an unexported embedded struct; export the embedded type")
	}

	walkByName := map[string]bool{}
	for rt, on := range utcTimesWalkMarshalers {
		if on {
			walkByName[reflectFullName(rt)] = true
		}
	}
	for name, r := range reviewedResponseMarshalers {
		if (r.policy == "walk") != walkByName[name] {
			errs = append(errs, "reviewedResponseMarshalers["+name+"] policy "+r.policy+" disagrees with utcTimesWalkMarshalers")
		}
		if r.policy != "walk" && r.policy != "no-time" {
			errs = append(errs, "reviewedResponseMarshalers["+name+"] has unknown policy "+r.policy)
		}
	}
	for name := range walkByName {
		if _, ok := reviewedResponseMarshalers[name]; !ok {
			errs = append(errs, "utcTimesWalkMarshalers has "+name+", which is not reviewed")
		}
	}
	if len(w.marshalers) == 0 {
		errs = append(errs, "the walk met no json.Marshaler at all; it is not reaching response types")
	}
	sort.Strings(errs)
	for _, e := range errs {
		t.Error(e)
	}
	t.Logf("checked %d response-writer calls; marshalers reached: %v", calls, keysOf(w.marshalers))
}

func reflectFullName(t reflect.Type) string { return t.PkgPath() + "." + t.Name() }

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nonHandlerJSONWriters are the JSON response writers outside this package, by
// "package-relative file:function". Each writes a fixed error envelope.
var nonHandlerJSONWriters = map[string]string{
	"server/http/router.go:writeJSONNotFound":              "404 envelope: error/message/code literals",
	"server/middleware/auth.go:EnforceAccountRestriction":  "403 PasswordChangeRequired envelope",
	"server/middleware/auth.go:handleMFAEnrollmentCheck":   "403 MFAEnrollmentRequired envelope",
	"server/middleware/auth.go:unauthorizedResponse":       "401 envelope",
	"server/middleware/auth.go:tooManyRequestsResponse":    "429 envelope",
	"server/middleware/auth.go:serviceUnavailableResponse": "503 envelope",
	"server/middleware/auth.go:forbiddenResponse":          "403 envelope",
	"server/middleware/auth.go:projectMFARequiredResponse": "403 ProjectMFARequired envelope",
	"server/middleware/auth.go:notFoundResponse":           "404 envelope",
	"server/middleware/auth.go:badRequestResponse":         "400 envelope",
	"server/middleware/rate_limit.go:middleware":           "429 envelope",
	"server/middleware/scim.go:scimError":                  "SCIM error envelope",
	"server/middleware/recovery.go:Recovery":               "500 envelope after a recovered panic",
}

// 3. JSON writers outside this package: error envelopes only, no time-typed values.
func TestUTCStructural_NonHandlerJSONWritersAreTimeFree(t *testing.T) {
	pkgs := loadTyped(t, "../../middleware", "..")
	seen := map[string]bool{}
	var errs []string
	for _, pkg := range pkgs {
		w := newTypeWalkerFor(t, pkg)
		for _, file := range pkg.Syntax {
			fname := pkg.Fset.Position(file.Pos()).Filename
			if strings.HasSuffix(fname, "_test.go") {
				continue
			}
			rel := fname[strings.Index(fname, "/server/")+1:]
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				obj := pkg.TypesInfo.Uses[sel.Sel]
				if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "encoding/json" || (obj.Name() != "NewEncoder" && obj.Name() != "Marshal" && obj.Name() != "MarshalIndent") {
					return true
				}
				key := rel + ":" + enclosingFuncName(file, call)
				seen[key] = true
				if _, ok := nonHandlerJSONWriters[key]; !ok {
					errs = append(errs, pkg.Fset.Position(call.Pos()).String()+": JSON writer "+key+" is not in nonHandlerJSONWriters (route a data response through server/http/handlers, or list an error envelope here)")
				}
				return true
			})
			// The values those writers encode: no sub-expression may have a
			// static type that can hold a time (interface{} values are opaque).
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Encode" {
					return true
				}
				for _, arg := range call.Args {
					ast.Inspect(arg, func(sub ast.Node) bool {
						e, ok := sub.(ast.Expr)
						if !ok {
							return true
						}
						tv := pkg.TypesInfo.TypeOf(e)
						if tv == nil {
							return true
						}
						if _, isIface := tv.Underlying().(*types.Interface); isIface {
							return true
						}
						if w.canHoldTime(tv, 0) && !isAnyMap(tv) {
							errs = append(errs, pkg.Fset.Position(e.Pos()).String()+": error envelope encodes a value of type "+tv.String()+" that can hold a time")
						}
						return true
					})
				}
				return true
			})
		}
	}
	for key := range nonHandlerJSONWriters {
		if !seen[key] {
			errs = append(errs, "nonHandlerJSONWriters has "+key+", which no longer writes JSON: remove it")
		}
	}
	sort.Strings(errs)
	for _, e := range errs {
		t.Error(e)
	}
}

func newTypeWalkerFor(t *testing.T, pkg *packages.Package) *typeWalker {
	t.Helper()
	var timeT types.Type
	packages.Visit([]*packages.Package{pkg}, nil, func(p *packages.Package) {
		if p.PkgPath == "time" && p.Types != nil {
			timeT = p.Types.Scope().Lookup("Time").Type()
		}
	})
	if timeT == nil {
		t.Fatalf("%s does not import time; cannot type the walk", pkg.PkgPath)
	}
	return &typeWalker{timeType: timeT, seen: map[types.Type]bool{}}
}

// isAnyMap reports a map[string]interface{} literal: its values are checked one
// by one as sub-expressions, so the map type itself is not a finding.
func isAnyMap(t types.Type) bool {
	m, ok := t.Underlying().(*types.Map)
	if !ok {
		return false
	}
	_, iface := m.Elem().Underlying().(*types.Interface)
	return iface
}
