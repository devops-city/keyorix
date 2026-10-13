// full_row_write_guard_test.go — structural guard for the "stale full-row write"
// race class (#2648, #2650, #2653, #2654; independent review #2662).
//
// The class: an operation reads a row, checks or edits something in memory, and
// then persists the WHOLE pre-read row — GORM Save (an upsert, which also
// resurrects a soft-deleted row) or Select("*").Updates(row). Every column a
// narrower concurrent writer changed in between (account_state, deleted_at,
// disabled, permission, ...) is silently written back to its stale value. A
// conditional WHERE on one column does not help the others. The fix shape is a
// column-scoped write: Updates(map[...]...), Update("col", v), a Select of NAMED
// columns, or a composite literal naming only the columns being set.
//
// What this guard checks: every non-test .go file under internal/storage/store and
// internal/core (recursively), every call written as `<expr>.Save(x)` or
// `<expr>.Updates(x)`, plus `<expr>.Clauses(clause.OnConflict{UpdateAll: true}).Create(x)`
// (an upsert that overwrites every column on conflict, reported as Call
// "Create+UpdateAll"), where x's static type resolves (see resolveFullRowArgModel)
// to a security-state model (see securityStateModels, derived from the models, not
// hand-listed). Such a call fails the guard unless it is
//   - Updates(x) with x a composite literal (only the literal's fields are written),
//     or a map, or
//   - Updates(x) whose receiver chain contains a Select(...) of string literals none
//     of which is "*",
//
// or its (file, function, model) appears in docs/full-row-write-exempt.tsv.
//
// What it does NOT check, stated so nobody mistakes green for more than it is:
//   - Writes on models that are not security-state (their Save calls are logged, not
//     failed — see TestFullRowWriteGuard_LogsNonSecurityStateSaves).
//   - Raw SQL (Exec("UPDATE ... SET col = ?")) — always column-scoped by construction,
//     so not this class.
//   - Calls through a helper whose name is not Save/Updates.
//   - An argument whose type cannot be resolved syntactically: that FAILS the guard
//     (fail closed) rather than being skipped.
//
// Sibling, per-operation guards added by the race-fix PRs (#2664, #2666, #2668:
// internal/core/*_column_scoped_guard_test.go) pin individual fixed operations; this
// one is the class-wide sweep. Consolidating them is left to a follow-up.
package store

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// securityStateColumns is the vocabulary that makes a model "security-state": a
// column whose value gates access, liveness or credential validity, and that some
// writer other than the row's general editor changes (a suspend, a revoke, a delete
// cascade, a disable, a decision). A model is security-state iff it has at least one
// of these fields (or embeds gorm.DeletedAt). The MODEL list is derived from this
// vocabulary over models.AllTestModels(); adding a model with a `State` or
// `DeletedAt` column puts it under the guard with no edit here.
var securityStateColumns = map[string]bool{
	"DeletedAt": true, "State": true, "Status": true, "AccountState": true,
	"Disabled": true, "Enabled": true, "IsActive": true, "Activated": true,
	"Revoked": true, "RevokedAt": true, "Released": true, "Approved": true,
	"Decision": true, "Permission": true, "Permissions": true, "RoleID": true,
	"PasswordHash": true, "MFAEnabled": true, "WebAuthnEnabled": true,
	"LoginLockedUntil": true, "ExpiresAt": true, "ConsumedAt": true, "UsedAt": true,
	"BypassesPermissionChecks": true, "OwnerID": true, "RequireMFA": true,
}

func securityStateModels() map[string]bool {
	out := map[string]bool{}
	deletedAt := reflect.TypeOf(gorm.DeletedAt{})
	for _, m := range models.AllTestModels() {
		t := reflect.TypeOf(m)
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if securityStateColumns[f.Name] || f.Type == deletedAt {
				out[t.Name()] = true
				break
			}
		}
	}
	return out
}

// TestFullRowWriteGuard_DerivedModelListCoversTheReviewedClass pins the derivation
// against the models the #2662 review actually found racing (plus the ones the
// C-GUARD-3 brief named). The brief also named "RoleAssignment": no such model
// exists — role grants are UserRole / GroupRole / MachineIdentityRole, checked here.
func TestFullRowWriteGuard_DerivedModelListCoversTheReviewedClass(t *testing.T) {
	got := securityStateModels()
	for _, want := range []string{
		"User", "ShareRecord", "SecretNode", "ProjectMembership", "MFASecret",
		"SecretACL", "UserRole", "GroupRole", "MachineIdentity", "DynamicSecretConfig",
		"AccessReviewItem", "Project", "Environment", "Group",
	} {
		require.Truef(t, got[want], "%s is no longer derived as security-state: securityStateColumns lost the column that classified it", want)
	}
}

type fullRowHit struct {
	File, Func, Model, Call string
	Line                    int
}

func (h fullRowHit) key() string { return h.File + "\t" + h.Func + "\t" + h.Model }

// fullRowWriteRoots are the directories swept, relative to this package directory.
var fullRowWriteRoots = []string{".", "../../core"}

func fullRowWriteHits(t *testing.T, roots []string) (hits []fullRowHit, nonSecurity []fullRowHit) {
	t.Helper()
	sec := securityStateModels()
	all := map[string]bool{}
	for _, m := range models.AllTestModels() {
		tt := reflect.TypeOf(m)
		for tt.Kind() == reflect.Pointer {
			tt = tt.Elem()
		}
		all[tt.Name()] = true
	}
	for _, root := range roots {
		results := fullRowResultIndex(t, root)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel := repoRelPath(t, path)
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				fn := funcDisplayName(fd)
				env := newTypeEnv(fd)
				env.results = results
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					env.observe(n)
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := ce.Fun.(*ast.SelectorExpr)
					if !ok || len(ce.Args) != 1 {
						return true
					}
					call := sel.Sel.Name
					switch {
					case call == "Save" || call == "Updates":
					case call == "Create" && chainHasUpdateAllUpsert(sel.X):
						call = "Create+UpdateAll"
					default:
						return true
					}
					if call == "Updates" && updatesIsColumnScoped(sel.X, ce.Args[0], env) {
						return true
					}
					model := env.modelOf(ce.Args[0])
					if model == "" {
						// Not resolvable: fail closed unless it is plainly not a model
						// (Save on something else entirely, e.g. a non-gorm helper).
						model = "?unresolved:" + fullRowExprString(ce.Args[0])
					} else if !all[model] {
						return true // a non-model type that happens to have Save/Updates
					}
					h := fullRowHit{File: rel, Func: fn, Model: model, Call: call, Line: fset.Position(ce.Pos()).Line}
					if strings.HasPrefix(model, "?") || sec[model] {
						hits = append(hits, h)
					} else {
						nonSecurity = append(nonSecurity, h)
					}
					return true
				})
			}
			return nil
		})
		require.NoError(t, err)
	}
	return hits, nonSecurity
}

// updatesIsColumnScoped: a map or composite-literal argument, or a Select of named
// (non-"*") string-literal columns somewhere in the receiver chain.
func updatesIsColumnScoped(recv ast.Expr, arg ast.Expr, env *typeEnv) bool {
	a := arg
	if u, ok := a.(*ast.UnaryExpr); ok && u.Op == token.AND {
		a = u.X
	}
	if cl, ok := a.(*ast.CompositeLit); ok {
		_ = cl
		return true
	}
	if env.isMap(a) {
		return true
	}
	for x := recv; x != nil; {
		ce, ok := x.(*ast.CallExpr)
		if !ok {
			break
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		if sel.Sel.Name == "Select" && len(ce.Args) > 0 {
			named := true
			for _, a := range ce.Args {
				bl, ok := a.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					named = false
					break
				}
				if s, _ := strconv.Unquote(bl.Value); s == "*" {
					named = false
				}
			}
			return named
		}
		x = sel.X
	}
	return false
}

// chainHasUpdateAllUpsert reports whether a receiver chain contains
// Clauses(clause.OnConflict{..., UpdateAll: true, ...}).
func chainHasUpdateAllUpsert(recv ast.Expr) bool {
	found := false
	ast.Inspect(recv, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "UpdateAll" {
			if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "true" {
				found = true
			}
		}
		return true
	})
	return found
}

// typeEnv is a deliberately small, syntactic type resolver for one function body:
// parameters, `var x T`, `x := &models.T{...}` / `models.T{}` / `new(models.T)`, and
// `for _, x := range xs` where xs is a known slice. It is enough for every Save /
// Updates argument in these packages today; anything else resolves to "" and the
// guard fails closed with an "?unresolved" hit.
type typeEnv struct {
	vars    map[string]ast.Expr
	results map[string]ast.Expr // first result type of every function/method declared under the same root, by name
}

// fullRowResultIndex maps every function or method name declared in a non-test
// file under root to its first result type, so `x, err := ls.GetShareRecord(...)`
// resolves x. A name declared twice with different result types is dropped
// (ambiguous: the guard then fails closed on it).
func fullRowResultIndex(t *testing.T, root string) map[string]ast.Expr {
	t.Helper()
	idx := map[string]ast.Expr{}
	ambiguous := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Type.Results == nil || len(fd.Type.Results.List) == 0 {
				continue
			}
			rt := fd.Type.Results.List[0].Type
			if prev, ok := idx[fd.Name.Name]; ok && fullRowExprString(prev) != fullRowExprString(rt) {
				ambiguous[fd.Name.Name] = true
			}
			idx[fd.Name.Name] = rt
		}
		return nil
	})
	require.NoError(t, err)
	for n := range ambiguous {
		delete(idx, n)
	}
	return idx
}

func newTypeEnv(fd *ast.FuncDecl) *typeEnv {
	e := &typeEnv{vars: map[string]ast.Expr{}}
	add := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				e.vars[n.Name] = f.Type
			}
		}
	}
	add(fd.Recv)
	add(fd.Type.Params)
	add(fd.Type.Results)
	return e
}

func (e *typeEnv) observe(n ast.Node) {
	switch s := n.(type) {
	case *ast.ValueSpec:
		for _, name := range s.Names {
			if s.Type != nil {
				e.vars[name.Name] = s.Type
			}
		}
	case *ast.AssignStmt:
		if len(s.Rhs) == 1 && len(s.Lhs) >= 1 {
			if ce, ok := s.Rhs[0].(*ast.CallExpr); ok {
				name := ""
				switch fn := ce.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if rt, ok := e.results[name]; ok && name != "new" {
					if id, ok := s.Lhs[0].(*ast.Ident); ok {
						e.vars[id.Name] = rt
					}
				}
			}
		}
		if len(s.Lhs) != len(s.Rhs) {
			return
		}
		for i, l := range s.Lhs {
			id, ok := l.(*ast.Ident)
			if !ok {
				continue
			}
			if t := literalType(s.Rhs[i]); t != nil {
				e.vars[id.Name] = t
			}
		}
	case *ast.RangeStmt:
		id, ok := s.Value.(*ast.Ident)
		if !ok {
			return
		}
		if xs, ok := s.X.(*ast.Ident); ok {
			if t, ok := e.vars[xs.Name]; ok {
				if at, ok := t.(*ast.ArrayType); ok {
					e.vars[id.Name] = at.Elt
				}
			}
		}
	}
}

func literalType(x ast.Expr) ast.Expr {
	if u, ok := x.(*ast.UnaryExpr); ok && u.Op == token.AND {
		if cl, ok := u.X.(*ast.CompositeLit); ok {
			return &ast.StarExpr{X: cl.Type}
		}
	}
	if cl, ok := x.(*ast.CompositeLit); ok {
		return cl.Type
	}
	if ce, ok := x.(*ast.CallExpr); ok {
		if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "new" && len(ce.Args) == 1 {
			return &ast.StarExpr{X: ce.Args[0]}
		}
	}
	return nil
}

func (e *typeEnv) typeOf(x ast.Expr) ast.Expr {
	switch v := x.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			if t := e.typeOf(v.X); t != nil {
				return &ast.StarExpr{X: t}
			}
		}
	case *ast.Ident:
		return e.vars[v.Name]
	case *ast.CompositeLit:
		return v.Type
	case *ast.StarExpr:
		if t := e.typeOf(v.X); t != nil {
			if st, ok := t.(*ast.StarExpr); ok {
				return st.X
			}
		}
	}
	return nil
}

func (e *typeEnv) isMap(x ast.Expr) bool {
	t := e.typeOf(x)
	_, ok := t.(*ast.MapType)
	return ok
}

// modelOf returns the models.<Name> a Save/Updates argument points at (through any
// number of *, &, []), or "".
func (e *typeEnv) modelOf(x ast.Expr) string {
	t := e.typeOf(x)
	for t != nil {
		switch v := t.(type) {
		case *ast.StarExpr:
			t = v.X
		case *ast.ArrayType:
			t = v.Elt
		case *ast.SelectorExpr:
			if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "models" {
				return v.Sel.Name
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}

func fullRowExprString(x ast.Expr) string {
	switch v := x.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.UnaryExpr:
		return v.Op.String() + fullRowExprString(v.X)
	case *ast.StarExpr:
		return "*" + fullRowExprString(v.X)
	case *ast.SelectorExpr:
		return fullRowExprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return fullRowExprString(v.Fun) + "()"
	case *ast.IndexExpr:
		return fullRowExprString(v.X) + "[]"
	}
	return fmt.Sprintf("%T", x)
}

func funcDisplayName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	rt := fd.Recv.List[0].Type
	star := ""
	if s, ok := rt.(*ast.StarExpr); ok {
		star, rt = "*", s.X
	}
	if id, ok := rt.(*ast.Ident); ok {
		return "(" + star + id.Name + ")." + fd.Name.Name
	}
	return fd.Name.Name
}

// repoRelPath renders path relative to the repository root (this package is two
// levels below internal/).
func repoRelPath(t *testing.T, path string) string {
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	rel, err := filepath.Rel(root, abs)
	require.NoError(t, err)
	return filepath.ToSlash(rel)
}

// fullRowExemptRow is one row of docs/full-row-write-exempt.tsv:
// file <TAB> function <TAB> model <TAB> reason <TAB> expires <TAB> added_by <TAB> reviewed_by
type fullRowExemptRow struct {
	File, Func, Model, Reason, Expires, AddedBy, ReviewedBy string
	Line                                                    int
}

func (r fullRowExemptRow) key() string { return r.File + "\t" + r.Func + "\t" + r.Model }

const fullRowExemptPath = "../../../docs/full-row-write-exempt.tsv"

func loadFullRowExempt(t *testing.T) []fullRowExemptRow {
	t.Helper()
	fh, err := os.Open(fullRowExemptPath)
	require.NoError(t, err)
	defer func() { _ = fh.Close() }()
	var rows []fullRowExemptRow
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		c := strings.Split(s, "\t")
		require.Lenf(t, c, 7, "%s:%d: want 7 tab-separated columns (file, function, model, reason, expires, added_by, reviewed_by)", fullRowExemptPath, line)
		rows = append(rows, fullRowExemptRow{c[0], c[1], c[2], c[3], c[4], c[5], c[6], line})
	}
	require.NoError(t, sc.Err())
	return rows
}

// fullRowCallerModelPrefix marks a ledger row (Model column) as a CALLER row of the
// caller-chain scan (see fullRowCallerHits): "calls:<LocalStorage method>". Rows
// without the prefix are direct-write rows of fullRowWriteHits.
const fullRowCallerModelPrefix = "calls:"

func isFullRowCallerRow(r fullRowExemptRow) bool {
	return strings.HasPrefix(r.Model, fullRowCallerModelPrefix)
}

// TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels is the guard.
func TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels(t *testing.T) {
	hits, _ := fullRowWriteHits(t, fullRowWriteRoots)
	var rows []fullRowExemptRow
	for _, r := range loadFullRowExempt(t) {
		if !isFullRowCallerRow(r) { // caller rows belong to the caller-chain guard
			rows = append(rows, r)
		}
	}
	exempt := map[string]fullRowExemptRow{}
	for _, r := range rows {
		_, dup := exempt[r.key()]
		require.Falsef(t, dup, "%s:%d duplicate row for %s", fullRowExemptPath, r.Line, r.key())
		exempt[r.key()] = r
	}
	matched := map[string]bool{}
	var bad []string
	for _, h := range hits {
		if _, ok := exempt[h.key()]; ok {
			matched[h.key()] = true
			continue
		}
		bad = append(bad, fmt.Sprintf("%s:%d %s %s(%s) — write only the columns this operation owns (Updates(map…), Update(col, v), Select(named cols)), or add a reviewed row to docs/full-row-write-exempt.tsv", h.File, h.Line, h.Func, h.Call, h.Model))
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d stale full-row write(s) on security-state models:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	var stale []string
	for _, r := range rows {
		if !matched[r.key()] && !fullRowArrivesRe.MatchString(r.Reason) {
			stale = append(stale, fmt.Sprintf("%s:%d %s %s %s", fullRowExemptPath, r.Line, r.File, r.Func, r.Model))
		}
	}
	if len(stale) > 0 {
		t.Errorf("%d exemption row(s) no longer match any hit — delete them (an exemption must not outlive its site):\n  %s", len(stale), strings.Join(stale, "\n  "))
	}
}

// fullRowArrivesRe marks a row pre-registered for a site that an open PR moves or
// renames ("arrives with #NNNN"): it may match nothing until that PR merges. Like a
// pending row it must carry an expiry, so it cannot linger.
var fullRowArrivesRe = regexp.MustCompile(`arrives with #\d+`)

// TestFullRowWriteGuard_PendingRowsNotExpired: a row whose reason says
// "pending: #NNNN" carries an expiry; past it, the row fails, so a stuck fix PR
// cannot leave the exemption in place forever. (Whether the PR has already merged is
// checked by scripts/check-pending-exemptions.sh, which needs network.)
func TestFullRowWriteGuard_PendingRowsNotExpired(t *testing.T) {
	now := time.Now().UTC()
	for _, r := range loadFullRowExempt(t) {
		if r.Expires == "-" {
			require.NotContainsf(t, r.Reason, "pending: #", "%s:%d a pending row must carry an expiry date", fullRowExemptPath, r.Line)
			require.Falsef(t, fullRowArrivesRe.MatchString(r.Reason), "%s:%d an \"arrives with\" row must carry an expiry date", fullRowExemptPath, r.Line)
			continue
		}
		exp, err := time.Parse("2006-01-02", r.Expires)
		require.NoErrorf(t, err, "%s:%d expires must be YYYY-MM-DD or -", fullRowExemptPath, r.Line)
		require.Truef(t, now.Before(exp.Add(24*time.Hour)), "%s:%d exemption for %s %s expired on %s: %s", fullRowExemptPath, r.Line, r.Func, r.Model, r.Expires, r.Reason)
	}
}

// TestFullRowWriteGuard_LogsNonSecurityStateSaves makes the guard's skipped
// population visible instead of silent.
func TestFullRowWriteGuard_LogsNonSecurityStateSaves(t *testing.T) {
	_, skipped := fullRowWriteHits(t, fullRowWriteRoots)
	for _, h := range skipped {
		t.Logf("not guarded (model %s is not security-state): %s:%d %s %s", h.Model, h.File, h.Line, h.Func, h.Call)
	}
}

// TestFullRowWriteGuard_DetectsTheFixedShapes is the guard's calibration: each
// historical bug shape from the class (#2648 Save(&existing); #2653 Select("*").Updates;
// an unresolvable argument) is a hit, and each fixed shape is not.
func TestFullRowWriteGuard_DetectsTheFixedShapes(t *testing.T) {
	dir := t.TempDir()
	src := `package x
import "github.com/keyorixhq/keyorix/internal/storage/models"
func (ls *LocalStorage) UpdateSharePermission(id uint) error {
	var existing models.ShareRecord
	return ls.db.Save(&existing).Error
}
func (ls *LocalStorage) UpdateUser(u *models.User) error {
	return ls.db.Model(&models.User{}).Where("id = ?", u.ID).Select("*").Updates(u).Error
}
func (ls *LocalStorage) Unresolved() error { return ls.db.Save(ls.thing()).Error }
func (ls *LocalStorage) GetShareRecord(id uint) (*models.ShareRecord, error) { return nil, nil }
func (ls *LocalStorage) UpdateShareRecord(id uint) error {
	existing, err := ls.GetShareRecord(id)
	if err != nil {
		return err
	}
	return ls.db.Save(existing).Error
}
func (ls *LocalStorage) FixedMap(u *models.User) error {
	return ls.db.Model(u).Updates(map[string]interface{}{"display_name": u.DisplayName}).Error
}
func (ls *LocalStorage) FixedSelect(u *models.User) error {
	return ls.db.Model(u).Select("display_name", "email").Updates(u).Error
}
func (ls *LocalStorage) FixedLiteral(id uint) error {
	return ls.db.Model(&models.User{}).Where("id = ?", id).Updates(models.User{DisplayName: "x"}).Error
}
func (ls *LocalStorage) UpsertMFASecret(s *models.MFASecret) error {
	return ls.db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "user_id"}}, UpdateAll: true}).Create(s).Error
}
func (ls *LocalStorage) PlainCreate(s *models.MFASecret) error { return ls.db.Create(s).Error }
func (ls *LocalStorage) NotSecurity(t *models.SecretTemplate) error { return ls.db.Save(t).Error }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600))
	hits, skipped := fullRowWriteHits(t, []string{dir})
	var got []string
	for _, h := range hits {
		got = append(got, h.Func+":"+h.Model)
	}
	sort.Strings(got)
	require.Equal(t, []string{
		"(*LocalStorage).Unresolved:?unresolved:ls.thing()",
		"(*LocalStorage).UpdateSharePermission:ShareRecord",
		"(*LocalStorage).UpdateShareRecord:ShareRecord",
		"(*LocalStorage).UpdateUser:User",
		"(*LocalStorage).UpsertMFASecret:MFASecret",
	}, got)
	require.Len(t, skipped, 1)
	require.Equal(t, "SecretTemplate", skipped[0].Model)
}
