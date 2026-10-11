// child_parent_liveness_registry_test.go — registry guard for the "child created
// under a possibly-deleted parent" race class (#2646, #2647, #2649, #2651, #2652,
// #2656; independent review #2662).
//
// The class: a storage method inserts (or un-deletes / re-enables) a row whose
// model has a foreign key to a soft-deletable or disableable parent. A parent
// delete cascade that runs between the caller's liveness check and the insert never
// sees the child, so the child commits under a deleted parent (a grant on a deleted
// secret, a lease under a deleted project, ...). The fix shape is lockLiveParent
// (local_parent_liveness.go): after the child write, in the same transaction,
// re-read the parent FOR SHARE and roll back if it is gone.
//
// What this guard derives, rather than hand-lists:
//   - Liveness parents: every model in models.AllTestModels() with a gorm.DeletedAt
//     field or a `Disabled bool` field.
//   - Child edges: every `...ID` field of every model, mapped to the model it
//     references by childFKTargets. The mapping is hand-written, but COMPLETE by
//     construction: an `...ID` field with no entry fails
//     TestChildParentLiveness_EveryIDFieldClassified, so a new child model or a new
//     foreign key cannot slip past unclassified.
//   - Insert sites: every function in this package's non-test .go files that calls
//     `<expr>.Create(x)`, `<expr>.FirstOrCreate(x, ...)` or `<expr>.CreateInBatches(x, n)`
//     with x a child model, or that un-deletes /
//     re-enables one (`Update("deleted_at", nil)` / `Update("disabled", false)` with a
//     `Model(&models.X{})` in the chain).
//
// A (function, child, parent) triple passes when the same function calls
// `lockLiveParent(tx, &models.<Parent>{}, ...)`, or when the function has at least
// one caller in this package and EVERY such caller does (one hop: insert helpers
// like createShareRecordTx are run by a locking caller). Otherwise it must appear
// in docs/child-parent-liveness-exempt.tsv with a reason.
//
// What it does NOT see: Save(x) — an update of an existing row whose stale
// deleted_at/disabled can resurrect a cascaded child, which is the stale
// full-row-write class and is guarded by full_row_write_guard_test.go instead;
// raw SQL inserts (Exec("INSERT ...") — TestChildParentLiveness_NoRawSQLInserts
// fails if one appears); inserts made outside internal/storage/store; whether the
// lockLiveParent call checks the RIGHT row (its WHERE args are not evaluated) or runs
// after the write in the same transaction (the doc comment on lockLiveParent states
// the contract; INV-STORE-21's tests prove it per site); and a parent delete path
// that sweeps children before locking the parent row (lockLiveParent's own caveat).
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

// childFKTargets maps "<Model>.<Field>" (or "*.<Field>" for every model) to the model
// that field references, or to "-" when it does not reference a liveness parent
// (with the reason in the comment). Exact "<Model>.<Field>" entries win over "*".
var childFKTargets = map[string]string{
	"*.ProjectID":                        "Project",
	"*.EnvironmentID":                    "Environment",
	"*.GroupID":                          "Group",
	"*.UserID":                           "User",
	"*.SecretNodeID":                     "SecretNode",
	"*.SecretID":                         "SecretNode",
	"*.OwnerID":                          "User",
	"*.MachineIdentityID":                "-", // MachineIdentity is state-machined (State), not soft-deleted/disabled: out of this class
	"*.RoleID":                           "-", // Role has no DeletedAt/Disabled
	"*.PermissionID":                     "-", // Permission has no DeletedAt/Disabled
	"*.TagID":                            "-", // Tag has no DeletedAt/Disabled
	"*.ClientID":                         "-", // string client identifier of an APIClient, not a soft-deletable parent
	"*.ProviderID":                       "-", // IdentityProvider has no DeletedAt/Disabled
	"*.ExternalID":                       "-", // external IdP subject string, not a foreign key
	"*.CredentialID":                     "-", // WebAuthn credential id bytes (the credential's own identifier), not a foreign key
	"*.FamilyID":                         "-", // session refresh-family identifier, not a foreign key
	"*.LeaseID":                          "-", // the lease's own external identifier string
	"*.InvitationID":                     "-", // ProjectInvitation has no DeletedAt/Disabled
	"*.RequestID":                        "-", // AccessRequest has no DeletedAt/Disabled
	"*.CampaignID":                       "-", // AccessReviewCampaign has no DeletedAt/Disabled
	"*.VersionID":                        "-", // SecretVersion has no DeletedAt/Disabled (hard-deleted with its secret)
	"*.SecretVersionID":                  "-", // SecretVersion, as above
	"*.HeadID":                           "-", // audit-chain checkpoint pointer, not a parent
	"*.LoginAttemptID":                   "-", // per-IP budget row a login flow holds (#2936); LoginAttempt has no DeletedAt/Disabled and a missing row only means nothing to hand back
	"*.ShareID":                          "-", // UserSecretPermission is a read-model view, never inserted by storage
	"*.ApproverMachineIdentityID":        "-",
	"*.CreatedByMachineIdentityID":       "-",
	"*.ClosedByMachineIdentityID":        "-",
	"*.InvitedByMachineIdentityID":       "-",
	"*.ResolvedByMachineIdentityID":      "-",
	"*.RevokedByMachineIdentityID":       "-",
	"*.OwnerMachineIdentityID":           "-",
	"*.ApproverID":                       "User",
	"*.SubjectUserID":                    "User",
	"SecretNode.ParentID":                "SecretNode",
	"SecretDependency.DependentSecretID": "SecretNode",
	"SecretDependency.DependsOnSecretID": "SecretNode",
	"DynamicSecretLease.ConfigID":        "DynamicSecretConfig",
	"ShareRecord.RecipientID":            "User", // or Group when IsGroup; both are liveness parents
	"ShareSummary.RecipientID":           "-",    // response DTO, not a table
	"RecentShareInfo.RecipientID":        "-",
	"AccessReviewItem.PrincipalID":       "-", // polymorphic (user/group/machine) snapshot of a review subject, not a live grant
	"AccessReviewItem.EnvironmentID":     "-", // descriptive snapshot column of a review item
	"AccessReviewItem.SecretID":          "-", // descriptive snapshot column of a review item
	"AuditEvent.UserID":                  "-", // audit rows are append-only history; they must outlive their subject
	"AuditEvent.SecretNodeID":            "-",
	"AuditEvent.ProjectID":               "-",
	"APICallLog.UserID":                  "-", // request log, history
	"SecretAccessLog.SecretNodeID":       "-", // access history
	"SecretMetadataHistory.SecretNodeID": "-", // history
	"AnomalyAlert.SecretNodeID":          "-", // detection history
	"SecretListFilter.ProjectID":         "-", // query DTO, not a table
	"SecretListFilter.EnvironmentID":     "-",
	"SecretListFilter.ParentID":          "-",
	"SecretVersionComment.SecretID":      "SecretNode",
	"StatsSnapshot.UserID":               "-", // metrics snapshot
	"Setting.UserID":                     "User",
	"GRPCService.Name":                   "-",
}

func childLiveModelName(m any) (reflect.Type, string) {
	t := reflect.TypeOf(m)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t, t.Name()
}

// livenessParents: models with gorm.DeletedAt or a Disabled bool.
func livenessParents() map[string]bool {
	out := map[string]bool{}
	deletedAt := reflect.TypeOf(gorm.DeletedAt{})
	for _, m := range models.AllTestModels() {
		t, name := childLiveModelName(m)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Type == deletedAt || (f.Name == "Disabled" && f.Type.Kind() == reflect.Bool) {
				out[name] = true
				break
			}
		}
	}
	return out
}

func childFKTarget(model, field string) (string, bool) {
	if v, ok := childFKTargets[model+"."+field]; ok {
		return v, true
	}
	v, ok := childFKTargets["*."+field]
	return v, ok
}

func childIDFields(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous || f.Name == "ID" || !strings.HasSuffix(f.Name, "ID") {
			continue
		}
		out = append(out, f.Name)
	}
	return out
}

// childParentEdges maps child model -> set of liveness-parent models it references.
func childParentEdges(t *testing.T) map[string][]string {
	t.Helper()
	parents := livenessParents()
	out := map[string][]string{}
	for _, m := range models.AllTestModels() {
		mt, name := childLiveModelName(m)
		seen := map[string]bool{}
		for _, f := range childIDFields(mt) {
			p, ok := childFKTarget(name, f)
			require.Truef(t, ok, "unclassified foreign-key-looking field %s.%s", name, f)
			// ShareRecord.RecipientID is a user OR a group (IsGroup): both are parents.
			// Handled before the dedup below, since OwnerID may already have added User.
			if name == "ShareRecord" && f == "RecipientID" && parents["Group"] && !seen["Group"] {
				seen["Group"] = true
				out[name] = append(out[name], "Group")
			}
			if p == "-" || !parents[p] || seen[p] {
				continue
			}
			seen[p] = true
			out[name] = append(out[name], p)
		}
		sort.Strings(out[name])
	}
	return out
}

// TestChildParentLiveness_EveryIDFieldClassified is the completeness half: every
// `...ID` field of every model has an entry, so the edge set is derived from the
// models and a new foreign key fails here until someone decides what it points at.
func TestChildParentLiveness_EveryIDFieldClassified(t *testing.T) {
	var missing []string
	for _, m := range models.AllTestModels() {
		mt, name := childLiveModelName(m)
		for _, f := range childIDFields(mt) {
			if _, ok := childFKTarget(name, f); !ok {
				missing = append(missing, name+"."+f)
			}
		}
	}
	require.Emptyf(t, missing, "classify these fields in childFKTargets (a liveness-parent model name, or \"-\" with a reason): %v", missing)
	edges := childParentEdges(t)
	// Calibration: the parents of the #2662 findings are derived, not hand-listed.
	for child, want := range map[string]string{
		"SecretACL": "SecretNode", "ShareRecord": "SecretNode", "DynamicSecretLease": "DynamicSecretConfig",
		"DynamicSecretConfig": "Project", "Environment": "Project",
	} {
		require.Containsf(t, edges[child], want, "derived edges lost %s -> %s", child, want)
	}
	// ShareRecord.RecipientID is polymorphic (user or group); both edges must exist
	// even though OwnerID already contributes User.
	for _, want := range []string{"User", "Group", "SecretNode"} {
		require.Containsf(t, edges["ShareRecord"], want, "derived edges lost ShareRecord -> %s", want)
	}
}

type childInsertSite struct {
	Func, Child, Kind string
	Line              int
}

type childLiveFunc struct {
	name   string
	locked map[string]bool // parent models passed to lockLiveParent in this body
	calls  map[string]bool // same-package function names this body calls
	sites  []childInsertSite
}

// childLiveScan parses every non-test .go file in dir.
func childLiveScan(t *testing.T, dir string) map[string]*childLiveFunc {
	t.Helper()
	childModels := map[string]bool{}
	for c := range childParentEdges(t) {
		childModels[c] = true
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	funcs := map[string]*childLiveFunc{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			cf := &childLiveFunc{name: fd.Name.Name, locked: map[string]bool{}, calls: map[string]bool{}}
			env := childLiveTypes(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
					for i, l := range as.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							if m := childLiveLiteralModel(as.Rhs[i]); m != "" {
								env[id.Name] = m
							}
						}
					}
				}
				if vs, ok := n.(*ast.ValueSpec); ok && vs.Type != nil {
					for _, nm := range vs.Names {
						if m := childLiveTypeModel(vs.Type); m != "" {
							env[nm.Name] = m
						}
					}
				}
				if rs, ok := n.(*ast.RangeStmt); ok {
					if v, ok := rs.Value.(*ast.Ident); ok {
						if xs, ok := rs.X.(*ast.Ident); ok && env[xs.Name] != "" {
							env[v.Name] = env[xs.Name]
						}
					}
				}
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				line := fset.Position(ce.Pos()).Line
				switch fn := ce.Fun.(type) {
				case *ast.Ident:
					cf.calls[fn.Name] = true
					if fn.Name == "lockLiveParent" && len(ce.Args) >= 2 {
						if m := childLiveLiteralModel(ce.Args[1]); m != "" {
							cf.locked[m] = true
						}
					}
				case *ast.SelectorExpr:
					cf.calls[fn.Sel.Name] = true
					switch fn.Sel.Name {
					case "Create", "FirstOrCreate", "CreateInBatches":
						if len(ce.Args) == 0 {
							break
						}
						m := childLiveArgModel(ce.Args[0], env)
						if childModels[m] {
							cf.sites = append(cf.sites, childInsertSite{Func: fd.Name.Name, Child: m, Kind: fn.Sel.Name, Line: line})
						}
					case "Update":
						if len(ce.Args) != 2 {
							break
						}
						col, ok := ce.Args[0].(*ast.BasicLit)
						if !ok {
							break
						}
						c, _ := strconv.Unquote(col.Value)
						v, _ := ce.Args[1].(*ast.Ident)
						if v == nil || !((c == "deleted_at" && v.Name == "nil") || (c == "disabled" && v.Name == "false")) {
							break
						}
						if m := childLiveChainModel(fn.X); childModels[m] {
							cf.sites = append(cf.sites, childInsertSite{Func: fd.Name.Name, Child: m, Kind: "revive:" + c, Line: line})
						}
					}
				}
				return true
			})
			funcs[childLiveFuncKey(fd)] = cf
		}
	}
	return funcs
}

// childLiveFuncKey distinguishes same-named methods on different receivers.
func childLiveFuncKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return fmt.Sprintf("%T:%s", fd.Recv.List[0].Type, fd.Name.Name) + childLiveRecvName(fd.Recv.List[0].Type)
}

func childLiveRecvName(x ast.Expr) string {
	if s, ok := x.(*ast.StarExpr); ok {
		x = s.X
	}
	if id, ok := x.(*ast.Ident); ok {
		return "@" + id.Name
	}
	return ""
}

func childLiveTypes(fd *ast.FuncDecl) map[string]string {
	env := map[string]string{}
	for _, fl := range []*ast.FieldList{fd.Recv, fd.Type.Params} {
		if fl == nil {
			continue
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				if m := childLiveTypeModel(f.Type); m != "" {
					env[n.Name] = m
				}
			}
		}
	}
	return env
}

func childLiveTypeModel(x ast.Expr) string {
	for {
		switch v := x.(type) {
		case *ast.StarExpr:
			x = v.X
		case *ast.ArrayType:
			x = v.Elt
		case *ast.SelectorExpr:
			if p, ok := v.X.(*ast.Ident); ok && p.Name == "models" {
				return v.Sel.Name
			}
			return ""
		default:
			return ""
		}
	}
}

func childLiveLiteralModel(x ast.Expr) string {
	if u, ok := x.(*ast.UnaryExpr); ok && u.Op == token.AND {
		x = u.X
	}
	if cl, ok := x.(*ast.CompositeLit); ok {
		return childLiveTypeModel(cl.Type)
	}
	if ce, ok := x.(*ast.CallExpr); ok {
		if id, ok := ce.Fun.(*ast.Ident); ok && (id.Name == "new" || id.Name == "make") && len(ce.Args) >= 1 {
			return childLiveTypeModel(ce.Args[0])
		}
	}
	return ""
}

func childLiveArgModel(x ast.Expr, env map[string]string) string {
	if m := childLiveLiteralModel(x); m != "" {
		return m
	}
	if u, ok := x.(*ast.UnaryExpr); ok && u.Op == token.AND {
		x = u.X
	}
	if id, ok := x.(*ast.Ident); ok {
		return env[id.Name]
	}
	return ""
}

// childLiveChainModel finds Model(&models.X{}) in a receiver chain.
func childLiveChainModel(x ast.Expr) string {
	for {
		ce, ok := x.(*ast.CallExpr)
		if !ok {
			return ""
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if sel.Sel.Name == "Model" && len(ce.Args) == 1 {
			return childLiveLiteralModel(ce.Args[0])
		}
		x = sel.X
	}
}

type childLiveExemptRow struct {
	Func, Child, Parent, Reason, Expires, AddedBy, ReviewedBy string
	Line                                                      int
}

func (r childLiveExemptRow) key() string { return r.Func + "\t" + r.Child + "\t" + r.Parent }

const childLiveExemptPath = "../../../docs/child-parent-liveness-exempt.tsv"

func loadChildLiveExempt(t *testing.T) []childLiveExemptRow {
	t.Helper()
	fh, err := os.Open(childLiveExemptPath)
	require.NoError(t, err)
	defer func() { _ = fh.Close() }()
	var rows []childLiveExemptRow
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
		require.Lenf(t, c, 7, "%s:%d: want 7 tab-separated columns (function, child, parent, reason, expires, added_by, reviewed_by)", childLiveExemptPath, line)
		rows = append(rows, childLiveExemptRow{c[0], c[1], c[2], c[3], c[4], c[5], c[6], line})
	}
	require.NoError(t, sc.Err())
	return rows
}

type childLiveViolation struct {
	Func, Child, Parent, Kind string
	Line                      int
}

func childLiveViolations(t *testing.T, dir string) []childLiveViolation {
	t.Helper()
	funcs := childLiveScan(t, dir)
	edges := childParentEdges(t)
	callers := map[string][]*childLiveFunc{}
	for _, f := range funcs {
		for c := range f.calls {
			if c != f.name {
				callers[c] = append(callers[c], f)
			}
		}
	}
	covered := func(f *childLiveFunc, parent string) bool {
		if f.locked[parent] {
			return true
		}
		cs := callers[f.name]
		if len(cs) == 0 {
			return false
		}
		for _, c := range cs {
			if !c.locked[parent] {
				return false
			}
		}
		return true
	}
	seen := map[string]bool{}
	var out []childLiveViolation
	for _, f := range funcs {
		for _, s := range f.sites {
			for _, p := range edges[s.Child] {
				k := f.name + "\t" + s.Child + "\t" + p
				if seen[k] || covered(f, p) {
					continue
				}
				seen[k] = true
				out = append(out, childLiveViolation{f.name, s.Child, p, s.Kind, s.Line})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Func+out[i].Child+out[i].Parent < out[j].Func+out[j].Child+out[j].Parent
	})
	return out
}

// TestChildParentLiveness_EveryChildInsertLocksItsParent is the guard.
func TestChildParentLiveness_EveryChildInsertLocksItsParent(t *testing.T) {
	rows := loadChildLiveExempt(t)
	exempt := map[string]childLiveExemptRow{}
	for _, r := range rows {
		_, dup := exempt[r.key()]
		require.Falsef(t, dup, "%s:%d duplicate row %s", childLiveExemptPath, r.Line, r.key())
		exempt[r.key()] = r
	}
	matched := map[string]bool{}
	var bad []string
	for _, v := range childLiveViolations(t, ".") {
		k := v.Func + "\t" + v.Child + "\t" + v.Parent
		if _, ok := exempt[k]; ok {
			matched[k] = true
			continue
		}
		bad = append(bad, fmt.Sprintf("%s (line %d, %s %s) writes a %s child without lockLiveParent(tx, &models.%s{}, ...) in the same transaction", v.Func, v.Line, v.Kind, v.Child, v.Child, v.Parent))
	}
	if len(bad) > 0 {
		t.Errorf("%d child write(s) can land under a concurrently deleted parent — call lockLiveParent after the write (local_parent_liveness.go), or add a reviewed row to docs/child-parent-liveness-exempt.tsv:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	var stale []string
	for _, r := range rows {
		if !matched[r.key()] && !childLiveArrivesRe.MatchString(r.Reason) {
			stale = append(stale, fmt.Sprintf("%s:%d %s", childLiveExemptPath, r.Line, strings.ReplaceAll(r.key(), "\t", " ")))
		}
	}
	if len(stale) > 0 {
		t.Errorf("%d exemption row(s) no longer match an unlocked site — delete them:\n  %s", len(stale), strings.Join(stale, "\n  "))
	}
}

// childLiveArrivesRe marks a row pre-registered for a site an open PR creates or
// renames ("arrives with #NNNN"); it may match nothing until that PR merges, and
// must carry an expiry like a pending row.
var childLiveArrivesRe = regexp.MustCompile(`arrives with #\d+`)

// TestChildParentLiveness_PendingRowsNotExpired: see the full-row guard's twin.
func TestChildParentLiveness_PendingRowsNotExpired(t *testing.T) {
	now := time.Now().UTC()
	for _, r := range loadChildLiveExempt(t) {
		if r.Expires == "-" {
			require.NotContainsf(t, r.Reason, "pending: #", "%s:%d a pending row must carry an expiry date", childLiveExemptPath, r.Line)
			require.Falsef(t, childLiveArrivesRe.MatchString(r.Reason), "%s:%d an \"arrives with\" row must carry an expiry date", childLiveExemptPath, r.Line)
			continue
		}
		exp, err := time.Parse("2006-01-02", r.Expires)
		require.NoErrorf(t, err, "%s:%d expires must be YYYY-MM-DD or -", childLiveExemptPath, r.Line)
		require.Truef(t, now.Before(exp.Add(24*time.Hour)), "%s:%d exemption %s expired on %s: %s", childLiveExemptPath, r.Line, r.key(), r.Expires, r.Reason)
	}
}

// TestChildParentLiveness_NoRawSQLInserts: the sweep only sees GORM calls.
func TestChildParentLiveness_NoRawSQLInserts(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		up := strings.ToUpper(string(b))
		require.NotContainsf(t, up, "\"INSERT INTO", "%s issues a raw INSERT the liveness registry cannot see — extend the guard first", p)
		require.NotContainsf(t, up, "`INSERT INTO", "%s issues a raw INSERT the liveness registry cannot see — extend the guard first", p)
	}
}

// TestChildParentLiveness_Calibration: the historical shapes are flagged, the fixed
// shapes (same-function and one-hop-caller lockLiveParent) are not.
func TestChildParentLiveness_Calibration(t *testing.T) {
	dir := t.TempDir()
	src := `package x
import "github.com/keyorixhq/keyorix/internal/storage/models"
func (ls *LocalStorage) CreateOrUpdateSecretACL(acl *models.SecretACL) error { return ls.db.Create(acl).Error }
func (ls *LocalStorage) RestoreEnvironment(id uint) error {
	return ls.db.Unscoped().Model(&models.Environment{}).Where("id = ?", id).Update("deleted_at", nil).Error
}
func (ls *LocalStorage) CreateDynamicSecretLease(l *models.DynamicSecretLease) error {
	return ls.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(l).Error; err != nil { return err }
		_, err := lockLiveParent(tx, &models.DynamicSecretConfig{}, "id = ?", l.ConfigID)
		return err
	})
}
func (ls *LocalStorage) CreateShareRecord(s *models.ShareRecord) error {
	return ls.db.Transaction(func(tx *gorm.DB) error {
		if err := createShareRecordTx(tx, s); err != nil { return err }
		_, err := lockLiveParent(tx, &models.SecretNode{}, "id = ?", s.SecretID)
		return err
	})
}
func createShareRecordTx(tx *gorm.DB, s *models.ShareRecord) error {
	var existing models.ShareRecord
	_ = existing
	return tx.Create(s).Error
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600))
	var got []string
	for _, v := range childLiveViolations(t, dir) {
		got = append(got, v.Func+":"+v.Child+"->"+v.Parent)
	}
	require.Contains(t, got, "CreateOrUpdateSecretACL:SecretACL->SecretNode")
	require.Contains(t, got, "RestoreEnvironment:Environment->Project")
	require.NotContains(t, got, "CreateDynamicSecretLease:DynamicSecretLease->DynamicSecretConfig")
	require.NotContains(t, got, "createShareRecordTx:ShareRecord->SecretNode")
	// Not locked for its other parents: still reported.
	require.Contains(t, got, "CreateDynamicSecretLease:DynamicSecretLease->Project")
}
