// checkthencreate_race_completeness_test.go — regression guard for the
// recurring "check-then-create" TOCTOU race bug class this codebase has hit
// (and fixed) repeatedly: #117 (email/external_id), #121 (secret-version
// number), #136 (ShareRecord duplicate grants), #305 (PlaceLegalHold),
// #309/#313 (InviteMember/DeleteProject), #462 (dynamic-secrets config), and
// MT-006 (secret_nodes name uniqueness).
//
// The shape, every time: a function checks for an existing row by natural key
// (a Get<Entity>By<Key>-shaped call, or a Get<Adjective><Entity> existence
// probe like GetActiveLegalHold/GetActiveProjectMembership) and then, on a
// miss, Create()s a new row. The check and the create are two separate
// non-transactional statements, so two concurrent callers can both pass the
// check before either commits — producing duplicate rows for what was
// supposed to be a unique natural key. The fix this repo has landed every
// time is NOT "make the check atomic" (there is no portable SELECT..FOR
// UPDATE-free way to do that across SQLite+Postgres here) — it is: add a
// database-level unique index covering the natural key, so the LOSER of the
// race gets a constraint violation instead of a second live duplicate row,
// and translate that violation into the same clean error the sequential
// check would have produced.
//
// Following this repo's own established convention (see
// TestRemoteUnsupportedStubsAreAllowlisted, remote_unsupported_completeness_test.go,
// in this same package), the check-then-create call sites below are
// discovered PROGRAMMATICALLY via go/ast — not a hand-maintained list, which
// would immediately go stale as new storage methods are added. What IS
// hand-maintained is a small, explicit, comment-justified allowlist
// (checkThenCreateAllowlist below) for the rare legitimate exception.
//
// Two independent AST passes:
//
//  1. buildUniqueIndexRegistry walks internal/storage/models (struct field
//     GORM tags) and internal/storage/factory.go (the ensure<X>Index helpers'
//     raw `CREATE UNIQUE INDEX ... ON <table> (<cols>)` statements — this
//     repo's OWN established pattern for adding a unique index to a table
//     that might already hold pre-existing duplicate rows; see e.g. #117's
//     commit message: "not a plain gorm uniqueIndex tag — AutoMigrate
//     creating a unique index directly on an existing, potentially-already-
//     duplicate table is the exact failure mode this repo's own established
//     pattern avoids"). The result is table -> set of columns covered by AT
//     LEAST ONE unique index, from either source.
//
//  2. discoverCheckThenCreateSites walks every non-test .go file in
//     internal/core and internal/storage/store/local_*.go and, per function,
//     looks for a Create call preceded (anywhere earlier in the same
//     function, including inside a nested closure such as a
//     db.Transaction(func(tx *gorm.DB) error { ... }) callback) by a Get*
//     call whose name shares a contiguous camelCase word run with the
//     create's target entity name (e.g. "SecretByName" contains the word
//     run "Secret"; "ActiveLegalHold" contains "LegalHold";
//     "ActiveProjectMembership" contains "ProjectMembership"). The create
//     call's actual internal/storage/models struct type is then resolved
//     from its own arguments via lightweight AST type-tracing (composite
//     literal, function parameter, or a `:=`/`var` assignment earlier in the
//     function) — NOT from the method name — so the registry lookup is keyed
//     on the real model/table.
//
// A site fails the test when its resolved model's table has ZERO unique-index
// coverage (from either registry source) and the site is not in the
// allowlist. See the package doc comment on checkThenCreateAllowlist for the
// known, deliberate false-negative gaps in this heuristic.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// ---------------------------------------------------------------------------
// Part 1: table -> unique-indexed-columns registry.
// ---------------------------------------------------------------------------

// uniqueIndexRegistry maps a DB table name to the set of columns covered by
// AT LEAST ONE unique index on that table (gorm struct tag OR a runtime
// ensure*Index helper in factory.go — this repo uses both mechanisms
// depending on whether the table might already hold pre-existing duplicate
// rows at migration time; see the package doc comment above).
type uniqueIndexRegistry map[string]map[string]bool

func (r uniqueIndexRegistry) add(table, column string) {
	if table == "" {
		return
	}
	if r[table] == nil {
		r[table] = map[string]bool{}
	}
	if column != "" {
		r[table][column] = true
	} else {
		// A unique index whose column couldn't be parsed out still proves the
		// table has SOME unique-index coverage; record a sentinel so
		// hasAnyUniqueIndex(table) is true without asserting a bogus column.
		r[table]["*"] = true
	}
}

func (r uniqueIndexRegistry) hasAnyUniqueIndex(table string) bool {
	return len(r[table]) > 0
}

// camelWordRe splits a TitleCase/camelCase Go identifier into its constituent
// words, e.g. "ActiveLegalHold" -> ["Active", "Legal", "Hold"].
var camelWordRe = regexp.MustCompile(`[A-Z][a-z0-9]*|[A-Z]+[a-z0-9]*`)

func splitCamel(s string) []string {
	return camelWordRe.FindAllString(s, -1)
}

// toSnakeCase converts a TitleCase Go identifier to snake_case, e.g.
// "SecretNode" -> "secret_node", "ExternalID" -> "external_id".
func toSnakeCase(s string) string {
	words := splitCamel(s)
	for i, w := range words {
		words[i] = strings.ToLower(w)
	}
	return strings.Join(words, "_")
}

// irregularPlurals covers the handful of struct-name stems in this codebase
// whose naive "+s" (or "+es"/"y"->"ies") pluralization would be wrong. GORM's
// actual namer uses github.com/jinzhu/inflection for this; reproducing the
// full library here isn't warranted for the small, known set of table names
// this repo actually has, but a generic pluralizer + this short list of
// exceptions keeps the mapping correct without hand-maintaining every table
// name (only the IRREGULAR ones, which is legitimately small and slow-
// changing, unlike the check-then-create site list this test also builds).
var irregularPlurals = map[string]string{
	"policy": "policies",
}

// pluralize is a minimal English pluralizer covering the noun endings that
// actually occur among this repo's model struct names (checked against every
// struct in internal/storage/models/models.go).
func pluralize(word string) string {
	if p, ok := irregularPlurals[word]; ok {
		return p
	}
	switch {
	case strings.HasSuffix(word, "y") && len(word) > 1 && !strings.ContainsRune("aeiou", rune(word[len(word)-2])):
		return word[:len(word)-1] + "ies"
	case strings.HasSuffix(word, "s"), strings.HasSuffix(word, "x"), strings.HasSuffix(word, "ch"), strings.HasSuffix(word, "sh"):
		return word + "es"
	default:
		return word + "s"
	}
}

// structNameToTable computes GORM's default table name for a struct name
// with no TableName() override: snake_case, then pluralize the LAST
// underscore-delimited word (matching jinzhu/inflection's behavior of
// pluralizing only the final word, e.g. "SecretNode" -> "secret_nodes", not
// "secret_nodeses" or "secret_node_s").
func structNameToTable(structName string) string {
	snake := toSnakeCase(structName)
	idx := strings.LastIndex(snake, "_")
	if idx == -1 {
		return pluralize(snake)
	}
	return snake[:idx+1] + pluralize(snake[idx+1:])
}

// gormColumnName computes the default GORM column name for a struct field
// with no `column:` tag override: plain snake_case of the field name (GORM
// does not pluralize column names).
func gormColumnName(fieldName string) string {
	return toSnakeCase(fieldName)
}

// buildUniqueIndexRegistry runs both registry-building passes and returns the
// combined result, plus the struct-name -> table-name map (needed by
// discoverCheckThenCreateSites' registry lookups too).
func buildUniqueIndexRegistry(t *testing.T, modelsDir, factoryFile string) (uniqueIndexRegistry, map[string]string) {
	t.Helper()
	reg := uniqueIndexRegistry{}
	tableNames := scanModelsForUniqueTags(t, modelsDir, reg)
	scanFactoryForRuntimeIndexes(t, factoryFile, reg)
	return reg, tableNames
}

// tableNameOverrideRe matches `func (StructName) TableName() string { return "literal" }`-
// shaped declarations (models.go has exactly this convention for its two
// overrides today: SoDPolicy, MachineIdentityOIDCBinding).
func scanModelsForUniqueTags(t *testing.T, modelsDir string, reg uniqueIndexRegistry) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(modelsDir)
	if err != nil {
		t.Fatalf("reading %s: %v", modelsDir, err)
	}

	fset := token.NewFileSet()
	tableNames := map[string]string{}
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(modelsDir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no .go files found under %s", modelsDir)
	}

	// Pass 1: TableName() overrides.
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != "TableName" || fd.Recv == nil || len(fd.Recv.List) != 1 {
				continue
			}
			structName := recvTypeName(fd.Recv.List[0].Type)
			if structName == "" || fd.Body == nil {
				continue
			}
			for _, stmt := range fd.Body.List {
				ret, ok := stmt.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					continue
				}
				lit, ok := ret.Results[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				tableNames[structName] = strings.Trim(lit.Value, `"`)
			}
		}
	}

	// Pass 2: every struct type -> its table name (override or computed),
	// plus every field's gorm tag scanned for uniqueIndex/unique coverage.
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			structName := ts.Name.Name
			table, ok := tableNames[structName]
			if !ok {
				table = structNameToTable(structName)
				tableNames[structName] = table
			}
			for _, field := range st.Fields.List {
				if field.Tag == nil {
					continue
				}
				tagVal := strings.Trim(field.Tag.Value, "`")
				gormTag := extractStructTagValue(tagVal, "gorm")
				if gormTag == "" || !gormTagHasUniqueness(gormTag) {
					continue
				}
				column := extractGormColumnOverride(gormTag)
				for _, name := range field.Names {
					col := column
					if col == "" {
						col = gormColumnName(name.Name)
					}
					reg.add(table, col)
				}
				// Embedded/anonymous fields with a unique tag (none exist today, but
				// don't silently drop coverage if one appears).
				if len(field.Names) == 0 && column != "" {
					reg.add(table, column)
				}
			}
			return true
		})
	}
	return tableNames
}

func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return recvTypeName(t.X)
	}
	return ""
}

// gormUniquenessRe matches the `uniqueIndex` (with or without :name/priority
// options) or bare `unique` gorm tag options that mark a column as part of a
// DB-level unique constraint.
var gormUniquenessRe = regexp.MustCompile(`(^|;)(uniqueIndex\b|unique\b)`)

func gormTagHasUniqueness(gormTag string) bool {
	return gormUniquenessRe.MatchString(gormTag)
}

// extractStructTagValue pulls the value of one key out of a raw Go struct tag
// string (e.g. `gorm:"not null;uniqueIndex" json:"name"` -> "not
// null;uniqueIndex" for key "gorm"). Minimal hand-rolled parser (avoids
// reflect.StructTag, which needs the tag as a real struct field to Get from);
// good enough for this repo's tags, which are always `key:"value"` pairs
// separated by single spaces with no escaped quotes inside gorm values.
func extractStructTagValue(tag, key string) string {
	re := regexp.MustCompile(key + `:"([^"]*)"`)
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	return m[1]
}

// extractGormColumnOverride pulls the column name out of a `column:xxx` gorm
// tag option, if present.
func extractGormColumnOverride(gormTag string) string {
	for part := range strings.SplitSeq(gormTag, ";") {
		if after, ok := strings.CutPrefix(part, "column:"); ok {
			return after
		}
	}
	return ""
}

// onTableColsRe finds a `... ON <table> (<cols>) ...` fragment within a
// db.Exec(...) call's argument text.
var onTableColsRe = regexp.MustCompile(`(?s)\bON\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)`)

// scanFactoryForRuntimeIndexes scans internal/storage/factory.go's source
// text for every `db.Exec(...)` call whose argument text builds a
// `CREATE UNIQUE INDEX ... ON <table> (<cols>) ...` statement — this repo's
// own pattern for adding a unique index to a table that might already hold
// pre-existing duplicate rows, rather than a plain gorm struct tag (see the
// package doc comment). Anchored on `db.Exec(` rather than the literal text
// "UNIQUE INDEX" because every ensure*Index helper builds the SQL from the
// shared `sqlCreateUniqueIdx` constant ("CREATE UNIQUE INDEX IF NOT EXISTS ")
// concatenated with a table-specific suffix — the literal words "UNIQUE
// INDEX" appear exactly once in the whole file, at that constant's
// definition, not at each call site. Scanning db.Exec(...) call bodies (and
// requiring EITHER the sqlCreateUniqueIdx identifier OR the literal "UNIQUE
// INDEX" text to appear inside them, so ordinary ALTER TABLE / non-unique
// CREATE INDEX Execs elsewhere in this migration file are correctly
// excluded) works on raw source text rather than go/ast because the SQL
// itself is just a Go string/string-concatenation expression, which go/ast
// would hand back as opaque, individually-useless *ast.BasicLit fragments
// anyway; scanning the literal text is both simpler and correctly
// reassembles a multi-line `+`-concatenated statement.
func scanFactoryForRuntimeIndexes(t *testing.T, factoryFile string, reg uniqueIndexRegistry) {
	t.Helper()
	b, err := os.ReadFile(factoryFile)
	if err != nil {
		t.Fatalf("reading %s: %v", factoryFile, err)
	}
	src := string(b)

	const execMarker = "db.Exec("
	found := 0
	for idx := strings.Index(src, execMarker); idx != -1; {
		start := idx + len(execMarker)
		windowEnd := min(start+500, len(src))
		window := src[start:windowEnd]
		// Stop the window at the end of this db.Exec(...) call so we never bleed
		// into the NEXT statement's unrelated "ON ..." text.
		if end := strings.Index(window, ").Error"); end != -1 {
			window = window[:end]
		}
		if strings.Contains(window, "sqlCreateUniqueIdx") || strings.Contains(window, "UNIQUE INDEX") {
			m := onTableColsRe.FindStringSubmatch(window)
			if m != nil {
				table := m[1]
				cols := splitSQLColumns(m[2])
				if len(cols) == 0 {
					reg.add(table, "")
				}
				for _, c := range cols {
					reg.add(table, c)
				}
				found++
			}
		}
		next := strings.Index(src[idx+len(execMarker):], execMarker)
		if next == -1 {
			break
		}
		idx = idx + len(execMarker) + next
	}
	if found == 0 {
		t.Fatalf("scanned %s for db.Exec(...) calls building a CREATE UNIQUE INDEX statement but extracted zero table/column pairs — the parsing regex is almost certainly broken, not that every runtime unique index was removed", factoryFile)
	}
}

// sqlColumnRe pulls the bare column identifier out of a column expression
// that may be wrapped in a SQL function call, e.g. "LOWER(email)" -> "email".
var sqlColumnRe = regexp.MustCompile(`[a-zA-Z_][a-zA-Z0-9_]*`)

func splitSQLColumns(raw string) []string {
	var cols []string
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Take the LAST identifier in the expression (handles "LOWER(email)" and
		// plain "email" uniformly; SQL function names like LOWER also match the
		// identifier regex, so the last match is the actual column).
		matches := sqlColumnRe.FindAllString(part, -1)
		if len(matches) == 0 {
			continue
		}
		cols = append(cols, matches[len(matches)-1])
	}
	return cols
}

// ---------------------------------------------------------------------------
// Part 2: check-then-create call-site discovery.
// ---------------------------------------------------------------------------

type ctcSite struct {
	File       string
	Line       int
	Func       string
	CheckCall  string
	CreateCall string
	Model      string // resolved internal/storage/models struct name; "" if unresolved
}

func (s ctcSite) key() string {
	return filepath.Base(s.File) + ":" + s.Func
}

// callSite is one Get*/Create* method call found in a function body, in
// source order.
type callSite struct {
	pos  token.Pos
	name string
	call *ast.CallExpr
}

var getCallRe = regexp.MustCompile(`^Get[A-Z]`)

func isCreateCallName(name string) bool {
	return name == "Create" || (strings.HasPrefix(name, "Create") && len(name) > len("Create") && name[len("Create")] >= 'A' && name[len("Create")] <= 'Z')
}

// collectMethodCalls returns every `<x>.Name(...)` call within body, in
// source-position order (descends into nested closures, e.g. a
// db.Transaction(func(tx *gorm.DB) error {...}) callback, since the race this
// test guards against is exactly as real inside one of those).
func collectMethodCalls(body ast.Node) []callSite {
	var calls []callSite
	ast.Inspect(body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		calls = append(calls, callSite{pos: ce.Pos(), name: sel.Sel.Name, call: ce})
		return true
	})
	sort.Slice(calls, func(i, j int) bool { return calls[i].pos < calls[j].pos })
	return calls
}

// containsWordSequence reports whether needle appears as a contiguous run
// within haystack (both already split into camelCase words).
func containsWordSequence(haystack, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j, w := range needle {
			if haystack[i+j] != w {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// discoverCheckThenCreateSites walks every non-test .go file directly under
// each of dirs and returns every discovered check-then-create call site.
func discoverCheckThenCreateSites(t *testing.T, fset *token.FileSet, dirs ...string) []ctcSite {
	t.Helper()
	var sites []ctcSite
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			sites = append(sites, findSitesInFile(fset, f, path)...)
		}
	}
	return sites
}

func findSitesInFile(fset *token.FileSet, f *ast.File, path string) []ctcSite {
	var sites []ctcSite
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		calls := collectMethodCalls(fn.Body)

		for ci, create := range slices.Backward(calls) {

			if !isCreateCallName(create.name) {
				continue
			}
			model := resolveEntityModel(create.call, fn)

			var stemWords []string
			if create.name != "Create" {
				stemWords = splitCamel(strings.TrimPrefix(create.name, "Create"))
			} else if model != "" {
				stemWords = splitCamel(model)
			}
			if len(stemWords) == 0 {
				continue
			}

			// Nearest preceding Get* call whose name contains stemWords as a
			// contiguous run.
			var matched *callSite
			for pi := ci - 1; pi >= 0; pi-- {
				prev := calls[pi]
				if prev.pos >= create.pos || !getCallRe.MatchString(prev.name) {
					continue
				}
				checkWords := splitCamel(strings.TrimPrefix(prev.name, "Get"))
				if containsWordSequence(checkWords, stemWords) {
					matched = &calls[pi]
					break
				}
			}
			if matched == nil {
				continue
			}

			pos := fset.Position(create.pos)
			sites = append(sites, ctcSite{
				File:       path,
				Line:       pos.Line,
				Func:       fn.Name.Name,
				CheckCall:  matched.name,
				CreateCall: create.name,
				Model:      model,
			})
		}
	}
	return sites
}

// resolveEntityModel finds the internal/storage/models struct type of
// create's target row by tracing its arguments: a composite literal
// (`&models.X{...}` or `models.X{...}`) either inline in the call, or
// assigned to a variable (function parameter, `:=`, or `var`) earlier in fn.
func resolveEntityModel(call *ast.CallExpr, fn *ast.FuncDecl) string {
	for _, arg := range call.Args {
		if name := modelTypeOfExpr(arg, fn); name != "" {
			return name
		}
	}
	return ""
}

func modelTypeOfExpr(expr ast.Expr, fn *ast.FuncDecl) string {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return modelTypeOfExpr(e.X, fn)
		}
	case *ast.CompositeLit:
		return modelsSelectorName(e.Type)
	case *ast.Ident:
		if fn.Type.Params != nil {
			for _, field := range fn.Type.Params.List {
				for _, n := range field.Names {
					if n.Name == e.Name {
						if name := modelsSelectorNameFromTypeExpr(field.Type); name != "" {
							return name
						}
					}
				}
			}
		}
		found := ""
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if found != "" {
				return false
			}
			switch s := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || id.Name != e.Name || i >= len(s.Rhs) {
						continue
					}
					if name := modelTypeOfExpr(s.Rhs[i], fn); name != "" {
						found = name
					}
				}
			case *ast.ValueSpec:
				for i, id := range s.Names {
					if id.Name != e.Name {
						continue
					}
					if s.Type != nil {
						if name := modelsSelectorNameFromTypeExpr(s.Type); name != "" {
							found = name
						}
					} else if i < len(s.Values) {
						if name := modelTypeOfExpr(s.Values[i], fn); name != "" {
							found = name
						}
					}
				}
			}
			return found == ""
		})
		return found
	}
	return ""
}

func modelsSelectorNameFromTypeExpr(t ast.Expr) string {
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	return modelsSelectorName(t)
}

func modelsSelectorName(t ast.Expr) string {
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "models" {
		return ""
	}
	return sel.Sel.Name
}

// ---------------------------------------------------------------------------
// Part 3: allowlist + the test itself.
// ---------------------------------------------------------------------------

// checkThenCreateAllowlist is the exhaustive, reasoned list of check-then-
// create sites that are deliberately NOT backed by a database-level unique
// index. Empty today: every check-then-create site this heuristic currently
// discovers on main is already index-backed (that's the negative control —
// #117/#121/#136/#305/#309/#313/#462/MT-006 are all fixed). Add an entry only
// for a genuinely reasoned exception (e.g. a natural key intentionally
// enforced by an application-level lock instead of a DB constraint — see the
// false-negative/false-positive discussion in this file's package doc
// comment for why that combination is NOT something this heuristic can
// verify on its own, so an allowlist entry for it needs a human-checked
// reason, not just "the check exists").
var checkThenCreateAllowlist = map[string]string{
	// "<file basename>:<enclosing func name>": "reason",
}

func TestCheckThenCreateSitesAreUniqueIndexBacked(t *testing.T) {
	thisFile := filepath.Join(srcpath.PkgDir(), "checkthencreate_race_completeness_test.go")
	storeDir := filepath.Dir(thisFile)
	storageDir := filepath.Join(storeDir, "..")
	modelsDir := filepath.Join(storageDir, "models")
	factoryFile := filepath.Join(storageDir, "factory.go")
	coreDir := filepath.Join(storeDir, "..", "..", "core")

	registry, tableNames := buildUniqueIndexRegistry(t, modelsDir, factoryFile)

	fset := token.NewFileSet()
	sites := discoverCheckThenCreateSites(t, fset, coreDir, storeDir)

	if len(sites) == 0 {
		t.Fatal("discovered zero check-then-create sites across internal/core and internal/storage/store — the AST walk is almost certainly broken (CreateSecret/GetSecretByName in internal/core/secrets.go alone should match), not that every check-then-create pattern was rewritten away")
	}

	var violations []string
	var unresolved []string
	for _, s := range sites {
		if s.Model == "" {
			unresolved = append(unresolved, formatSite(s)+" (model type not statically resolved)")
			continue
		}
		table, ok := tableNames[s.Model]
		if !ok {
			table = structNameToTable(s.Model)
		}
		if registry.hasAnyUniqueIndex(table) {
			continue
		}
		if reason, ok := checkThenCreateAllowlist[s.key()]; ok {
			t.Logf("allowlisted check-then-create site %s (table %q has no unique index): %s", formatSite(s), table, reason)
			continue
		}
		violations = append(violations, formatSite(s)+
			": model "+s.Model+" / table "+table+" has NO unique index (gorm uniqueIndex tag or factory.go ensure*Index)")
	}
	sort.Strings(violations)
	sort.Strings(unresolved)

	if len(unresolved) > 0 {
		t.Logf("%d check-then-create site(s) found but their model type could not be statically resolved (skipped, not failed — see false-negative note in this file's doc comment):\n%s",
			len(unresolved), strings.Join(unresolved, "\n"))
	}

	if len(violations) > 0 {
		t.Errorf("found %d check-then-create site(s) (existence check via a Get*-shaped call, followed by a Create call) whose target model's table has NO database-level unique index, and which are not in checkThenCreateAllowlist:\n%s\n"+
			"Two concurrent callers can both pass the check before either commits, creating duplicate rows for what should be a unique natural key (this repo's own history: #117/#121/#136/#305/#309/#313/#462/MT-006). "+
			"Fix by adding a unique index — either a `uniqueIndex` gorm struct tag in internal/storage/models/models.go (safe only for a table that can never already hold duplicates), or, for an existing table, a runtime "+
			"ensure<X>Index helper in internal/storage/factory.go following the warnIfDuplicatesExist + partial-unique-index pattern the fixes above all use — then translate the resulting constraint violation into a clean "+
			"sentinel error at the storage layer. If this site is a deliberate, reasoned exception, add it to checkThenCreateAllowlist with a comment explaining why.",
			len(violations), strings.Join(violations, "\n"))
	}
}

func formatSite(s ctcSite) string {
	return filepath.Base(s.File) + ":" + strconv.Itoa(s.Line) + " " + s.Func + "() [" + s.CheckCall + " -> " + s.CreateCall + "]"
}
