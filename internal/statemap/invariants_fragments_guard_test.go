// invariants_fragments_guard_test.go — the doc guard for every package's
// INVARIANTS.md (CLAUDE.md "Read the package's INVARIANTS.md before changing
// its code"; index: docs/INVARIANTS.md; convention:
// docs/invariants-fragments.md).
//
// Before this file, NOTHING read any INVARIANTS.md: the "one ID, one rule"
// property every entry relies on was asserted, not checked, and it had
// already decayed — internal/core/INVARIANTS.md on main defines INV-CORE-41
// twice (two different rules, landed by two PRs that each appended "the next
// number"). Several open PRs at the time of writing append INV-CORE-41/42
// again. Fragments (`<pkg>/INVARIANTS.d/<ID>.md`, one invariant per file,
// collision-free slug IDs) remove the shared-file merge conflict; this guard
// removes the silent-duplicate failure mode for both layouts.
//
// It lives in internal/statemap (an existing, fast, repo-wide static-analysis
// package already run by CI's root catch-all leg and already listed in
// docs/review-coverage.tsv) so it adds no new Go package.
//
// What it checks, for every directory holding an INVARIANTS.md (except the
// docs/INVARIANTS.md index) plus every INVARIANTS.d/ directory:
//
//	(a) no invariant ID is defined twice where at least one definition is an
//	    INVARIANTS.d/ fragment (fragment vs fragment, or fragment vs legacy
//	    bullet). A duplicate purely among legacy INVARIANTS.md bullets is NOT
//	    a failure: it is reported via t.Log as "LEGACY DUPLICATE". This is
//	    deliberate — ~50 open PRs append numbered bullets to the legacy files,
//	    several already reuse IDs (INV-CORE-41/42, INV-STORE-21), and failing
//	    on those would block the merge queue this layout exists to unblock.
//	    Legacy duplicates become fatal at migration time instead:
//	    scripts/ledgers/migrate-invariants-to-fragments.sh refuses to migrate
//	    a package holding one, and a migrated package has every ID in a
//	    fragment, where this rule applies in full;
//	(b) a fragment defines exactly one bold `**INV-...**` ID, as its first
//	    line, in the package bullet shape `- **<ID>** ...`;
//	(c) a fragment's ID equals its file name minus `.md`, and every ID (legacy
//	    or fragment) carries the package prefix declared by the package
//	    file's own `Format: \`INV-<PKG>-NN ...\`` line; a fragment ID is either
//	    legacy-numeric (a migrated entry) or a lowercase kebab slug;
//	(d) an INVARIANTS.d/ directory has a sibling INVARIANTS.md (no orphans),
//	    and contains only `*.md` fragment files;
//	(e) every NEW (slug-ID) fragment states `Guard:` or `UNGUARDED`. Not
//	    applied to legacy bullets, nor to legacy-numbered fragments produced
//	    by migrating them, because it does not hold on main: when this landed
//	    six legacy bullets state neither (INV-CLI-02, INV-CLI-12, INV-CORE-41
//	    [the second one; it says "Guard (regression...)"], INV-ENCRYPTION-26,
//	    INV-STORAGE-33, INV-GRPC-06 — mostly "not a gap, by design" entries).
//	    Enforcing it repo-wide would need those reworded first, in files that
//	    many open PRs touch;
//	(f) an optional `<!-- section: <heading> -->` line in a fragment names a
//	    `## ` heading that exists in the sibling INVARIANTS.md.
//
// What it does NOT check: that a named guard test exists or passes (that is
// scripts/check-closures.sh's / check-adr-conformance.sh's job for ledgered
// claims); that an UNGUARDED issue number is real or open; that the
// hand-maintained counts table in docs/INVARIANTS.md is correct; anything
// about bold `**INV-...**` text that is not at the start of a list item in a
// legacy INVARIANTS.md (only list-item definitions are recognised there — the
// recognised shapes are `- **ID**` and `* **ID**`, at any indentation).
package statemap

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

const invariantsIndexPath = "docs/INVARIANTS.md"

var (
	// A definition in a legacy INVARIANTS.md: a list item opening with a bold ID.
	invDefLineRE = regexp.MustCompile(`^\s*[-*]\s+\*\*(INV-[^*\s]+)\*\*`)
	// Any bold ID anywhere (used to count definitions in a fragment).
	invBoldIDRE = regexp.MustCompile(`\*\*(INV-[^*\s]+)\*\*`)
	// The package's declared prefix: Format: `INV-CORE-NN ...`.
	invFormatRE  = regexp.MustCompile("(?m)^Format: `(INV-[A-Z]+)-NN\\b")
	invSectionRE = regexp.MustCompile(`^<!-- section: (.+?) -->$`)
	invHeadingRE = regexp.MustCompile(`^## (.+?)\s*$`)
	// Suffix after the package prefix: legacy numeric, or a kebab slug that
	// starts with a letter.
	invNumericSuffixRE = regexp.MustCompile(`^[0-9]{2,}$`)
	invSlugSuffixRE    = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
)

type invDef struct {
	id       string
	fragment bool
	file     string // fsys-relative path
	line     int
}

// skipDirForInvariants prunes trees that are not this repo's source.
func skipDirForInvariants(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", ".next":
		return true
	}
	return false
}

// checkInvariantDocs returns one human-readable violation per problem found
// in fsys (rooted at the repo root) — an empty result means green — plus the
// non-fatal legacy-only duplicates (see rule (a)), both sorted.
func checkInvariantDocs(fsys fs.FS) (violations, legacyDups []string, err error) {
	add := func(format string, args ...any) { violations = append(violations, fmt.Sprintf(format, args...)) }

	pkgFiles := map[string]bool{} // dir -> has INVARIANTS.md
	fragDirs := map[string]bool{} // dir (parent of INVARIANTS.d) -> true
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && skipDirForInvariants(d.Name()) {
				return fs.SkipDir
			}
			if d.Name() == "INVARIANTS.d" {
				fragDirs[path.Dir(p)] = true
			}
			return nil
		}
		if d.Name() == "INVARIANTS.md" {
			pkgFiles[path.Dir(p)] = true
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	defsByID := map[string][]invDef{}
	record := func(d invDef) { defsByID[d.id] = append(defsByID[d.id], d) }

	checkIDShape := func(id, prefix, where string, fragment bool) {
		if !strings.HasPrefix(id, prefix+"-") {
			add("%s: invariant ID %s does not carry this package's prefix %s- (declared by its INVARIANTS.md Format: line)", where, id, prefix)
			return
		}
		suffix := strings.TrimPrefix(id, prefix+"-")
		if invNumericSuffixRE.MatchString(suffix) {
			return
		}
		if fragment && invSlugSuffixRE.MatchString(suffix) {
			return
		}
		if fragment {
			add("%s: invariant ID %s: suffix %q is neither a legacy number nor a lowercase kebab slug (e.g. %s-mfa-purpose-binding)", where, id, suffix, prefix)
		} else {
			add("%s: invariant ID %s: legacy INVARIANTS.md entries use %s-NN; slug IDs belong in INVARIANTS.d/ fragments", where, id, prefix)
		}
	}

	dirs := make([]string, 0, len(pkgFiles))
	for d := range pkgFiles {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		file := path.Join(dir, "INVARIANTS.md")
		raw, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, nil, err
		}
		content := string(raw)
		lines := strings.Split(content, "\n")

		if file == invariantsIndexPath {
			for i, l := range lines {
				if m := invDefLineRE.FindStringSubmatch(l); m != nil {
					add("%s:%d: the index must not define invariants (%s) — define it in its package's INVARIANTS.md or INVARIANTS.d/", file, i+1, m[1])
				}
			}
			if fragDirs[dir] {
				add("%s: docs/INVARIANTS.d/ is not allowed — the index has no package prefix", path.Join(dir, "INVARIANTS.d"))
			}
			continue
		}

		fm := invFormatRE.FindStringSubmatch(content)
		if fm == nil {
			add("%s: no `Format: \\`INV-<PKG>-NN ...\\`` line — the package prefix cannot be derived", file)
			continue
		}
		prefix := fm[1]

		headings := map[string]bool{}
		for i := range lines {
			if h := invHeadingRE.FindStringSubmatch(lines[i]); h != nil {
				headings[h[1]] = true
			}
			m := invDefLineRE.FindStringSubmatch(lines[i])
			if m == nil {
				continue
			}
			where := fmt.Sprintf("%s:%d", file, i+1)
			id := m[1]
			record(invDef{id: id, file: file, line: i + 1})
			checkIDShape(id, prefix, where, false)
			// (e) is not applied to legacy bullets — see the file comment.
		}

		if !fragDirs[dir] {
			continue
		}
		fdir := path.Join(dir, "INVARIANTS.d")
		entries, err := fs.ReadDir(fsys, fdir)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range entries {
			fp := path.Join(fdir, e.Name())
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				add("%s: INVARIANTS.d/ may contain only <ID>.md fragment files", fp)
				continue
			}
			fraw, err := fs.ReadFile(fsys, fp)
			if err != nil {
				return nil, nil, err
			}
			fcontent := string(fraw)
			ids := invBoldIDRE.FindAllStringSubmatch(fcontent, -1)
			if len(ids) != 1 {
				got := make([]string, 0, len(ids))
				for _, m := range ids {
					got = append(got, m[1])
				}
				add("%s: a fragment must define exactly one **INV-...** ID, found %d %v", fp, len(ids), got)
				continue
			}
			id := ids[0][1]
			flines := strings.Split(strings.TrimLeft(fcontent, "\n"), "\n")
			if !strings.HasPrefix(flines[0], "- **"+id+"**") {
				add("%s: the first line must be the definition bullet `- **%s** <rule>. Why: ... Guard: ... | UNGUARDED (#issue)`", fp, id)
			}
			if want := strings.TrimSuffix(e.Name(), ".md"); want != id {
				add("%s: fragment defines %s but its file name says %s — the file name must equal the ID", fp, id, want)
			}
			checkIDShape(id, prefix, fp, true)
			record(invDef{id: id, file: fp, line: 1, fragment: true})
			isSlug := invSlugSuffixRE.MatchString(strings.TrimPrefix(id, prefix+"-"))
			if isSlug && !strings.Contains(fcontent, "Guard:") && !strings.Contains(fcontent, "UNGUARDED") {
				add("%s: %s states neither `Guard:` nor `UNGUARDED`", fp, id)
			}
			for _, l := range flines {
				if s := invSectionRE.FindStringSubmatch(strings.TrimSpace(l)); s != nil && !headings[s[1]] {
					add("%s: section marker %q names no `## %s` heading in %s", fp, s[1], s[1], file)
				}
			}
		}
	}

	for dir := range fragDirs {
		if !pkgFiles[dir] {
			add("%s: orphan INVARIANTS.d/ — no sibling INVARIANTS.md declares this package's prefix", path.Join(dir, "INVARIANTS.d"))
		}
	}

	ids := make([]string, 0, len(defsByID))
	for id := range defsByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		defs := defsByID[id]
		if len(defs) < 2 {
			continue
		}
		locs := make([]string, 0, len(defs))
		anyFragment := false
		for _, d := range defs {
			locs = append(locs, fmt.Sprintf("%s:%d", d.file, d.line))
			anyFragment = anyFragment || d.fragment
		}
		if !anyFragment {
			legacyDups = append(legacyDups, fmt.Sprintf("LEGACY DUPLICATE (not failing until migration; renumber as a slug fragment): %s defined %d times: %s", id, len(defs), strings.Join(locs, ", ")))
			continue
		}
		add("duplicate invariant ID %s defined %d times: %s — give the newer one a collision-free slug ID (see docs/invariants-fragments.md)", id, len(defs), strings.Join(locs, ", "))
	}
	sort.Strings(violations)
	sort.Strings(legacyDups)
	return violations, legacyDups, nil
}

// invariantsRepoRoot walks up from the test's working directory to the
// directory holding both the root module's go.mod and .git.
func invariantsRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil &&
			strings.Contains(string(b), "module github.com/keyorixhq/keyorix\n") {
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate the keyorix repo root (go.mod for module github.com/keyorixhq/keyorix next to .git) above the test's working directory")
		}
		dir = parent
	}
}

// TestInvariantDocs_RealRepo is the green half: the real tree must pass.
func TestInvariantDocs_RealRepo(t *testing.T) {
	root := invariantsRepoRoot(t)
	v, legacy, err := checkInvariantDocs(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range legacy {
		t.Log(s)
	}
	for _, s := range v {
		t.Error(s)
	}
	// Floor: the scanner must actually be seeing the package files — an empty
	// walk would be green for the wrong reason.
	n := 0
	_ = fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && p != "." && skipDirForInvariants(d.Name()) {
			return fs.SkipDir
		}
		if err == nil && !d.IsDir() && d.Name() == "INVARIANTS.md" {
			n++
		}
		return nil
	})
	if n < 12 {
		t.Errorf("expected >=12 INVARIANTS.md files (11 packages + the docs index), walked %d", n)
	}
}

// --- red/green fixtures for every rejection path -----------------------------

const fixturePkg = "# pkg invariants\n\nFormat: `INV-PKG-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.\n\n" +
	"## Section A\n\n- **INV-PKG-01** Rule one. Why: x. Guard:\n  `TestOne`.\n- **INV-PKG-02** Rule two. UNGUARDED (#1).\n"

func fixtureFS(extra map[string]string) fstest.MapFS {
	m := fstest.MapFS{
		"docs/INVARIANTS.md": {Data: []byte("# index\n\n| Package |\n")},
		"pkg/INVARIANTS.md":  {Data: []byte(fixturePkg)},
		"pkg/INVARIANTS.d/INV-PKG-mfa-purpose-binding.md": {Data: []byte(
			"- **INV-PKG-mfa-purpose-binding** Rule. Why: y. Guard: `TestX`.\n<!-- section: Section A -->\n")},
	}
	for k, v := range extra {
		if v == "" {
			delete(m, k)
			continue
		}
		m[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return m
}

func TestInvariantDocs_Fixtures(t *testing.T) {
	cases := []struct {
		name    string
		extra   map[string]string
		want    string // substring of the single expected violation; "" = green
		wantLog string // substring of the single expected legacy-duplicate log line
	}{
		{name: "green baseline"},
		{name: "green: migrated numeric fragment", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-03.md": "- **INV-PKG-03** Three. UNGUARDED (#2).\n"}},
		{name: "duplicate fragment vs legacy", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-01.md": "- **INV-PKG-01** Again. Guard: `T`.\n"},
			want: "duplicate invariant ID INV-PKG-01 defined 2 times"},
		{name: "green: duplicate purely among legacy bullets is logged, not fatal", extra: map[string]string{
			"pkg/INVARIANTS.md": fixturePkg + "- **INV-PKG-02** Dup. Guard: `T`.\n"},
			wantLog: "LEGACY DUPLICATE (not failing until migration; renumber as a slug fragment): INV-PKG-02 defined 2 times: pkg/INVARIANTS.md:9, pkg/INVARIANTS.md:10"},
		{name: "two fragments defining the same ID", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-twin.md":  "- **INV-PKG-twin** R. Guard: `T`.\n",
			"pkg/INVARIANTS.d/INV-PKG-twin2.md": "- **INV-PKG-twin** S. Guard: `T`.\n"},
			want: "duplicate invariant ID INV-PKG-twin defined 2 times"},
		{name: "fragment duplicating a legacy-duplicated ID still fails", extra: map[string]string{
			"pkg/INVARIANTS.md":              fixturePkg + "- **INV-PKG-02** Dup. Guard: `T`.\n",
			"pkg/INVARIANTS.d/INV-PKG-02.md": "- **INV-PKG-02** Third. Guard: `T`.\n"},
			want: "duplicate invariant ID INV-PKG-02 defined 3 times"},
		{name: "fragment name mismatch", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-other.md": "- **INV-PKG-something** R. Guard: `T`.\n"},
			want: "file name must equal the ID"},
		{name: "fragment with two IDs", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-two.md": "- **INV-PKG-two** R. Guard: `T`.\n- **INV-PKG-three** S. Guard: `T`.\n"},
			want: "exactly one **INV-...** ID, found 2"},
		{name: "fragment with zero IDs", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-none.md": "- INV-PKG-none R. Guard: `T`.\n"},
			want: "exactly one **INV-...** ID, found 0"},
		{name: "fragment wrong prefix", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-CORE-foo.md": "- **INV-CORE-foo** R. Guard: `T`.\n"},
			want: "does not carry this package's prefix INV-PKG-"},
		{name: "fragment bad slug", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-Foo_Bar.md": "- **INV-PKG-Foo_Bar** R. Guard: `T`.\n"},
			want: "neither a legacy number nor a lowercase kebab slug"},
		{name: "fragment not starting with the bullet", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-late.md": "Intro.\n- **INV-PKG-late** R. Guard: `T`.\n"},
			want: "first line must be the definition bullet"},
		{name: "orphan INVARIANTS.d", extra: map[string]string{
			"lonely/INVARIANTS.d/INV-X-a.md": "- **INV-X-a** R. Guard: `T`.\n"},
			want: "lonely/INVARIANTS.d: orphan INVARIANTS.d/"},
		{name: "non-md file in INVARIANTS.d", extra: map[string]string{
			"pkg/INVARIANTS.d/notes.txt": "x\n"},
			want: "may contain only <ID>.md fragment files"},
		{name: "fragment missing Guard/UNGUARDED", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-bare.md": "- **INV-PKG-bare** R. Why: z.\n"},
			want: "INV-PKG-bare states neither `Guard:` nor `UNGUARDED`"},
		{name: "green: legacy bullet missing Guard/UNGUARDED is not checked (rule (e) is slug-fragments only)", extra: map[string]string{
			"pkg/INVARIANTS.md": fixturePkg + "- **INV-PKG-04** Bare rule. Why: z.\n"}},
		{name: "green: migrated numeric fragment missing Guard/UNGUARDED is not checked", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-05.md": "- **INV-PKG-05** Bare rule. Why: z. Not a gap.\n"}},
		{name: "legacy slug ID", extra: map[string]string{
			"pkg/INVARIANTS.md": fixturePkg + "- **INV-PKG-slug** R. Guard: `T`.\n"},
			want: "slug IDs belong in INVARIANTS.d/ fragments"},
		{name: "unknown section marker", extra: map[string]string{
			"pkg/INVARIANTS.d/INV-PKG-sec.md": "- **INV-PKG-sec** R. Guard: `T`.\n<!-- section: Nope -->\n"},
			want: `section marker "Nope" names no`},
		{name: "missing Format line", extra: map[string]string{
			"pkg/INVARIANTS.md": strings.Replace(fixturePkg, "Format:", "Shape:", 1)},
			want: "the package prefix cannot be derived"},
		{name: "index defines an invariant", extra: map[string]string{
			"docs/INVARIANTS.md": "# index\n- **INV-PKG-09** R. Guard: `T`.\n"},
			want: "the index must not define invariants"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, legacy, err := checkInvariantDocs(fixtureFS(tc.extra))
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantLog == "" && len(legacy) != 0 {
				t.Fatalf("want no legacy-duplicate log lines, got:\n%s", strings.Join(legacy, "\n"))
			}
			if tc.wantLog != "" && (len(legacy) != 1 || !strings.Contains(legacy[0], tc.wantLog)) {
				t.Fatalf("want exactly one legacy-duplicate log line containing %q, got %d:\n%s", tc.wantLog, len(legacy), strings.Join(legacy, "\n"))
			}
			if tc.want == "" {
				if len(v) != 0 {
					t.Fatalf("want green, got %d violation(s):\n%s", len(v), strings.Join(v, "\n"))
				}
				return
			}
			// The two-fragments-same-ID case necessarily also trips "file name
			// must equal the ID" for one of the two files; require the expected
			// violation to be present and every other one to be that.
			found := false
			for _, s := range v {
				if strings.Contains(s, tc.want) {
					found = true
				} else if !strings.Contains(s, "file name must equal the ID") || !strings.Contains(tc.want, "duplicate") {
					t.Errorf("unexpected extra violation: %s", s)
				}
			}
			if !found {
				t.Fatalf("want a violation containing %q, got %d:\n%s", tc.want, len(v), strings.Join(v, "\n"))
			}
		})
	}
}
