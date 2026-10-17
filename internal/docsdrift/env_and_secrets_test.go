package docsdrift

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// DOCS-DRIFT-1 item 3: environment variables and secret hygiene.
//
// TestDocsEnvVarsExist: every KEYORIX_* name a command doc mentions must occur
// in the repository's non-test code. The set is built here, by scanning the
// sources, not restated: *.go (all modules, including cli/ and server/, read as
// text, nothing imported), plus the deployment files that read variables the Go
// code never sees (shell scripts such as server/entrypoint.sh, Dockerfiles,
// compose and Helm YAML/templates, nginx templates). _test.go files, docs/ and
// vendored trees do not count: a variable only a test reads is not something an
// operator can rely on. Names ending in "_" (KEYORIX_SSO_, a prefix pattern in
// prose) are not variables and are skipped.
//
// What it does not check: that the code reads the variable in the way the doc
// says (a variable that exists but is read by a different component, or only as
// a documented fallback, passes), and variables written without the KEYORIX_
// prefix.

var envVarName = regexp.MustCompile(`KEYORIX_[A-Z0-9_]*[A-Z0-9]`)

// envVarSkipDirs are directories whose files are not product code.
var envVarSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "docs": true, "vendor": true, "testdata": true,
	".scratch": true, ".claude": true, "changelog.d": true, ".gocache": true, ".gopath": true,
}

func envVarSourceFile(name string) bool {
	if strings.HasSuffix(name, "_test.go") {
		return false
	}
	switch filepath.Ext(name) {
	case ".go", ".sh", ".yml", ".yaml", ".tpl", ".conf", ".template", ".txt", ".toml":
		return true
	}
	return strings.HasPrefix(name, "Dockerfile") || name == "Makefile"
}

// envVarFamilies are variable names the code builds at run time from a quoted
// prefix and a suffix ("KEYORIX_SSO_"+upper(name)+"_CLIENT_SECRET"), so no
// source contains the full name. A documented name matches a family when it has
// the prefix and suffix AND a source file contains the quoted prefix literal.
var envVarFamilies = []struct{ Prefix, Suffix string }{
	{"KEYORIX_SSO_", "_CLIENT_SECRET"},
}

var envVarPrefixLiteral = regexp.MustCompile(`"(KEYORIX_[A-Z0-9_]*_)"`)

// codeEnvVars returns every KEYORIX_* name that occurs in the repo's sources,
// and the quoted prefix literals ("KEYORIX_SSO_") used to build names.
func codeEnvVars(t testing.TB) (names, prefixes map[string]bool) {
	t.Helper()
	root := repoRoot(t)
	out := map[string]bool{}
	prefixes = map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if envVarSkipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !envVarSourceFile(d.Name()) {
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 -- walking the repo
		if err != nil {
			return nil
		}
		for _, m := range envVarName.FindAll(b, -1) {
			out[string(m)] = true
		}
		for _, m := range envVarPrefixLiteral.FindAllSubmatch(b, -1) {
			prefixes[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out, prefixes
}

// withFamilies returns known plus every documented name that a family produces.
func withFamilies(known, prefixes map[string]bool, docNames []string) map[string]bool {
	out := maps.Clone(known)
	for _, n := range docNames {
		for _, f := range envVarFamilies {
			if prefixes[f.Prefix] && strings.HasPrefix(n, f.Prefix) && strings.HasSuffix(n, f.Suffix) {
				out[n] = true
			}
		}
	}
	return out
}

type envFinding struct {
	Doc  string
	Line int
	Name string
}

// findUnknownEnvVars reports each KEYORIX_* mention in doc that is not in known.
func findUnknownEnvVars(docName, doc string, known map[string]bool) []envFinding {
	var out []envFinding
	for n, line := range strings.Split(doc, "\n") {
		for _, loc := range envVarName.FindAllStringIndex(line, -1) {
			name := line[loc[0]:loc[1]]
			if loc[1] < len(line) && line[loc[1]] == '_' { // KEYORIX_SSO_<NAME> pattern
				continue
			}
			if !known[name] {
				out = append(out, envFinding{docName, n + 1, name})
			}
		}
	}
	return out
}

func TestDocsEnvVarsExist(t *testing.T) {
	code, prefixes := codeEnvVars(t)
	if !code["KEYORIX_MASTER_PASSWORD"] || !code["KEYORIX_CONFIG_PATH"] || !prefixes["KEYORIX_SSO_"] || len(code) < 40 {
		t.Fatalf("env var scan found %d names (prefixes %v) without KEYORIX_MASTER_PASSWORD/KEYORIX_CONFIG_PATH/KEYORIX_SSO_: the scanner has drifted", len(code), prefixes)
	}
	checked := 0
	for _, rel := range commandDocs(t) {
		doc := readDoc(t, rel)
		mentions := envVarName.FindAllString(doc, -1)
		checked += len(mentions)
		known := withFamilies(code, prefixes, mentions)
		for _, f := range findUnknownEnvVars(rel, doc, known) {
			t.Errorf("%s:%d: %s is not used by any non-test source in the repository", f.Doc, f.Line, f.Name)
		}
	}
	t.Logf("%d KEYORIX_* mentions checked against %d names found in the sources", checked, len(code))
}

func TestDocsEnvVarsCheckCatchesPlantedError(t *testing.T) {
	known := map[string]bool{"KEYORIX_MASTER_PASSWORD": true}
	doc := "export KEYORIX_MASTER_PASSWORD_FILE=/x\nexport KEYORIX_MASTER_PASSWORD=y\nKEYORIX_SSO_<NAME>_SECRET\n"
	got := findUnknownEnvVars("planted.md", doc, known)
	if len(got) != 1 || got[0].Name != "KEYORIX_MASTER_PASSWORD_FILE" || got[0].Line != 1 {
		t.Fatalf("findings = %+v, want exactly KEYORIX_MASTER_PASSWORD_FILE on line 1", got)
	}
}

// Secret hygiene in commands.
//
// A secret given as a flag value lands in argv, visible to every local user in
// ps and /proc and kept in shell history. The product's own commands refuse it
// (recover-admin demands "-" for stdin; passphrases take -file/-fd/-stdin), so a
// doc that shows one is teaching a practice the code rejects or discourages.
// TestDocsDoNotPutSecretsInFlags flags, in fenced lines and inline spans, any
// --flag whose name says it carries a secret (password, passphrase, token,
// secret, api-key, recovery-key) and which is not a file/fd/stdin/path
// indirection, when it is given a value other than "-" (stdin).
//
// TestDocsDoNotMakeSecretFilesReadable flags a chmod (or mkdir -m) in those
// lines that gives group or other any permission on a path that names a secret
// (password, passphrase, token, secret, key, kek, master) or a backup: the
// `admin backup` archive bundles the database and the wrapped key files.
//
// Not checked: secrets in environment-variable assignments on the command line
// (documented fallbacks, visible in /proc/<pid>/environ to the same user only),
// secrets in config YAML examples, and prose that is not backticked.

var (
	secretFlag        = regexp.MustCompile(`^--?([a-z][a-z0-9-]*)(=(.*))?$`)
	secretFlagWords   = regexp.MustCompile(`(password|passphrase|token|secret|api-key|recovery-key|private-key)`)
	secretFlagSafe    = regexp.MustCompile(`(-file|-fd|-stdin|-path|-dir|-env|-name|-ttl|-id|-type|-length|-bytes)$`)
	chmodOctal        = regexp.MustCompile(`^[0-7]*([0-7])([0-7])$`)
	chmodSymbolic     = regexp.MustCompile(`^[ugoa]*[go][ugoa]*[+=][rwxXst]+`)
	secretPathHint    = regexp.MustCompile(`(?i)(password|passphrase|token|secret|\bkey\b|\.key|kek|master|backup)`)
	commandLineTokens = regexp.MustCompile(`\S+`)
)

// commandLines returns the fenced lines (continuations joined, comments cut) and
// backticked inline spans of a document, with 1-based line numbers.
func commandLines(doc string) (lines []string, nums []int) {
	joined := strings.ReplaceAll(doc, "\\\n", " ")
	inFence := false
	for n, line := range strings.Split(joined, "\n") {
		trim := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), ">"))
		if strings.HasPrefix(trim, "```") || strings.HasPrefix(trim, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			if strings.HasPrefix(trim, "#") {
				continue
			}
			if i := strings.Index(trim, " #"); i >= 0 {
				trim = strings.TrimSpace(trim[:i])
			}
			lines = append(lines, trim)
			nums = append(nums, n+1)
			continue
		}
		for _, m := range regexp.MustCompile("`([^`\n]+)`").FindAllStringSubmatch(line, -1) {
			lines = append(lines, m[1])
			nums = append(nums, n+1)
		}
	}
	return lines, nums
}

type secretFinding struct {
	Doc  string
	Line int
	What string
}

func findSecretFlags(docName, doc string) []secretFinding {
	var out []secretFinding
	lines, nums := commandLines(doc)
	for i, line := range lines {
		toks := commandLineTokens.FindAllString(line, -1)
		for j, tk := range toks {
			m := secretFlag.FindStringSubmatch(strings.Trim(tk, `"'`))
			if m == nil || !secretFlagWords.MatchString(m[1]) || secretFlagSafe.MatchString(m[1]) {
				continue
			}
			value, has := m[3], m[2] != ""
			if !has && j+1 < len(toks) && !strings.HasPrefix(toks[j+1], "-") {
				value, has = toks[j+1], true
			}
			if has && strings.Trim(value, `"'`) != "-" {
				out = append(out, secretFinding{docName, nums[i], "flag " + tk + " is given a value; a secret passed as a flag value is visible in ps and shell history (use a *-file, fd or stdin form)"})
			}
		}
	}
	return out
}

func findWorldReadableSecretFiles(docName, doc string) []secretFinding {
	var out []secretFinding
	lines, nums := commandLines(doc)
	for i, line := range lines {
		toks := commandLineTokens.FindAllString(line, -1)
		for j, tk := range toks {
			if tk != "chmod" && tk != "mkdir" {
				continue
			}
			rest := toks[j+1:]
			if tk == "mkdir" { // mkdir -m MODE dir: only the -m form carries a mode
				if len(rest) < 3 || rest[0] != "-m" {
					continue
				}
				rest = rest[1:]
			}
			for len(rest) > 0 && strings.HasPrefix(rest[0], "-") { // chmod -R ...
				rest = rest[1:]
			}
			if len(rest) < 2 {
				continue
			}
			mode := rest[0]
			path := strings.Join(rest[1:], " ")
			if !secretPathHint.MatchString(path) {
				continue
			}
			if m := chmodOctal.FindStringSubmatch(mode); m != nil && (m[1] != "0" || m[2] != "0") {
				out = append(out, secretFinding{docName, nums[i], tk + " " + mode + " makes a secret-bearing path group/world accessible: " + path})
			} else if chmodSymbolic.MatchString(mode) {
				out = append(out, secretFinding{docName, nums[i], tk + " " + mode + " opens a secret-bearing path to group/other: " + path})
			}
		}
	}
	return out
}

func TestDocsDoNotPutSecretsInFlags(t *testing.T) {
	for _, rel := range commandDocs(t) {
		for _, f := range findSecretFlags(rel, readDoc(t, rel)) {
			t.Errorf("%s:%d: %s", f.Doc, f.Line, f.What)
		}
	}
}

func TestDocsDoNotMakeSecretFilesReadable(t *testing.T) {
	for _, rel := range commandDocs(t) {
		for _, f := range findWorldReadableSecretFiles(rel, readDoc(t, rel)) {
			t.Errorf("%s:%d: %s", f.Doc, f.Line, f.What)
		}
	}
}

func TestDocsSecretChecksCatchPlantedErrors(t *testing.T) {
	bad := "```sh\n" +
		"keyorix-server admin recover-admin --user a@b.c --recovery-key s3cr3t\n" +
		"keyorix login --password hunter2\n" +
		"keyorix-server admin encryption rotate-kek --new-passphrase=abc\n" +
		"chmod 644 secrets/master_password\n" +
		"chmod go+r ./kek.key\n" +
		"chmod 644 ./keyorix-backup-2026-10-01.tar.gz\n" +
		"mkdir -m 777 backups\n" +
		"```\n"
	flags := findSecretFlags("planted.md", bad)
	files := findWorldReadableSecretFiles("planted.md", bad)
	if len(flags) != 3 || len(files) != 4 {
		t.Fatalf("planted doc: %d flag findings (want 3), %d file findings (want 4): %+v %+v", len(flags), len(files), flags, files)
	}

	good := "```sh\n" +
		"keyorix-server admin recover-admin --user a@b.c --recovery-key -\n" +
		"keyorix-server admin encryption rotate-kek --new-passphrase-file ./new_master_password\n" +
		"keyorix-server --passphrase-stdin\n" +
		"chmod 600 secrets/master_password\n" +
		"chmod 755 ./bin/keyorix-server\n" +
		"mkdir -m 700 backups\n" +
		"mkdir -p backups\n" +
		"```\n"
	if f := findSecretFlags("good.md", good); len(f) != 0 {
		t.Fatalf("safe flags reported: %+v", f)
	}
	if f := findWorldReadableSecretFiles("good.md", good); len(f) != 0 {
		t.Fatalf("safe chmod reported: %+v", f)
	}
}
