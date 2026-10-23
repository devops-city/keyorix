package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// relativeSentinel is the value every *_FILE variable is set to: a relative path
// that is exactly what an operator who mistook X_FILE for X would type. It must
// never appear in an error, a log line or a process's output.
const relativeSentinel = "SENTINEL-secret-value-do-not-print"

// sentinelFailureModes are the ways a relative X_FILE can fail. Each one prepares
// the sentinel name inside dir (the process's working directory).
var sentinelFailureModes = []struct {
	name    string
	prepare func(t *testing.T, dir string)
}{
	{"missing", func(*testing.T, string) {}},
	{"unreadable", func(t *testing.T, dir string) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-000 file")
		}
		writeSentinelFile(t, dir, "x\n", 0o000)
	}},
	{"empty", func(t *testing.T, dir string) { writeSentinelFile(t, dir, "", 0o600) }},
	{"directory", func(t *testing.T, dir string) {
		if err := os.Mkdir(filepath.Join(dir, relativeSentinel), 0o700); err != nil {
			t.Fatal(err)
		}
	}},
	{"too-open", func(t *testing.T, dir string) { writeSentinelFile(t, dir, "x\n", 0o644) }},
}

func writeSentinelFile(t *testing.T, dir, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, relativeSentinel)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// secretLookupFuncs are the functions that resolve a secret by variable name
// (and so read <name>_FILE), with the index of the name argument. A call with a
// constant name contributes that name; a call whose name is computed must be in
// dynamicSecretNameSites, i.e. come from a config slot sentinelConfig fills.
var secretLookupFuncs = map[string]int{
	"Lookup":            0, // secretenv
	"LookupChecked":     0, // secretenv
	"resolveSecret":     0, // internal/config
	"ResolvePassphrase": 1, // internal/crypto
	"FileVars":          0, // secretenv (cmd/keyorix-k8s-sync, PassphraseSource.Describe)
}

// dynamicSecretNameSites are the files whose lookups take an operator-chosen
// variable name, and the config slot that names it. sentinelConfig fills every
// one of those slots, so its secretEnvNames (reached through
// ValidateSecretSources / EnforceSecretFilePermissions) covers them.
var dynamicSecretNameSites = map[string]string{
	"internal/config/config.go":               "SecretEnvVars, SSO providers, auto_rotation dsn_env, connect vault token_env, key_provider env_var/shamir_share_env (secretEnvNames)",
	"internal/config/configured_secrets.go":   "secretEnvNames",
	"internal/config/config_auto_rotation.go": "auto_rotation backend dsn_env",
	"internal/config/config_sso.go":           "SSO provider client secret",
	"server/wire_backend_rotation.go":         "connect vault token_env (default VAULT_TOKEN)",
	"internal/crypto/raw_providers.go":        "key_provider env_var",
	"internal/crypto/shamir_provider.go":      "key_provider shamir_share_env",
	"internal/encryptionops/dek.go":           "key_provider env_var",
	"internal/crypto/passphrase.go":           "the caller's passphrase variable (constants discovered at the ResolvePassphrase call sites)",
}

// sentinelConfig fills every operator-named secret slot, and returns the
// variable names it chose.
func sentinelConfig() (*config.Config, []string) {
	cfg := &config.Config{}
	cfg.SSO.Providers = []config.SSOProviderConfig{{Name: "sentineltest"}}
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{{DSNEnv: "KX_SENTINEL_ROTATION_DSN"}}
	cfg.Connect.Connectors = []config.ConnectorConfig{{Type: "vault"}, {Type: "vault", TokenEnv: "KX_SENTINEL_VAULT_TOKEN"}}
	cfg.Storage.Encryption.KeyProvider.EnvVar = "KX_SENTINEL_KEK"
	cfg.Storage.Encryption.KeyProvider.ShamirShareEnv = []string{"KX_SENTINEL_SHARE_1"}
	return cfg, []string{
		"KEYORIX_SSO_SENTINELTEST_CLIENT_SECRET", "KX_SENTINEL_ROTATION_DSN", "VAULT_TOKEN",
		"KX_SENTINEL_VAULT_TOKEN", "KX_SENTINEL_KEK", "KX_SENTINEL_SHARE_1",
	}
}

// discoverSecretFileVars returns every secret variable name the main module
// resolves with a constant name, from the source (not a hand list), and fails
// the test on a computed-name lookup in a file dynamicSecretNameSites does not
// cover.
func discoverSecretFileVars(t *testing.T) []string {
	t.Helper()
	root := findServerRepoRoot(t)
	type parsed struct {
		rel string
		af  *ast.File
	}
	var files []parsed
	consts := map[string]string{} // package-level string constants, by name, module-wide
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir // another module (cli, operator, migrate, devtools)
				}
			}
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git", ".scratch", "web":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		af, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		files = append(files, parsed{filepath.ToSlash(rel), af})
		for _, decl := range af.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if s, err := strconv.Unquote(lit.Value); err == nil {
								consts[id.Name] = s
							}
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	constName := func(e ast.Expr) (string, bool) {
		switch x := e.(type) {
		case *ast.BasicLit:
			s, err := strconv.Unquote(x.Value)
			return s, err == nil
		case *ast.Ident:
			s, ok := consts[x.Name]
			return s, ok
		case *ast.SelectorExpr:
			s, ok := consts[x.Sel.Name]
			return s, ok
		}
		return "", false
	}
	names := map[string]bool{}
	usedSites := map[string]bool{}
	var uncovered []string
	for _, f := range files {
		if strings.HasPrefix(f.rel, "internal/secretenv/") {
			continue // the implementation, not a caller
		}
		ast.Inspect(f.af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var fn string
			switch x := call.Fun.(type) {
			case *ast.Ident:
				fn = x.Name
			case *ast.SelectorExpr:
				fn = x.Sel.Name
			}
			idx, ok := secretLookupFuncs[fn]
			if !ok || idx >= len(call.Args) {
				return true
			}
			if fn == "Lookup" { // only secretenv.Lookup / an in-package lookup, not e.g. os.LookupEnv
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "secretenv" {
						return true
					}
				}
			}
			if name, ok := constName(call.Args[idx]); ok {
				names[name] = true
				return true
			}
			if _, ok := dynamicSecretNameSites[f.rel]; !ok {
				uncovered = append(uncovered, fset.Position(call.Pos()).String())
			}
			usedSites[f.rel] = true
			return true
		})
	}
	if len(uncovered) > 0 {
		t.Fatalf("secret lookup with a computed variable name in a file dynamicSecretNameSites does not cover; "+
			"add the config slot it comes from to sentinelConfig and the file to dynamicSecretNameSites:\n  %s",
			strings.Join(uncovered, "\n  "))
	}
	for site := range dynamicSecretNameSites {
		if !usedSites[site] {
			t.Errorf("dynamicSecretNameSites lists %s, which has no computed-name secret lookup any more: remove it", site)
		}
	}
	for _, n := range config.SecretEnvVars {
		names[n] = true
	}
	out := slices.Sorted(maps.Keys(names))
	if len(out) < len(config.SecretEnvVars) {
		t.Fatalf("discovered %d names, fewer than config.SecretEnvVars (%d): the scan is broken", len(out), len(config.SecretEnvVars))
	}
	return out
}

func assertNoSentinel(t *testing.T, where, text string) {
	t.Helper()
	if strings.Contains(text, relativeSentinel) {
		t.Errorf("%s printed the relative X_FILE value (it may be the secret itself):\n%s", where, text)
	}
}

func notShown(name string) string {
	return name + secretenv.FileSuffix + " (" + secretenv.RelativePathNotShown + ")"
}

// TestRelativeFileValueNeverEchoed_InProcess sets every *_FILE variable the
// server side reads (discovered from the source, plus every operator-named slot)
// to a relative sentinel, triggers each failure mode, and asserts the sentinel
// appears in no error and no log line of: secretenv.Lookup/LookupChecked,
// Config.ValidateSecretSources, Config.EnforceSecretFilePermissions (strict and
// warn), crypto.ResolvePassphrase and PassphraseSource.Describe. Each lookup
// error must name the variable with the "not shown" text, so a mode that stopped
// failing cannot pass vacuously.
func TestRelativeFileValueNeverEchoed_InProcess(t *testing.T) {
	cfg, dynamic := sentinelConfig()
	names := append(discoverSecretFileVars(t), dynamic...)
	t.Logf("variables: %v", names)
	for _, mode := range sentinelFailureModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			mode.prepare(t, dir)
			for _, n := range names {
				t.Setenv(n, "")
				t.Setenv(n+secretenv.FileSuffix, relativeSentinel)
			}
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			for _, n := range names {
				_, _, err := secretenv.Lookup(n)
				_, _, errChecked := secretenv.LookupChecked(n)
				for which, e := range map[string]error{"Lookup": err, "LookupChecked": errChecked} {
					if e == nil {
						if mode.name == "too-open" && which == "Lookup" {
							continue // Lookup leaves permissions to the caller
						}
						t.Errorf("%s(%s) with %s file: no error", which, n, mode.name)
						continue
					}
					assertNoSentinel(t, which+"("+n+")", e.Error())
					if !strings.Contains(e.Error(), notShown(n)) {
						t.Errorf("%s(%s): error does not say %q: %v", which, n, notShown(n), e)
					}
				}
				assertNoSentinel(t, "PassphraseSource.Describe", crypto.PassphraseSource{}.Describe(n))
				if _, err := crypto.ResolvePassphrase(crypto.PassphraseSource{}, n); err != nil {
					assertNoSentinel(t, "ResolvePassphrase("+n+")", err.Error())
				}
			}
			if err := cfg.ValidateSecretSources(); err != nil {
				assertNoSentinel(t, "ValidateSecretSources", err.Error())
			} else if mode.name != "too-open" {
				t.Errorf("ValidateSecretSources accepted a %s file", mode.name)
			}
			for _, strict := range []bool{true, false} {
				cfg.Security.EnableFilePermissionCheck = strict
				if _, err := cfg.EnforceSecretFilePermissions(); err != nil {
					assertNoSentinel(t, "EnforceSecretFilePermissions", err.Error())
				}
			}
			assertNoSentinel(t, "log output", logs.String())
		})
	}
}

// TestRelativeFileValueNeverEchoed_ServerBinary boots the real keyorix-server
// with every constant-named *_FILE variable set to the relative sentinel, once
// per failure mode, and asserts the sentinel is absent from its combined
// stdout/stderr while every variable is reported with the "not shown" text. An
// absolute path is still shown (positive control).
func TestRelativeFileValueNeverEchoed_ServerBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the server binary")
	}
	bin := buildServerBinary(t)
	names := discoverSecretFileVars(t)
	run := func(t *testing.T, dir, value string) string {
		t.Helper()
		cfgPath := filepath.Join(dir, "keyorix.yaml")
		if err := os.WriteFile(cfgPath, []byte("storage:\n  type: local\n  database:\n    path: \"./keyorix.db\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "KEYORIX_CONFIG_PATH=" + cfgPath}
		for _, n := range names {
			env = append(env, n+secretenv.FileSuffix+"="+value)
		}
		cmd := exec.Command(bin)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("keyorix-server started with every secret file broken:\n%s", out)
		}
		return string(out)
	}
	for _, mode := range sentinelFailureModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			mode.prepare(t, dir)
			out := run(t, dir, relativeSentinel)
			assertNoSentinel(t, "keyorix-server output", out)
			if mode.name == "too-open" {
				if !strings.Contains(out, secretenv.RelativePathNotShown) {
					t.Errorf("keyorix-server did not report a too-open relative secret file:\n%s", out)
				}
				return
			}
			// Boot validates config.SecretEnvVars; the other discovered names
			// (e.g. KEYORIX_NEW_MASTER_PASSWORD, read by admin key rotation) are
			// covered in-process.
			for _, n := range config.SecretEnvVars {
				if !strings.Contains(out, notShown(n)) {
					t.Errorf("keyorix-server output does not report %s with the not-shown text:\n%s", n, out)
				}
			}
		})
	}
	t.Run("absolute path still shown", func(t *testing.T) {
		dir := t.TempDir()
		abs := filepath.Join(dir, "missing-secret-file")
		out := run(t, dir, abs)
		if !strings.Contains(out, strconv.Quote(abs)) {
			t.Errorf("an absolute X_FILE path must stay visible; output:\n%s", out)
		}
	})
}

// TestEntrypointDescribeMatchesSecretenv holds the entrypoint's _rs_describe to
// secretenv.DescribeFile, for a relative and an absolute path.
func TestEntrypointDescribeMatchesSecretenv(t *testing.T) {
	fn := resolveSecretFunc(t)
	for _, p := range []string{relativeSentinel, "./token", "/run/secrets/db"} {
		out, err := exec.Command("sh", "-c", fn+"\n_rs_describe KX_SECRET \"$1\"", "sh", p).Output()
		if err != nil {
			t.Fatal(err)
		}
		want := secretenv.DescribeFile("KX_SECRET_FILE", p)
		if p[0] == '/' {
			want = "KX_SECRET_FILE=" + p // the shell prints the path bare, the Go side quotes it
		}
		if string(out) != want {
			t.Errorf("_rs_describe %q = %q, want %q", p, out, want)
		}
	}
}

// TestRelativeFileValueNeverEchoed_Entrypoint runs the shipped resolve_secret
// for every variable entrypoint.sh resolves (discovered from its
// `resolve_secret NAME` calls) with the relative sentinel, in every failure
// mode, and asserts stderr names the variable with the not-shown text and never
// the value. It also fails if a message line in resolve_secret names $_rs_path.
func TestRelativeFileValueNeverEchoed_Entrypoint(t *testing.T) {
	src, err := os.ReadFile("entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for line := range strings.SplitSeq(string(src), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "resolve_secret" {
			names = append(names, f[1])
		}
	}
	if len(names) == 0 {
		t.Fatal("found no `resolve_secret NAME OUT` call in entrypoint.sh")
	}
	fn := resolveSecretFunc(t)
	for line := range strings.SplitSeq(fn, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		// The words of every echo/printf on the line, up to its redirection or the
		// end of the command: `stat ... "$_rs_path" 2>/dev/null) || { echo ...; }`
		// reads the path, which is fine; printing it is not.
		for _, verb := range []string{"echo ", "printf "} {
			for rest := code; strings.Contains(rest, verb); {
				rest = rest[strings.Index(rest, verb)+len(verb):]
				msg := rest
				if i := strings.IndexAny(msg, ";|}>"); i >= 0 {
					msg = msg[:i]
				}
				if strings.Contains(msg, "_rs_path") {
					t.Errorf("resolve_secret prints $_rs_path directly (use $_rs_label from _rs_describe): %s", code)
				}
			}
		}
	}
	for _, mode := range sentinelFailureModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			mode.prepare(t, dir)
			for _, n := range names {
				cmd := exec.Command("sh", "-c", fn+"\nresolve_secret "+n+" _kx_out")
				cmd.Dir = dir
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), n + secretenv.FileSuffix + "=" + relativeSentinel}
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				if err := cmd.Run(); err == nil {
					t.Errorf("resolve_secret %s accepted a %s file", n, mode.name)
				}
				assertNoSentinel(t, "entrypoint resolve_secret "+n, stdout.String()+stderr.String())
				if !strings.Contains(stderr.String(), notShown(n)) {
					t.Errorf("resolve_secret %s (%s): stderr does not say %q: %s", n, mode.name, notShown(n), stderr.String())
				}
			}
		})
	}
}
