// docs_container_admin_test.go -- #2540 (DEMO-1 golden path): the operator docs
// showed `docker compose exec backend ./keyorix-server admin recovery-key rotate`
// against the LIVE backend, which every customer following SELF_HOSTING.md hit as
// "a Keyorix server ... appears to be using this database -- stop it first". The
// command is right to refuse (design-b2 §2 holds the exclusive admin lock for the
// whole rotation); the doc was wrong. Same section also showed a bare
// `keyorix-server` (not on the image's PATH) and a `keyorix` service/binary that
// does not exist.
//
// TestDockerDocsAdminCommandsAreRunnable checks every `docker compose exec|run
// <service> <binary> admin ...` line inside a fenced code block of the operator
// docs against facts DERIVED from the code, not restated by hand:
//
//  1. <service> is a service in docker-compose.yml.
//  2. <binary> is how the image can actually invoke the server binary: from
//     server/Dockerfile, the binary is COPY'd into WORKDIR; with no ENV PATH
//     naming that directory, only "./keyorix-server" or "<WORKDIR>/keyorix-server"
//     work.
//  3. If the admin command NEEDS THE SERVER STOPPED (see adminCommandNeedsServerStopped),
//     it is not shown via `exec` (which runs inside the live backend), and a
//     `run --rm` of it is preceded, in the same fenced block, by
//     `docker compose stop <service>`.
//
// What it does not check, stated so a green run is not read as more: host-binary
// commands (QUICK_START.md's ./bin/keyorix-server lines -- whether the server is
// running there is narrated in prose, not encoded in the command), and anything
// outside fenced code blocks.
package admin

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// serverStoppedLockCalls are the function/method names whose call means "this
// command needs the database or the key directory to itself": the database's
// exclusive server lock (acquireDatabaseLock -> serverguard.AcquireExclusive),
// and the key directory's dek.lock in either mode (a live server holds it
// exclusively for its lifetime, so even the SHARED form is refused beside one).
var serverStoppedLockCalls = map[string]bool{
	"acquireDatabaseLock":     true,
	"AcquireExclusive":        true,
	"AcquireExclusiveKeyLock": true,
	"AcquireSharedKeyLock":    true,
}

// liveSafeDespiteLockCall lists admin commands whose code path reaches a lock in
// serverStoppedLockCalls only CONDITIONALLY, with a documented live path. Each
// entry is a claim; keep its reason specific.
var liveSafeDespiteLockCall = map[string]string{
	// On Postgres (the Docker stack) without --exclusive, backup reads through a
	// REPEATABLE READ snapshot and takes neither lock beside a live server
	// (#2602, fixed in its own PR; SQLite and --exclusive still need the server
	// stopped and say so).
	"backup": "Postgres live-snapshot path (#2602)",
}

// adminPackageFuncs parses this package's non-test sources and returns every
// package-level function declaration by name.
func adminPackageFuncs(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read server/admin: %v", err)
	}
	out := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse server/admin/%s: %v", name, err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil {
				out[fd.Name.Name] = fd
			}
		}
	}
	return out
}

// adminCommandNeedsServerStopped reports whether cmd's RunE reaches a call in
// serverStoppedLockCalls; its second result is false when cmd cannot be
// classified (no RunE, or a RunE that is a function literal rather than a
// package-level function). Recognized call forms, stated so the enumeration's
// completeness can be checked: a call whose callee name (plain identifier or
// the selector's final name, e.g. svc.AcquireExclusiveKeyLock) is in
// serverStoppedLockCalls; and calls to OTHER package-level functions of this
// package by plain identifier, followed transitively, including inside
// function literals (closures passed to withUsableStorage etc.). Not
// followed: methods on this package's own types, and function values called
// through variables -- neither currently sits between a RunE and a lock.
func adminCommandNeedsServerStopped(t *testing.T, funcs map[string]*ast.FuncDecl, cmd *cobra.Command) (bool, bool) {
	t.Helper()
	if cmd.RunE == nil {
		return false, false
	}
	full := runtime.FuncForPC(reflect.ValueOf(cmd.RunE).Pointer()).Name()
	name := full[strings.LastIndex(full, ".")+1:]
	root, ok := funcs[name]
	if !ok {
		// A function literal (e.g. "init.func1") has no declaration to walk:
		// unclassifiable, which the caller must treat as such.
		return false, false
	}
	seen := map[string]bool{}
	var visit func(fd *ast.FuncDecl) bool
	visit = func(fd *ast.FuncDecl) bool {
		if seen[fd.Name.Name] {
			return false
		}
		seen[fd.Name.Name] = true
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var callee string
			switch f := call.Fun.(type) {
			case *ast.Ident:
				callee = f.Name
			case *ast.SelectorExpr:
				callee = f.Sel.Name
			}
			if serverStoppedLockCalls[callee] {
				found = true
				return false
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				if next, ok := funcs[id.Name]; ok && visit(next) {
					found = true
					return false
				}
			}
			return true
		})
		return found
	}
	return visit(root), true
}

var composeAdminLineRe = regexp.MustCompile(`^docker compose (exec|run)\s+(.*)$`)

type dockerDocInvocation struct {
	file, line, verb, service, binary string
	adminArgs                         []string
	stoppedBefore                     map[string]bool // services `docker compose stop`ped earlier in the same fenced block
}

// dockerDocAdminInvocations extracts every `docker compose exec|run ...` line
// that invokes `admin` from a fenced code block of the given files.
func dockerDocAdminInvocations(t *testing.T, relFiles []string) []dockerDocInvocation {
	t.Helper()
	var out []dockerDocInvocation
	for _, rel := range relFiles {
		path := filepath.Join(adminDocRepoRoot(t), rel)
		b, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative paths
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		inFence := false
		stopped := map[string]bool{}
		sc := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(b), "\\\n", " ")))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "```") {
				inFence = !inFence
				stopped = map[string]bool{}
				continue
			}
			if !inFence || strings.HasPrefix(line, "#") {
				continue
			}
			if rest, ok := strings.CutPrefix(line, "docker compose stop "); ok {
				for s := range strings.FieldsSeq(rest) {
					stopped[s] = true
				}
				continue
			}
			m := composeAdminLineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			toks := adminDocTokenize(m[2])
			// Skip compose's own flags (--rm, -T, -v x:y, -e K=V ...).
			i := 0
			for i < len(toks) && strings.HasPrefix(toks[i], "-") {
				if (toks[i] == "-v" || toks[i] == "-e" || toks[i] == "--volume" || toks[i] == "--env") && i+1 < len(toks) {
					i++
				}
				i++
			}
			if i+2 >= len(toks) || toks[i+2] != "admin" {
				// Not `<service> <binary> admin ...` -- but a line naming a
				// "keyorix" binary with no admin subcommand is still worth
				// checking for the service/binary shape.
				if i+1 < len(toks) && strings.Contains(toks[i+1], "keyorix") {
					out = append(out, dockerDocInvocation{file: rel, line: line, verb: m[1], service: toks[i], binary: toks[i+1]})
				}
				continue
			}
			copyStopped := map[string]bool{}
			maps.Copy(copyStopped, stopped)
			out = append(out, dockerDocInvocation{
				file: rel, line: line, verb: m[1], service: toks[i], binary: toks[i+1],
				adminArgs: toks[i+3:], stoppedBefore: copyStopped,
			})
		}
	}
	return out
}

// composeServices returns the service names defined in docker-compose.yml.
func composeServices(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(adminDocRepoRoot(t), "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	out := map[string]bool{}
	inServices := false
	for l := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(l, "services:") {
			inServices = true
			continue
		}
		if inServices && len(l) > 0 && l[0] != ' ' && l[0] != '#' {
			break
		}
		if m := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`).FindStringSubmatch(l); inServices && m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// imageServerBinaryInvocations derives, from server/Dockerfile's final stage,
// the ways a command inside the container can invoke the server binary.
func imageServerBinaryInvocations(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(adminDocRepoRoot(t), "server", "Dockerfile"))
	if err != nil {
		t.Fatalf("read server/Dockerfile: %v", err)
	}
	stages := strings.Split(string(b), "\nFROM ")
	final := stages[len(stages)-1]
	workdir := ""
	copied := false
	pathEnv := ""
	for l := range strings.SplitSeq(final, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "WORKDIR "):
			workdir = strings.TrimSpace(strings.TrimPrefix(l, "WORKDIR "))
		case strings.HasPrefix(l, "COPY ") && strings.Contains(l, "keyorix-server"):
			copied = true
		case strings.HasPrefix(l, "ENV PATH"):
			pathEnv = l
		}
	}
	if workdir == "" || !copied {
		t.Fatalf("could not derive the server binary's location from server/Dockerfile's final stage (WORKDIR %q, copied %v) -- "+
			"this guard's derivation has drifted from the Dockerfile", workdir, copied)
	}
	out := map[string]bool{"./keyorix-server": true, filepath.Join(workdir, "keyorix-server"): true}
	if strings.Contains(pathEnv, workdir) {
		out["keyorix-server"] = true
	}
	return out
}

// TestDockerDocsAdminCommandsAreRunnable -- see this file's header.
// Deliberately NOT t.Parallel() -- see TestQuickStartAdminCommandsExist's comment.
func TestDockerDocsAdminCommandsAreRunnable(t *testing.T) {
	files := []string{"docs/SELF_HOSTING.md", "docs/UPGRADING.md", "QUICK_START.md", "README.md"}
	invs := dockerDocAdminInvocations(t, files)
	if len(invs) == 0 {
		t.Fatalf("extracted zero `docker compose exec|run ... keyorix...` lines from %v; SELF_HOSTING.md documents "+
			"several -- the extractor has drifted and this guard is checking nothing", files)
	}
	services := composeServices(t)
	if !services["backend"] {
		t.Fatalf("derived compose services %v do not include \"backend\" -- the compose parser has drifted", services)
	}
	binaries := imageServerBinaryInvocations(t)
	funcs := adminPackageFuncs(t)

	for _, inv := range invs {
		where := inv.file + ": `" + inv.line + "`"
		if !services[inv.service] {
			t.Errorf("%s: docker-compose.yml has no service %q", where, inv.service)
		}
		if !binaries[inv.binary] {
			keys := make([]string, 0, len(binaries))
			for k := range binaries {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			t.Errorf("%s: %q does not run the server binary inside the image (server/Dockerfile: works as %v)", where, inv.binary, keys)
		}
		if len(inv.adminArgs) == 0 {
			continue
		}
		var path []string
		for _, a := range inv.adminArgs {
			if strings.HasPrefix(a, "-") {
				break
			}
			path = append(path, a)
		}
		cmd, remaining, err := rootCmd.Find(path)
		if err != nil || len(remaining) > 0 || cmd == rootCmd {
			t.Errorf("%s: `admin %s` is not a command", where, strings.Join(path, " "))
			continue
		}
		needsStop, classified := adminCommandNeedsServerStopped(t, funcs, cmd)
		if !classified {
			t.Errorf("%s: cannot classify `admin %s` (its RunE is not a package-level function this guard can walk) -- "+
				"give it a named RunE", where, strings.Join(path, " "))
			continue
		}
		if !needsStop {
			continue
		}
		if _, ok := liveSafeDespiteLockCall[strings.Join(path, " ")]; ok {
			continue
		}
		switch inv.verb {
		case "exec":
			t.Errorf("%s: `admin %s` needs the server stopped (its code takes the database or key-directory lock a "+
				"live server holds), but `docker compose exec` runs it inside the LIVE %s container -- show "+
				"`docker compose stop %s` then `docker compose run --rm %s ...` instead",
				where, strings.Join(path, " "), inv.service, inv.service, inv.service)
		case "run":
			if !inv.stoppedBefore[inv.service] {
				t.Errorf("%s: `admin %s` needs the server stopped, but this fenced block runs it without a preceding "+
					"`docker compose stop %s` -- `run --rm` shares the live service's database and key volume",
					where, strings.Join(path, " "), inv.service)
			}
		}
	}
}

// TestAdminCommandNeedsServerStopped_Calibration: the classifier must say
// "needs the server stopped" for a command known to take the database lock,
// and must NOT say it for every command -- a classifier that answers the same
// for everything would make the guard above vacuous in one direction or the
// other.
func TestAdminCommandNeedsServerStopped_Calibration(t *testing.T) {
	funcs := adminPackageFuncs(t)
	known, _, err := rootCmd.Find([]string{"recovery-key", "rotate"})
	if err != nil {
		t.Fatalf("find recovery-key rotate: %v", err)
	}
	if needs, _ := adminCommandNeedsServerStopped(t, funcs, known); !needs {
		t.Fatal("classifier says `admin recovery-key rotate` does not need the server stopped; it calls acquireDatabaseLock (design-b2 §2)")
	}
	yes, no := 0, 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if needs, ok := adminCommandNeedsServerStopped(t, funcs, c); ok {
			if needs {
				yes++
			} else {
				no++
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
	if yes == 0 || no == 0 {
		t.Fatalf("classifier is constant over the admin command tree (needs-stop=%d, live-safe=%d) -- it no longer discriminates", yes, no)
	}
}
