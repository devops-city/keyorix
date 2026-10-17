// Package demohosted holds the offline checks for the hosted-demo deploy kit
// (DEMO-HOSTED-1). There is no Docker, no VM and no network here: the compose overlay and
// Caddyfile are parsed and checked against the production compose file, install.sh is run
// in --render-only mode into a temp dir, and the shell scripts are syntax-checked.
//
// What these tests do NOT prove: that Compose accepts the merged file, that Caddy accepts
// the Caddyfile, that Let's Encrypt issues a certificate, that the containers can read the
// secret files, or that a reset reseeds. Those need the real VM ("pending e2e VM" in the
// PR); the README lists the first-boot checks.
package demohosted

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const repoRoot = "../.."

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel)) // #nosec G304 -- fixed repo-relative names from this file
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func kitFile(t *testing.T, name string) string { return readFile(t, "deploy/demo-hosted/"+name) }

func parseYAML(t *testing.T, rel string) *yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(readFile(t, rel)), &n); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return n.Content[0]
}

// get returns the value node for key in a mapping node, or nil.
func get(n *yaml.Node, keys ...string) *yaml.Node {
	for _, k := range keys {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == k {
				next = n.Content[i+1]
			}
		}
		n = next
	}
	return n
}

func strs(n *yaml.Node) []string {
	var out []string
	if n == nil {
		return out
	}
	for _, c := range n.Content {
		out = append(out, c.Value)
	}
	return out
}

func keys(n *yaml.Node) []string {
	var out []string
	if n == nil {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, n.Content[i].Value)
	}
	sort.Strings(out)
	return out
}

// --- compose overlay ------------------------------------------------------------------------

func TestOverlay_OnlyTouchesWhatItDocuments(t *testing.T) {
	overlay := parseYAML(t, "deploy/demo-hosted/docker-compose.demo.yml")
	if got := get(overlay, "name"); got == nil || got.Value != "keyorix-demo" {
		t.Fatalf("overlay project name must be keyorix-demo (democtl.sh removes keyorix-demo_* volumes), got %v", got)
	}
	allowed := map[string][]string{
		"web":     {"ports"},
		"backend": {"volumes"},
		"caddy":   {"environment", "volumes"},
	}
	svcs := get(overlay, "services")
	for _, name := range keys(svcs) {
		want, ok := allowed[name]
		if !ok {
			t.Errorf("overlay changes service %q, which is not in the documented set", name)
			continue
		}
		if got := keys(get(svcs, name)); !reflect.DeepEqual(got, want) {
			t.Errorf("overlay service %s changes %v, documented %v (images, secrets, read_only, cap_*, security_opt must stay inherited)", name, got, want)
		}
	}
	for _, k := range keys(overlay) {
		if k != "name" && k != "services" {
			t.Errorf("overlay has top-level %q; secrets/volumes/networks must stay inherited from docker-compose.yml", k)
		}
	}
}

// publishedNonLoopback lists "service host:container" for every port a service publishes on
// a non-loopback address in the MERGED view (base ports unless the overlay overrides them).
func publishedNonLoopback(t *testing.T) []string {
	t.Helper()
	base := parseYAML(t, "docker-compose.yml")
	overlay := parseYAML(t, "deploy/demo-hosted/docker-compose.demo.yml")
	var out []string
	for _, name := range keys(get(base, "services")) {
		ports := get(base, "services", name, "ports")
		if o := get(overlay, "services", name, "ports"); o != nil {
			if o.Tag != "!override" {
				t.Fatalf("overlay ports of %s must be tagged !override (a plain list would be MERGED with the base's public port)", name)
			}
			ports = o
		}
		for _, p := range strs(ports) {
			parts := strings.Split(p, ":")
			if len(parts) == 3 && (parts[0] == "127.0.0.1" || parts[0] == "::1") {
				continue
			}
			out = append(out, name+" "+p)
		}
	}
	sort.Strings(out)
	return out
}

func TestOverlay_OnlyCaddyIsPublic(t *testing.T) {
	got := publishedNonLoopback(t)
	want := []string{"caddy 443:443", "caddy 80:80"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("publicly published ports = %v, want exactly %v (web's 8088 must be loopback-only; Docker bypasses the host firewall)", got, want)
	}
}

func TestOverlay_Mounts(t *testing.T) {
	overlay := parseYAML(t, "deploy/demo-hosted/docker-compose.demo.yml")
	base := parseYAML(t, "docker-compose.yml")

	target := func(vol string) string { // short syntax: src:dst[:mode], src may contain ${..:?..:..}
		i := strings.Index(vol, "}") // skip a ${VAR:?msg: with colons} prefix
		rest := vol
		off := 0
		if strings.HasPrefix(vol, "${") && i > 0 {
			off = i + 1
			rest = vol[off:]
		}
		p := strings.Split(rest, ":")
		if len(p) < 2 {
			return ""
		}
		return p[1]
	}
	targets := func(n *yaml.Node) map[string]string {
		m := map[string]string{}
		for _, v := range strs(n) {
			m[target(v)] = v
		}
		return m
	}

	baseBackend := targets(get(base, "services", "backend", "volumes"))
	backend := targets(get(overlay, "services", "backend", "volumes"))
	const cfgTarget = "/app/config/keyorix.docker.yaml"
	if _, ok := baseBackend[cfgTarget]; !ok {
		t.Fatalf("base backend no longer mounts %s; the overlay's config replacement is now wrong", cfgTarget)
	}
	v, ok := backend[cfgTarget]
	if !ok || len(backend) != 1 {
		t.Fatalf("overlay backend volumes = %v, want exactly a replacement of %s", backend, cfgTarget)
	}
	if !strings.Contains(v, "KEYORIX_DEMO_CONFIG:?") || !strings.HasSuffix(v, ":ro") {
		t.Errorf("config mount %q must come from a REQUIRED KEYORIX_DEMO_CONFIG and be read-only", v)
	}

	caddy := targets(get(overlay, "services", "caddy", "volumes"))
	cf, ok := caddy["/etc/caddy/Caddyfile"]
	if !ok || !strings.Contains(cf, "deploy/demo-hosted/Caddyfile.demo") || !strings.HasSuffix(cf, ":ro") {
		t.Errorf("caddy must run deploy/demo-hosted/Caddyfile.demo read-only, got %q", cf)
	}
	g, ok := caddy["/etc/caddy/gate"]
	if !ok || !strings.Contains(g, "KEYORIX_DEMO_GATE_DIR:?") || !strings.HasSuffix(g, ":ro") {
		t.Errorf("caddy must mount the gate dir from a REQUIRED KEYORIX_DEMO_GATE_DIR read-only, got %q", g)
	}
}

func TestOverlay_CaddyEnvironmentIsRequiredNotDefaulted(t *testing.T) {
	overlay := parseYAML(t, "deploy/demo-hosted/docker-compose.demo.yml")
	env := get(overlay, "services", "caddy", "environment")
	vals := map[string]string{}
	for i := 0; i+1 < len(env.Content); i += 2 {
		vals[env.Content[i].Value] = env.Content[i+1].Value
	}
	for _, k := range []string{"KEYORIX_DOMAIN", "KEYORIX_ACME_EMAIL"} {
		if !strings.Contains(vals[k], ":?") {
			t.Errorf("%s = %q must be a required variable (${%s:?...}), not defaulted: the base file defaults the domain to localhost", k, vals[k], k)
		}
	}
	if strings.Contains(vals["KEYORIX_DOMAIN"], "localhost") {
		t.Error("KEYORIX_DOMAIN must not fall back to localhost (Caddy's internal CA)")
	}
	if ca := vals["KEYORIX_ACME_CA"]; !strings.Contains(ca, "https://acme-v02.api.letsencrypt.org/directory") || strings.Contains(ca, "staging") {
		t.Errorf("KEYORIX_ACME_CA default must be the production Let's Encrypt directory, got %q", ca)
	}
}

// The overlay relies on these properties of the production file. If the base changes,
// this fails here instead of silently weakening the demo.
func TestBaseComposeProperties_TheOverlayRelaysOn(t *testing.T) {
	base := parseYAML(t, "docker-compose.yml")
	backendEnv := get(base, "services", "backend", "environment")
	bm := map[string]string{}
	for i := 0; i+1 < len(backendEnv.Content); i += 2 {
		bm[backendEnv.Content[i].Value] = backendEnv.Content[i+1].Value
	}
	for _, k := range []string{"KEYORIX_MASTER_PASSWORD_FILE", "KEYORIX_DB_PASSWORD_FILE", "KEYORIX_ADMIN_PASSWORD_FILE", "KEYORIX_BOOTSTRAP_TOKEN_FILE"} {
		if bm[k] == "" {
			t.Errorf("base backend no longer reads %s from a file", k)
		}
	}
	for _, k := range []string{"KEYORIX_MASTER_PASSWORD", "KEYORIX_DB_PASSWORD", "KEYORIX_ADMIN_PASSWORD", "KEYORIX_BOOTSTRAP_TOKEN"} {
		if _, ok := bm[k]; ok {
			t.Errorf("base backend sets %s in its environment (a default or plaintext secret)", k)
		}
	}
	for _, svc := range []string{"backend", "web", "caddy", "postgres"} {
		if r := get(base, "services", svc, "read_only"); r == nil || r.Value != "true" {
			t.Errorf("base service %s is no longer read_only", svc)
		}
		if strs(get(base, "services", svc, "cap_drop"))[0] != "ALL" {
			t.Errorf("base service %s no longer drops all capabilities", svc)
		}
	}
	if p := strs(get(base, "services", "caddy", "profiles")); len(p) != 1 || p[0] != "tls" {
		t.Errorf("base caddy profiles = %v, want [tls] (democtl.sh passes --profile tls)", p)
	}
	if get(base, "services", "postgres", "ports") != nil {
		t.Error("base postgres publishes a port")
	}
}

// --- server config -----------------------------------------------------------------------------

func TestDemoConfig_IsShippedConfigPlusStrictAudit(t *testing.T) {
	out := renderInstall(t, nil)
	var shipped, demo map[string]any
	if err := yaml.Unmarshal([]byte(readFile(t, "keyorix.docker.yaml")), &shipped); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out.state, "keyorix.demo.yaml")) // #nosec G304 -- temp dir of this test
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &demo); err != nil {
		t.Fatalf("generated config is not valid YAML: %v", err)
	}
	db := demo["storage"].(map[string]any)["database"].(map[string]any)
	if db["audit_durability"] != "strict" {
		t.Fatalf("storage.database.audit_durability = %v, want strict (hardening guide 5a)", db["audit_durability"])
	}
	if v, ok := db["insecure_audit_skip_reads"]; ok && v != false {
		t.Fatalf("insecure_audit_skip_reads = %v: secret reads must stay audited", v)
	}
	delete(db, "audit_durability")
	if !reflect.DeepEqual(shipped, demo) {
		t.Fatalf("generated config differs from keyorix.docker.yaml in more than audit_durability:\nshipped: %v\ndemo:    %v", shipped, demo)
	}
	// The shipped baseline the demo inherits: TLS required, rate limiting on, TLS to Postgres.
	if sec := demo["security"].(map[string]any); sec["require_transport_tls"] != true {
		t.Error("security.require_transport_tls is not true")
	}
	if db["ssl_mode"] != "verify-full" {
		t.Errorf("ssl_mode = %v, want verify-full", db["ssl_mode"])
	}
}

// --- Caddyfile ------------------------------------------------------------------------------------

func TestCaddyfile_TLSHeadersGate(t *testing.T) {
	cf := kitFile(t, "Caddyfile.demo")
	var code []string
	for l := range strings.SplitSeq(cf, "\n") {
		if s := strings.TrimSpace(l); s != "" && !strings.HasPrefix(s, "#") {
			code = append(code, s)
		}
	}
	text := strings.Join(code, "\n")

	if !strings.Contains(text, "\n{$KEYORIX_DOMAIN} {") && !strings.HasPrefix(text, "{$KEYORIX_DOMAIN} {") {
		t.Error("the site address must be exactly {$KEYORIX_DOMAIN} (no default, no localhost)")
	}
	for _, bad := range []string{"localhost", "tls internal", "auto_https off", "disable_redirects", "http://", "skip_install_trust", "staging"} {
		if strings.Contains(text, bad) {
			t.Errorf("Caddyfile.demo contains %q: that defeats automatic Let's Encrypt TLS", bad)
		}
	}
	for _, want := range []string{
		"email {$KEYORIX_ACME_EMAIL}",
		"acme_ca {$KEYORIX_ACME_CA}",
		"admin off",
		`Strict-Transport-Security "max-age=63072000; includeSubDomains"`,
		`X-Content-Type-Options "nosniff"`,
		`X-Frame-Options "DENY"`,
		`Referrer-Policy "no-referrer"`,
		"Permissions-Policy",
		"-Server",
		"format json",
		"output stdout",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Caddyfile.demo lacks %q", want)
		}
	}
	// The gate is imported by exact name (a missing file stops Caddy), inside route{}, and
	// strictly before the proxy.
	gi := strings.Index(text, "import /etc/caddy/gate/gate.caddy")
	ri := strings.Index(text, "reverse_proxy web:80")
	rt := strings.Index(text, "route {")
	if gi < 0 || ri < 0 || rt < 0 || !(rt < gi && gi < ri) {
		t.Errorf("want route { import gate.caddy ... reverse_proxy } in that order, got route=%d gate=%d proxy=%d", rt, gi, ri)
	}
	if regexp.MustCompile(`import\s+\S*[*?\[]`).MatchString(text) {
		t.Error("the gate must not be imported with a glob: an empty glob is silently a no-op and would serve the demo open")
	}
}

// --- install.sh in --render-only mode -------------------------------------------------------------------

type rendered struct{ state, conf, output string }

func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "openssl", "htpasswd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed; install.sh --render-only needs it (CI images have it)", tool)
		}
	}
}

func runInstall(t *testing.T, state, conf string, extra []string) (string, error) {
	t.Helper()
	needTools(t)
	args := append([]string{filepath.Join("deploy", "demo-hosted", "install.sh"), "--render-only",
		"--state-dir", state, "--conf-dir", conf}, extra...)
	cmd := exec.Command("bash", args...) // #nosec G204 -- fixed script, test-controlled args
	cmd.Dir = repoRoot
	// A uid that is not ours, as the existing init-secrets tests do: on a CI runner whose uid is
	// 1001 init-secrets.sh would otherwise refuse the files it just made.
	uid := os.Getuid() + 1
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + state, "INIT_SECRETS_SERVER_UID=" + strconv.Itoa(uid)}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func renderInstall(t *testing.T, extra []string) rendered {
	t.Helper()
	dir := t.TempDir()
	state, conf := filepath.Join(dir, "state"), filepath.Join(dir, "conf")
	args := append([]string{"--hostname", "demo.example.com", "--acme-email", "ops@example.com"}, extra...)
	out, err := runInstall(t, state, conf, args)
	if err != nil {
		t.Fatalf("install.sh --render-only failed: %v\n%s", err, out)
	}
	return rendered{state: state, conf: conf, output: out}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- temp dir of this test
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstall_SecretsAreGeneratedStrongAndPrivate(t *testing.T) {
	r := renderInstall(t, nil)
	sec := filepath.Join(r.state, "secrets")

	tok := strings.TrimSpace(read(t, filepath.Join(sec, "bootstrap_token")))
	if len(tok) < 32 {
		t.Fatalf("bootstrap token is %d characters, want >= 32", len(tok))
	}
	fi, err := os.Stat(filepath.Join(sec, "bootstrap_token"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("bootstrap_token mode = %o, want 0600", fi.Mode().Perm())
	}

	weak := map[string]bool{"": true, "admin": true, "password": true, "changeme": true, "keyorix": true, "demo": true}
	seen := map[string]string{}
	for _, n := range []string{"db_password", "master_password", "admin_password", "bootstrap_token"} {
		v := strings.TrimSpace(read(t, filepath.Join(sec, n)))
		if weak[strings.ToLower(v)] || len(v) < 24 {
			t.Errorf("%s is empty or weak (%d chars)", n, len(v))
		}
		if other, dup := seen[v]; dup {
			t.Errorf("%s and %s hold the same value", n, other)
		}
		seen[v] = n
	}

	// A second install gets its own KEK passphrase: nothing is shared between installs.
	r2 := renderInstall(t, nil)
	if read(t, filepath.Join(sec, "master_password")) == read(t, filepath.Join(r2.state, "secrets", "master_password")) {
		t.Fatal("two installs generated the same master password")
	}
}

func TestInstall_ShortBootstrapTokenIsReplaced(t *testing.T) {
	r := renderInstall(t, nil)
	tokPath := filepath.Join(r.state, "secrets", "bootstrap_token")
	if err := os.WriteFile(tokPath, []byte("short\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if out, err := runInstall(t, r.state, r.conf, nil); err != nil {
		t.Fatalf("re-run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(read(t, tokPath)); len(got) < 32 {
		t.Fatalf("a 5 character token survived a re-run: %q", got)
	}
	fi, _ := os.Stat(tokPath)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after re-run = %o, want 0600", fi.Mode().Perm())
	}
}

func TestInstall_NoSecretValueIsPrintedOrWrittenOutsideSecretFiles(t *testing.T) {
	r := renderInstall(t, []string{"--gate", "both", "--allow-ip", "203.0.113.7"})
	var secretValues []string
	for _, p := range []string{"secrets/db_password", "secrets/master_password", "secrets/admin_password", "secrets/bootstrap_token", "gate_password"} {
		secretValues = append(secretValues, strings.TrimSpace(read(t, filepath.Join(r.state, p))))
	}
	haystacks := map[string]string{
		"installer output":   r.output,
		"demo.env":           read(t, filepath.Join(r.conf, "demo.env")),
		"keyorix.demo.yaml":  read(t, filepath.Join(r.state, "keyorix.demo.yaml")),
		"gate.caddy":         read(t, filepath.Join(r.state, "gate", "gate.caddy")),
		"init-secrets.env":   read(t, filepath.Join(r.state, "init-secrets.env")),
		"state-dir listing":  strings.Join(listNames(t, r.state), " "),
		"secret-dir listing": strings.Join(listNames(t, filepath.Join(r.state, "secrets")), " "),
		"gate-dir listing":   strings.Join(listNames(t, filepath.Join(r.state, "gate")), " "),
		"conf-dir listing":   strings.Join(listNames(t, r.conf), " "),
	}
	for where, h := range haystacks {
		for _, s := range secretValues {
			if s != "" && strings.Contains(h, s) {
				t.Errorf("a secret value appears in %s", where)
			}
		}
	}
}

func listNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestInstall_GateModes(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		basic bool
		ip    string
	}{
		{"default is basic auth", nil, true, ""},
		{"basic", []string{"--gate", "basic"}, true, ""},
		{"ip", []string{"--gate", "ip", "--allow-ip", "203.0.113.7/32,198.51.100.0/24"}, false, "203.0.113.7/32 198.51.100.0/24"},
		{"both", []string{"--gate", "both", "--allow-ip", "203.0.113.7"}, true, "203.0.113.7"},
		{"none", []string{"--gate", "none"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := renderInstall(t, c.args)
			g := read(t, filepath.Join(r.state, "gate", "gate.caddy"))
			hasBasic := regexp.MustCompile(`(?m)^basic_auth \{\n\tdemo \$2[aby]\$\d\d\$\S{53}\n\}$`).MatchString(g)
			if hasBasic != c.basic {
				t.Errorf("basic_auth with a bcrypt hash present = %v, want %v\n%s", hasBasic, c.basic, maskHash(g))
			}
			if c.ip != "" {
				if !strings.Contains(g, "@not_allowed not remote_ip "+c.ip+"\n") || !strings.Contains(g, `respond @not_allowed "Forbidden" 403`) {
					t.Errorf("ip allow-list missing or wrong:\n%s", g)
				}
				if c.basic && strings.Index(g, "respond") > strings.Index(g, "basic_auth") {
					t.Error("the IP check must come before basic auth")
				}
			} else if strings.Contains(g, "remote_ip") {
				t.Errorf("unexpected IP rule:\n%s", g)
			}
			if c.basic {
				pw := strings.TrimSpace(read(t, filepath.Join(r.state, "gate_password")))
				if len(pw) < 24 {
					t.Errorf("generated gate password has %d characters", len(pw))
				}
				fi, _ := os.Stat(filepath.Join(r.state, "gate_password"))
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("gate_password mode = %o, want 0600", fi.Mode().Perm())
				}
			}
		})
	}
}

func maskHash(s string) string {
	return regexp.MustCompile(`\$2[aby]\$\S+`).ReplaceAllString(s, "<hash>")
}

func TestInstall_IdempotentAndKeepsPreviousChoices(t *testing.T) {
	r := renderInstall(t, []string{"--gate", "both", "--allow-ip", "203.0.113.7", "--idle-minutes", "60"})
	snap := func() map[string]string {
		m := map[string]string{}
		for _, root := range []string{r.state, r.conf} {
			_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
				if err == nil && fi.Mode().IsRegular() {
					m[p] = read(t, p)
				}
				return nil
			})
		}
		return m
	}
	before := snap()
	// No flags at all: every choice comes back from demo.env.
	if out, err := runInstall(t, r.state, r.conf, nil); err != nil {
		t.Fatalf("second run failed: %v\n%s", err, out)
	}
	if after := snap(); !reflect.DeepEqual(before, after) {
		for p, v := range before {
			if after[p] != v {
				t.Errorf("%s changed on an idempotent re-run", p)
			}
		}
		t.Fatal("re-running install.sh changed generated files")
	}
	// A single changed flag changes only that value.
	if out, err := runInstall(t, r.state, r.conf, []string{"--idle-minutes", "90"}); err != nil {
		t.Fatalf("third run failed: %v\n%s", err, out)
	}
	env := read(t, filepath.Join(r.conf, "demo.env"))
	if !strings.Contains(env, "KEYORIX_DEMO_IDLE_MINUTES=90\n") || !strings.Contains(env, "KEYORIX_DEMO_GATE=both\n") || !strings.Contains(env, "KEYORIX_DEMO_ALLOW_IP=203.0.113.7\n") {
		t.Errorf("demo.env after changing one flag:\n%s", env)
	}
}

func TestInstall_RejectsBadInputBeforeChangingAnything(t *testing.T) {
	bad := map[string][]string{
		"hostname with scheme":    {"--hostname", "https://demo.example.com", "--acme-email", "a@b.co"},
		"bare hostname":           {"--hostname", "localhost", "--acme-email", "a@b.co"},
		"hostname with space":     {"--hostname", "demo example.com", "--acme-email", "a@b.co"},
		"uppercase hostname":      {"--hostname", "Demo.Example.com", "--acme-email", "a@b.co"},
		"no e-mail":               {"--hostname", "demo.example.com"},
		"bad e-mail":              {"--hostname", "demo.example.com", "--acme-email", "nope"},
		"unknown gate":            {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--gate", "maybe"},
		"ip gate without list":    {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--gate", "ip"},
		"bad cidr":                {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--gate", "ip", "--allow-ip", "10.0.0.1; rm -rf /"},
		"idle too short":          {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--idle-minutes", "1"},
		"unknown idle action":     {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--idle-action", "reboot"},
		"bad reset time":          {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--reset-time", "25:00"},
		"absolute seed script":    {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--seed-script", "/bin/true"},
		"seed script with dotdot": {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--seed-script", "../x.sh"},
		"missing seed script":     {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--seed-script", "scripts/demo/not-merged-yet.sh"},
		"unknown flag":            {"--hostname", "demo.example.com", "--acme-email", "a@b.co", "--frobnicate"},
	}
	for name, args := range bad {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			state, conf := filepath.Join(dir, "state"), filepath.Join(dir, "conf")
			out, err := runInstall(t, state, conf, args)
			if err == nil {
				t.Fatalf("accepted %v:\n%s", args, out)
			}
			if !strings.Contains(out, "install: ERROR:") {
				t.Errorf("no install: ERROR message:\n%s", out)
			}
			for _, d := range []string{state, conf} {
				if _, statErr := os.Stat(d); statErr == nil {
					t.Errorf("%s was created although the input was rejected", d)
				}
			}
		})
	}
}

func TestInstall_SeedScriptIsStoredAsGiven(t *testing.T) {
	// The kit never copies or edits DEMO-LOCAL-2's scripts: it records repo-relative paths.
	r := renderInstall(t, []string{"--seed-script", "deploy/demo-hosted/democtl.sh", "--seed-script", "deploy/demo-hosted/install.sh", "--require-seed"})
	env := read(t, filepath.Join(r.conf, "demo.env"))
	if !strings.Contains(env, "KEYORIX_DEMO_SEED_SCRIPTS=deploy/demo-hosted/democtl.sh deploy/demo-hosted/install.sh\n") || !strings.Contains(env, "KEYORIX_DEMO_REQUIRE_SEED=1\n") {
		t.Errorf("demo.env:\n%s", env)
	}
	// And the default is the documented placeholder: empty list.
	if env := read(t, filepath.Join(renderInstall(t, nil).conf, "demo.env")); !strings.Contains(env, "KEYORIX_DEMO_SEED_SCRIPTS=\n") {
		t.Errorf("default seed list must be empty (placeholder hook):\n%s", env)
	}
}

// --- democtl.sh -----------------------------------------------------------------------------------------

// funcBody returns the text of a top-level shell function `name() {` ... `}`.
func funcBody(t *testing.T, script, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{[^\n]*\n(.*?)^\}\n`)
	m := re.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("function %s not found in democtl.sh", name)
	}
	return stripComments(m[1])
}

// stripComments drops whole-line and trailing "  # ..." comments so a check on code is not
// satisfied or tripped by prose. (No democtl.sh string literal contains " #".)
func stripComments(s string) string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if i := strings.Index(l, " #"); i >= 0 {
			l = l[:i]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func TestDemoctl_ResetIsFullAndKeepsTheCertificate(t *testing.T) {
	s := kitFile(t, "democtl.sh")
	reset := funcBody(t, s, "cmd_reset")
	for _, want := range []string{"remove_volume postgres_data", "remove_volume keyorix_keys", "run_seed_hook", "compose down --remove-orphans"} {
		if !strings.Contains(reset, want) {
			t.Errorf("cmd_reset lacks %q", want)
		}
	}
	// -v / --volumes would delete caddy_data: a nightly new certificate hits Let's Encrypt's limits.
	for _, name := range []string{"cmd_up", "cmd_down", "cmd_reset", "cmd_idle_check", "cmd_seed", "remove_volume"} {
		body := funcBody(t, s, name)
		if regexp.MustCompile(`down[^\n]*( -v\b| --volumes)|docker volume (rm|prune)[^\n]*caddy|volume prune`).MatchString(body) {
			t.Errorf("%s can delete caddy_data (the issued certificate); only destroy may", name)
		}
	}
	if !strings.Contains(funcBody(t, s, "cmd_destroy"), "down -v") {
		t.Error("destroy should remove every volume")
	}
	// Fail closed: a failure after the wipe stops the public entry.
	if !regexp.MustCompile(`trap reset_exit_guard EXIT`).MatchString(reset) || !strings.Contains(funcBody(t, s, "reset_exit_guard"), "compose stop caddy") {
		t.Error("a failed reset must stop caddy via the EXIT guard")
	}
	// A volume that cannot be removed must stop the reset, not be skipped.
	if strings.Contains(funcBody(t, s, "remove_volume"), "|| true") {
		t.Error("remove_volume ignores a failed removal; the reset would keep the old data")
	}
}

func TestDemoctl_SeedHookIsAPlaceholderUntilConfigured(t *testing.T) {
	s := kitFile(t, "democtl.sh")
	hook := funcBody(t, s, "run_seed_hook")
	for _, want := range []string{"PLACEHOLDER", "KEYORIX_DEMO_REQUIRE_SEED", `case $rel in /*|*..*)`, `"$path" ||`, "KEYORIX_DEMO_ADMIN_PASSWORD_FILE", "KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE"} {
		if !strings.Contains(hook, want) {
			t.Errorf("run_seed_hook lacks %q", want)
		}
	}
	for _, f := range []string{"install.sh", "democtl.sh"} {
		for i, line := range strings.Split(kitFile(t, f), "\n") {
			if code := strings.TrimSpace(line); !strings.HasPrefix(code, "#") && strings.Contains(code, "scripts/demo") {
				t.Errorf("%s:%d names a scripts/demo path in code; DEMO-LOCAL-2 owns those, pass them with --seed-script", f, i+1)
			}
		}
	}
}

func TestDemoctl_IdleOnlyCountsRealUse(t *testing.T) {
	idle := funcBody(t, kitFile(t, "democtl.sh"), "cmd_idle_check")
	for _, want := range []string{`"status":[23][0-9][0-9]`, `"uri":"/health"`, "http.log.access", "take_lock -n", "grace"} {
		if !strings.Contains(idle, want) {
			t.Errorf("cmd_idle_check lacks %q", want)
		}
	}
	if !regexp.MustCompile(`stop\) compose stop ;;\s+poweroff\) systemctl poweroff ;;`).MatchString(idle) {
		t.Error("idle actions must be exactly stop and poweroff")
	}
}

// A name-based screen only: no line reads a secret file BY NAME with a content-printing tool
// and no fixed weak value is written in the scripts. The value-based check is
// TestInstall_NoSecretValueIsPrintedOrWrittenOutsideSecretFiles.
func TestKitScripts_NeverPrintOrArgvASecret(t *testing.T) {
	re := regexp.MustCompile(`\b(cat|head|tail|cut|base64|xxd)\b[^\n|]*\b(master_password|admin_password|bootstrap_token|db_password|gate_password)\b`)
	for _, f := range []string{"install.sh", "democtl.sh"} {
		for i, line := range strings.Split(stripComments(kitFile(t, f)), "\n") {
			if re.MatchString(line) {
				t.Errorf("%s:%d reads a secret file by name: %s", f, i+1, strings.TrimSpace(line))
			}
		}
		for _, bad := range []string{"changeme", "KEYORIX_MASTER_PASSWORD=", "POSTGRES_PASSWORD:", "--password", "--value"} {
			if strings.Contains(kitFile(t, f), bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
	}
}

// --- systemd, README, shell hygiene -------------------------------------------------------------------------

func TestSystemdUnits(t *testing.T) {
	ents, err := os.ReadDir("systemd")
	if err != nil {
		t.Fatal(err)
	}
	install := kitFile(t, "install.sh")
	for _, e := range ents {
		if !strings.Contains(install, e.Name()) {
			t.Errorf("systemd/%s is not installed by install.sh", e.Name())
		}
	}
	reset := kitFile(t, "systemd/keyorix-demo-reset.timer")
	for _, want := range []string{"OnCalendar=*-*-* 03:30:00 UTC", "Persistent=true", "Unit=keyorix-demo-reset.service"} {
		if !strings.Contains(reset, want) {
			t.Errorf("reset timer lacks %q", want)
		}
	}
	if !strings.Contains(kitFile(t, "systemd/keyorix-demo-reset.service"), "ExecStart=/usr/local/sbin/keyorix-demo reset\n") {
		t.Error("reset service must run `keyorix-demo reset`")
	}
	idleTimer := kitFile(t, "systemd/keyorix-demo-idle.timer")
	if !strings.Contains(idleTimer, "OnUnitActiveSec=5min") || !strings.Contains(idleTimer, "OnBootSec=") {
		t.Error("idle timer must fire at boot+delay and every 5 minutes")
	}
	if !strings.Contains(kitFile(t, "systemd/keyorix-demo-idle.service"), "ExecStart=/usr/local/sbin/keyorix-demo idle-check\n") {
		t.Error("idle service must run `keyorix-demo idle-check`")
	}
	if !strings.Contains(kitFile(t, "systemd/keyorix-demo.service"), "ExecStart=/usr/local/sbin/keyorix-demo up\n") {
		t.Error("boot service must run `keyorix-demo up`")
	}
	if !strings.Contains(install, "/usr/local/sbin/keyorix-demo") || !strings.Contains(install, "democtl.sh") {
		t.Error("install.sh must install democtl.sh as /usr/local/sbin/keyorix-demo")
	}
}

// The README is a claim about the kit; check what can be checked: every democtl command and
// every install.sh option is documented, and the sections the brief asked for exist.
func TestREADME_DocumentsEveryCommandAndOption(t *testing.T) {
	readme := kitFile(t, "README.md")

	for _, m := range regexp.MustCompile(`(?m)^  ([a-z-]+)(?: --yes)?\) `).FindAllStringSubmatch(kitFile(t, "democtl.sh"), -1) {
		if !strings.Contains(readme, "keyorix-demo "+m[1]) {
			t.Errorf("README does not document `keyorix-demo %s`", m[1])
		}
	}
	flags := regexp.MustCompile(`(?m)^    (--[a-z-]+)(?:\|--[a-z-]+)?\)`).FindAllStringSubmatch(kitFile(t, "install.sh"), -1)
	if len(flags) < 15 {
		t.Fatalf("found only %d install.sh options; the pattern is stale", len(flags))
	}
	for _, m := range flags {
		if !strings.Contains(readme, m[1]) {
			t.Errorf("README does not document install.sh option %s", m[1])
		}
	}
	for _, h := range []string{"VM size", "Ports", "DNS", "Reset", "Destroy", "Cost", "Safety", "pending"} {
		if !regexp.MustCompile(`(?mi)^#+ .*`+h).MatchString(readme) && !strings.Contains(readme, h) {
			t.Errorf("README lacks a section or mention of %q", h)
		}
	}
	if regexp.MustCompile(`(?i)(req/s|ops/s|latency|p99|throughput)`).MatchString(readme) {
		t.Error("README quotes performance figures; benchmark numbers do not belong in repo docs")
	}
}

func TestShellScripts_SyntaxAndShellcheck(t *testing.T) {
	scripts := []string{"deploy/demo-hosted/install.sh", "deploy/demo-hosted/democtl.sh"}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	for _, s := range scripts {
		cmd := exec.Command(bash, "-n", s) // #nosec G204 -- fixed names
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", s, err, out)
		}
		fi, err := os.Stat(filepath.Join(repoRoot, s))
		if err != nil || fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable", s)
		}
	}
	sc, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck is not installed; bash -n above still ran")
	}
	cmd := exec.Command(sc, scripts...) // #nosec G204 -- fixed names
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("shellcheck:\n%s", out)
	}
}

func TestKit_NoOtherFilesOutsideTheKit(t *testing.T) {
	// The brief: deploy kit under deploy/demo-hosted/ only. Guard against stray generated
	// files (render output, secrets) being committed into it.
	var stray []string
	_ = filepath.Walk(".", func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		switch filepath.Ext(p) {
		case ".go", ".md", ".sh", ".yml", ".demo", ".service", ".timer":
		default:
			stray = append(stray, p)
		}
		return nil
	})
	for _, p := range stray {
		t.Errorf("unexpected file in the kit: %s", p)
	}
}
