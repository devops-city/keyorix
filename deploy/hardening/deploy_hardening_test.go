// deploy_hardening_test.go -- DEPLOY-1 guard: the container-hardening baseline
// of the two shipped deployment paths (docker-compose.yml and the Helm chart
// deploy/helm/keyorix) is asserted from the files themselves, so it cannot
// drift back to a root / writable-rootfs / all-capabilities workload unnoticed.
//
// Baseline (every long-running workload): non-root, read-only root filesystem,
// capabilities dropped to ALL (the only allowed add-back is NET_BIND_SERVICE for
// ports 80/443), no privilege escalation, no privileged mode. For the chart also
// seccomp RuntimeDefault and no service-account token. Docker applies its
// default seccomp profile unless it is explicitly disabled, so for compose the
// test asserts it is NOT disabled.
//
// What this does NOT cover: whether the workloads actually start under these
// settings (that was proven by deploying on the bench VM, see the PR), image
// contents, or secrets handling (env vs file mounts needs server *_FILE support).
//
// The chart half needs `helm` and skips cleanly without it; CI's "helm-chart"
// job has it (see password_policy_helm_chart_test.go).
package hardening

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func repoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

type m = map[string]any

func asMap(v any) m {
	if x, ok := v.(m); ok {
		return x
	}
	return m{}
}

func asList(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return nil
}

func hasString(list any, want string) bool {
	for _, e := range asList(list) {
		if s, ok := e.(string); ok && strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// ---- compose -------------------------------------------------------------

func TestCompose_ServicesAreHardened(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc m
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	services := asMap(doc["services"])
	for _, name := range []string{"postgres", "backend", "web", "caddy"} {
		svc, ok := services[name].(m)
		if !ok {
			t.Fatalf("docker-compose.yml: service %q missing -- update this guard if it was renamed", name)
		}
		if svc["read_only"] != true {
			t.Errorf("%s: read_only must be true (writable paths belong on tmpfs/volumes)", name)
		}
		if !hasString(svc["cap_drop"], "ALL") {
			t.Errorf("%s: cap_drop must contain ALL", name)
		}
		for _, c := range asList(svc["cap_add"]) {
			if s, _ := c.(string); s != "NET_BIND_SERVICE" {
				t.Errorf("%s: cap_add %v -- only NET_BIND_SERVICE may be added back", name, c)
			}
		}
		if !hasString(svc["security_opt"], "no-new-privileges:true") {
			t.Errorf("%s: security_opt must contain no-new-privileges:true", name)
		}
		for _, o := range asList(svc["security_opt"]) {
			if s, _ := o.(string); strings.Contains(s, "seccomp") || strings.Contains(s, "apparmor=unconfined") {
				t.Errorf("%s: security_opt %q disables Docker's default confinement", name, s)
			}
		}
		if svc["privileged"] == true {
			t.Errorf("%s: privileged must not be set", name)
		}
	}
	// postgres' image would otherwise start as root and drop privileges itself,
	// which needs CAP_SETUID/SETGID/CHOWN; running as the image's own uid avoids that.
	pg := asMap(services["postgres"])
	if u, _ := pg["user"].(string); u == "" || u == "0" || strings.HasPrefix(u, "0:") || u == "root" {
		t.Errorf("postgres: user must be a non-root uid:gid, got %q", u)
	}
}

func nonRootUser(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:") {
		return false
	}
	return true
}

func volumeNames(svc m) []string {
	var out []string
	for _, v := range asList(svc["volumes"]) {
		if s, ok := v.(string); ok {
			// "caddy_data:/data" or "./file:/path:ro"
			if src, _, found := strings.Cut(s, ":"); found && !strings.HasPrefix(src, ".") && !strings.HasPrefix(src, "/") {
				out = append(out, src+":"+strings.Split(s, ":")[1])
			}
		}
	}
	return out
}

// DEPLOY-2 decision 3: caddy runs as a non-root user with only NET_BIND_SERVICE.
// Its /data and /config volumes were created root-owned by the previous layout, so
// a one-shot caddy-init service chowns them first. The init step is the only root
// service and may add back only CHOWN; the guard also pins that caddy waits for it
// to COMPLETE (not merely start) and that both mount the very same volumes.
func TestCompose_CaddyRunsNonRootAfterOneShotInit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc m
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	services := asMap(doc["services"])
	caddy, ok := services["caddy"].(m)
	if !ok {
		t.Fatal("caddy service missing")
	}
	user, _ := caddy["user"].(string)
	if !nonRootUser(user) {
		t.Errorf("caddy: user must be a non-root uid:gid, got %q", user)
	}
	if !strings.Contains(user, ":") {
		t.Errorf("caddy: user %q must name uid:gid explicitly so the init step can chown to it", user)
	}
	if len(asList(caddy["cap_add"])) != 1 || !hasString(caddy["cap_add"], "NET_BIND_SERVICE") {
		t.Errorf("caddy: cap_add must be exactly [NET_BIND_SERVICE], got %v", caddy["cap_add"])
	}

	initSvc, ok := services["caddy-init"].(m)
	if !ok {
		t.Fatal("caddy-init service missing: an existing root-owned caddy_data/caddy_config volume would make non-root caddy fail")
	}
	if p := asList(initSvc["profiles"]); len(p) != 1 || !hasString(p, "tls") {
		t.Errorf("caddy-init: profiles must be [tls] like caddy, got %v", initSvc["profiles"])
	}
	if initSvc["restart"] != "no" {
		t.Errorf("caddy-init: restart must be \"no\" (one-shot), got %v", initSvc["restart"])
	}
	if initSvc["read_only"] != true {
		t.Error("caddy-init: read_only must be true")
	}
	if !hasString(initSvc["cap_drop"], "ALL") {
		t.Error("caddy-init: cap_drop must contain ALL")
	}
	// CHOWN to change the owner; DAC_READ_SEARCH because Caddy creates its storage
	// directories 0700: after the first run they belong to 65532, and root without
	// it cannot open them, so every later run (and an interrupted first one) would
	// fail and, with caddy gated on service_completed_successfully, keep HTTPS down.
	// DAC_OVERRIDE (write everywhere) is deliberately NOT needed and not allowed.
	if caps := asList(initSvc["cap_add"]); len(caps) != 2 || !hasString(caps, "CHOWN") || !hasString(caps, "DAC_READ_SEARCH") {
		t.Errorf("caddy-init: cap_add must be exactly [CHOWN, DAC_READ_SEARCH], got %v", initSvc["cap_add"])
	}
	if !hasString(initSvc["security_opt"], "no-new-privileges:true") {
		t.Error("caddy-init: security_opt must contain no-new-privileges:true")
	}
	if initSvc["privileged"] == true {
		t.Error("caddy-init: privileged must not be set")
	}
	joined := ""
	for _, key := range []string{"entrypoint", "command"} {
		for _, c := range asList(initSvc[key]) {
			s, _ := c.(string)
			joined += s + " "
		}
	}
	if !strings.Contains(joined, "chown") || !strings.Contains(joined, user) {
		t.Errorf("caddy-init: entrypoint/command %q must chown the volumes to caddy's user %q", joined, user)
	}
	if !strings.Contains(joined, "/data") || !strings.Contains(joined, "/config") {
		t.Errorf("caddy-init: %q must chown both /data and /config", joined)
	}
	// Scope: the two Caddy volumes only, no symlink following, no mount crossing,
	// and only entries not already owned by caddy (idempotent: a migrated volume is
	// left untouched).
	if got := asList(initSvc["entrypoint"]); len(got) == 0 || got[0] != "find" {
		t.Errorf("caddy-init: entrypoint must be a find over the Caddy volumes (idempotent, owner-filtered), got %v", got)
	}
	for _, want := range []string{"-xdev", "-user", "-group", "-h"} {
		if !strings.Contains(" "+joined, " "+want+" ") {
			t.Errorf("caddy-init: entrypoint %q must contain %s", joined, want)
		}
	}
	for _, c := range asList(initSvc["entrypoint"]) {
		if s, _ := c.(string); s == "-L" || s == "-follow" || s == "-R" || strings.HasPrefix(s, "/") && s != "/data" && s != "/config" {
			t.Errorf("caddy-init: entrypoint element %q widens the scope beyond /data and /config", s)
		}
	}
	if initSvc["network_mode"] != "none" {
		t.Errorf("caddy-init: network_mode must be none, got %v", initSvc["network_mode"])
	}

	dep := asMap(asMap(caddy["depends_on"])["caddy-init"])
	if dep["condition"] != "service_completed_successfully" {
		t.Errorf("caddy: depends_on caddy-init must use condition service_completed_successfully, got %v", dep["condition"])
	}
	cv, iv := volumeNames(caddy), volumeNames(initSvc)
	for _, want := range []string{"caddy_data:/data", "caddy_config:/config"} {
		found := false
		for _, v := range cv {
			found = found || v == want
		}
		if !found {
			t.Errorf("caddy: volume %s missing", want)
		}
		found = false
		for _, v := range iv {
			found = found || v == want
		}
		if !found {
			t.Errorf("caddy-init: volume %s missing -- it must chown the same volumes caddy uses", want)
		}
	}
}

// ---- helm chart ----------------------------------------------------------

func renderChart(t *testing.T) []m { return renderChartWith(t) }

func renderChartWith(t *testing.T, extra ...string) []m {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart hardening check")
	}
	chart := filepath.Join(repoRoot(), "deploy", "helm", "keyorix")
	args := append([]string{"template", "kx", chart,
		"--set", "auth.masterPassword=x",
		"--set", "postgresql.auth.password=x",
		"--set-string", "auth.adminPassword=0123456789abcdef0123",
	}, extra...)
	cmd := exec.Command("helm", args...) //nolint:gosec // fixed binary, chart path and test-controlled args
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var docs []m
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var d m
		if err := dec.Decode(&d); err != nil {
			break
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func TestHelmChart_WorkloadsAreHardened(t *testing.T) {
	docs := renderChart(t)
	seen := map[string]bool{}
	for _, d := range docs {
		if d["kind"] != "Deployment" {
			continue
		}
		name, _ := asMap(d["metadata"])["name"].(string)
		comp, _ := asMap(asMap(d["metadata"])["labels"])["app.kubernetes.io/component"].(string)
		seen[comp] = true
		if ann := asMap(asMap(d["metadata"])["annotations"]); ann != nil {
			for k, v := range ann {
				if s, _ := v.(string); strings.HasPrefix(k, "checkov.io/skip") && strings.Contains(s, "CKV_K8S_22") {
					t.Errorf("%s: %s=%q -- the read-only-rootfs exemption must not come back", name, k, s)
				}
			}
		}
		spec := asMap(asMap(asMap(d["spec"])["template"])["spec"])
		pod := asMap(spec["securityContext"])
		if pod["runAsNonRoot"] != true {
			t.Errorf("%s: pod runAsNonRoot must be true", name)
		}
		if uid, _ := pod["runAsUser"].(int); uid == 0 {
			t.Errorf("%s: pod runAsUser must be set and non-zero", name)
		}
		if asMap(pod["seccompProfile"])["type"] != "RuntimeDefault" {
			t.Errorf("%s: pod seccompProfile.type must be RuntimeDefault", name)
		}
		if spec["automountServiceAccountToken"] != false {
			t.Errorf("%s: automountServiceAccountToken must be false", name)
		}
		if comp == "server" {
			// keys PVC must be writable by the server uid under a root-owned provisioner.
			if pod["fsGroup"] != pod["runAsUser"] || pod["fsGroup"] == nil {
				t.Errorf("%s: server pod fsGroup (%v) must equal runAsUser (%v) so the keys PVC is writable", name, pod["fsGroup"], pod["runAsUser"])
			}
		}
		volumes := map[string]m{}
		for _, v := range asList(spec["volumes"]) {
			vm := asMap(v)
			n, _ := vm["name"].(string)
			volumes[n] = vm
		}
		for _, c := range asList(spec["containers"]) {
			cm := asMap(c)
			cname, _ := cm["name"].(string)
			sc := asMap(cm["securityContext"])
			if sc["allowPrivilegeEscalation"] != false {
				t.Errorf("%s/%s: allowPrivilegeEscalation must be false", name, cname)
			}
			if sc["readOnlyRootFilesystem"] != true {
				t.Errorf("%s/%s: readOnlyRootFilesystem must be true", name, cname)
			}
			if sc["privileged"] == true {
				t.Errorf("%s/%s: privileged must not be set", name, cname)
			}
			caps := asMap(sc["capabilities"])
			if !hasString(caps["drop"], "ALL") {
				t.Errorf("%s/%s: capabilities.drop must contain ALL", name, cname)
			}
			for _, a := range asList(caps["add"]) {
				if s, _ := a.(string); s != "NET_BIND_SERVICE" {
					t.Errorf("%s/%s: capabilities.add %v -- only NET_BIND_SERVICE may be added back", name, cname, a)
				}
			}
			// A read-only rootfs only works if every other write target is a mounted volume;
			// every mount must reference a declared volume (catches a dropped emptyDir).
			for _, vmnt := range asList(cm["volumeMounts"]) {
				vn, _ := asMap(vmnt)["name"].(string)
				if _, ok := volumes[vn]; !ok {
					t.Errorf("%s/%s: volumeMount %q has no matching volume", name, cname, vn)
				}
			}
		}
	}
	for _, want := range []string{"server", "web", "postgresql"} {
		if !seen[want] {
			t.Errorf("no %q Deployment rendered -- the guard would be vacuous; update it if the component was renamed", want)
		}
	}
}

// ---- tmpfs / emptyDir size limits ------------------------------------------

// An unbounded tmpfs is host RAM: a runaway writer in a "hardened" container
// could still take the host down. Every tmpfs mount in compose must carry an
// explicit size=.
func TestCompose_EveryTmpfsHasASizeLimit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc m
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	total := 0
	for name, v := range asMap(doc["services"]) {
		for _, e := range asList(asMap(v)["tmpfs"]) {
			total++
			s, _ := e.(string)
			if !strings.Contains(s, "size=") {
				t.Errorf("%s: tmpfs %q has no size= (unbounded tmpfs is unbounded host memory)", name, s)
			}
		}
	}
	if total == 0 {
		t.Fatal("no tmpfs mounts found -- the guard would be vacuous; update it if they were removed")
	}
}

// Same for the chart: an emptyDir without sizeLimit lets a pod fill the node's
// ephemeral storage. (A data emptyDir used when persistence is off is bounded by
// the persistence size.)
func TestHelmChart_EveryEmptyDirHasASizeLimit(t *testing.T) {
	docs := renderChart(t)
	total := 0
	for _, d := range docs {
		if d["kind"] != "Deployment" {
			continue
		}
		name, _ := asMap(d["metadata"])["name"].(string)
		spec := asMap(asMap(asMap(d["spec"])["template"])["spec"])
		for _, v := range asList(spec["volumes"]) {
			vm := asMap(v)
			ed, ok := vm["emptyDir"]
			if !ok {
				continue
			}
			total++
			if asMap(ed)["sizeLimit"] == nil {
				t.Errorf("%s: emptyDir volume %v has no sizeLimit", name, vm["name"])
			}
		}
	}
	if total == 0 {
		t.Fatal("no emptyDir volumes found -- the guard would be vacuous")
	}
}

// ---- postgres uid -----------------------------------------------------------

// The bundled Postgres must run as the uid the chosen image actually uses, the
// same in compose and in the chart: the official Alpine images use 70, the Debian
// ones 999. A data volume created by the previous (root-entrypoint) layouts is
// owned by that uid, so any other value cannot open an existing volume. The
// image's own uid was verified with `docker run postgres:15-alpine id postgres`
// (uid=70(postgres) gid=70(postgres)); this guard keeps the three places that
// must agree -- compose user, chart securityContext and image flavour -- in step.
func postgresUIDForImage(image string) int {
	if strings.Contains(image, "alpine") {
		return 70
	}
	return 999
}

func TestPostgresUID_ConsistentBetweenComposeAndHelmAndMatchesImage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc m
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	pg := asMap(asMap(doc["services"])["postgres"])
	image, _ := pg["image"].(string)
	want := postgresUIDForImage(image)
	wantStr := strconv.Itoa(want)
	if user, _ := pg["user"].(string); user != wantStr+":"+wantStr {
		t.Errorf("compose postgres: user %q must be %s:%s for image %s", user, wantStr, wantStr, image)
	}
	for _, e := range asList(pg["tmpfs"]) {
		if s, _ := e.(string); strings.HasPrefix(s, "/var/run/postgresql") &&
			(!strings.Contains(s, "uid="+wantStr) || !strings.Contains(s, "gid="+wantStr)) {
			t.Errorf("compose postgres: tmpfs %q must be owned by uid/gid %s", s, wantStr)
		}
	}

	for _, d := range renderChart(t) {
		if d["kind"] != "Deployment" {
			continue
		}
		if comp, _ := asMap(asMap(d["metadata"])["labels"])["app.kubernetes.io/component"].(string); comp != "postgresql" {
			continue
		}
		spec := asMap(asMap(asMap(d["spec"])["template"])["spec"])
		pod := asMap(spec["securityContext"])
		for _, k := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
			if got, _ := pod[k].(int); got != want {
				t.Errorf("helm postgresql: %s is %v, want %d (the uid of the postgres image)", k, pod[k], want)
			}
		}
		chartImage, _ := asMap(asList(spec["containers"])[0])["image"].(string)
		if postgresUIDForImage(chartImage) != want {
			t.Errorf("helm postgresql image %q and compose image %q are different flavours (uid %d vs %d)", chartImage, image, postgresUIDForImage(chartImage), want)
		}
		return
	}
	t.Fatal("no postgresql Deployment rendered -- the guard would be vacuous")
}

func postgresPodSpec(t *testing.T, docs []m) m {
	t.Helper()
	for _, d := range docs {
		if d["kind"] != "Deployment" {
			continue
		}
		if comp, _ := asMap(asMap(d["metadata"])["labels"])["app.kubernetes.io/component"].(string); comp == "postgresql" {
			return asMap(asMap(asMap(d["spec"])["template"])["spec"])
		}
	}
	t.Fatal("no postgresql Deployment rendered")
	return nil
}

// A volume created by an older chart (which ran the pod as 999) is owned by 999.
// The opt-in migration is the only root container the chart can render; it must stay
// that narrow: off by default, CHOWN + DAC_READ_SEARCH only, read-only root FS,
// confined to the data volume, owner-filtered and symlink-safe.
func TestHelmChart_PostgresOwnershipMigrationIsOptInAndNarrow(t *testing.T) {
	if got := asList(postgresPodSpec(t, renderChart(t))["initContainers"]); len(got) != 0 {
		t.Fatalf("default render must not contain an init container (the chart has no root container by default), got %v", got)
	}

	spec := postgresPodSpec(t, renderChartWith(t, "--set", "postgresql.migrateOwnership=true"))
	inits := asList(spec["initContainers"])
	if len(inits) != 1 {
		t.Fatalf("migrateOwnership=true must render exactly one init container, got %d", len(inits))
	}
	c := asMap(inits[0])
	sc := asMap(c["securityContext"])
	if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || sc["privileged"] == true {
		t.Errorf("init container securityContext too loose: %v", sc)
	}
	caps := asMap(sc["capabilities"])
	if !hasString(caps["drop"], "ALL") {
		t.Error("init container must drop ALL capabilities")
	}
	if add := asList(caps["add"]); len(add) != 2 || !hasString(add, "CHOWN") || !hasString(add, "DAC_READ_SEARCH") {
		t.Errorf("init container capabilities.add must be exactly [CHOWN, DAC_READ_SEARCH], got %v", add)
	}
	var words []string
	for _, w := range asList(c["command"]) {
		s, _ := w.(string)
		words = append(words, s)
	}
	joined := " " + strings.Join(words, " ") + " "
	for _, want := range []string{" find /var/lib/postgresql/data ", " -xdev ", " -user 70 ", " -group 70 ", " chown -h 70:70 "} {
		if !strings.Contains(joined, want) {
			t.Errorf("init container command %q must contain %q", joined, want)
		}
	}
	for _, bad := range []string{" -L ", " -follow ", " -R "} {
		if strings.Contains(joined, bad) {
			t.Errorf("init container command %q must not contain %q", joined, bad)
		}
	}
	mounts := asList(c["volumeMounts"])
	if len(mounts) != 1 || asMap(mounts[0])["mountPath"] != "/var/lib/postgresql/data" {
		t.Errorf("init container must mount only the data volume, got %v", mounts)
	}

	// With persistence off there is no old volume to migrate: no init container.
	spec = postgresPodSpec(t, renderChartWith(t, "--set", "postgresql.migrateOwnership=true", "--set", "postgresql.persistence.enabled=false"))
	if got := asList(spec["initContainers"]); len(got) != 0 {
		t.Errorf("no init container expected without persistence, got %v", got)
	}

	// The uid is one value: pod, group and fsGroup follow it.
	spec = postgresPodSpec(t, renderChartWith(t, "--set", "postgresql.runAsUser=999"))
	pod := asMap(spec["securityContext"])
	for _, k := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
		if pod[k] != 999 {
			t.Errorf("postgresql.runAsUser=999: %s is %v", k, pod[k])
		}
	}
}
