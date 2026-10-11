package deploy

import (
	"path"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The base compose backend is read_only: true. The secure override makes the
// entrypoint write files (the private config copy, the generated certificate,
// key and metrics token, the public CA copy); on a read-only root filesystem
// each of those must land on a writable mount, or `cp` fails under `set -e` and
// the backend restart-loops (#3053 review). This merges the two files the way
// `docker compose -f docker-compose.yml -f docker-compose.secure.yml` does for
// the keys involved and checks every written path.
//
// What this does not cover: that the mount's owner lets uid 1001 write (verified
// on the e2e VM, see the PR), or any other service.

type composeBackend struct {
	ReadOnly    bool              `yaml:"read_only"`
	Tmpfs       []string          `yaml:"tmpfs"`
	Volumes     []string          `yaml:"volumes"`
	Environment map[string]string `yaml:"environment"`
}

func loadComposeBackend(t *testing.T, raw string) composeBackend {
	t.Helper()
	var f struct {
		Services struct {
			Backend composeBackend `yaml:"backend"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatal(err)
	}
	return f.Services.Backend
}

// writableMount is one mount of the merged backend: a tmpfs, a named volume or
// a read-write bind mount.
type writableMount struct {
	target   string
	writable bool
}

func mergedBackendMounts(base, override composeBackend) []writableMount {
	var mounts []writableMount
	for _, spec := range append(append([]string{}, base.Tmpfs...), override.Tmpfs...) {
		mounts = append(mounts, writableMount{target: strings.SplitN(spec, ":", 2)[0], writable: true})
	}
	// A later volume with the same target replaces the earlier one (compose
	// merges volumes by target).
	byTarget := map[string]writableMount{}
	var order []string
	for _, spec := range append(append([]string{}, base.Volumes...), override.Volumes...) {
		parts := strings.Split(spec, ":")
		if len(parts) < 2 {
			continue
		}
		m := writableMount{target: parts[1], writable: true}
		if len(parts) > 2 {
			for _, opt := range strings.Split(parts[2], ",") {
				if opt == "ro" {
					m.writable = false
				}
			}
		}
		if _, ok := byTarget[m.target]; !ok {
			order = append(order, m.target)
		}
		byTarget[m.target] = m
	}
	for _, target := range order {
		mounts = append(mounts, byTarget[target])
	}
	return mounts
}

// notWritable returns the files in paths that cannot be created on the merged
// backend: on a read-only root filesystem, the longest mount containing the
// file must be writable.
func notWritable(base, override composeBackend, paths []string) []string {
	if !base.ReadOnly {
		return nil
	}
	mounts := mergedBackendMounts(base, override)
	var bad []string
	for _, p := range paths {
		best := -1
		ok := false
		for _, m := range mounts {
			if (p == m.target || strings.HasPrefix(p, strings.TrimSuffix(m.target, "/")+"/")) && len(m.target) > best {
				best, ok = len(m.target), m.writable
			}
		}
		if !ok {
			bad = append(bad, p)
		}
	}
	return bad
}

// entrypointWrittenPaths lists the files the secure override has the entrypoint
// create. The config copy goes through "<path>.tmp" in the same directory.
func entrypointWrittenPaths(t *testing.T, override composeBackend) []string {
	t.Helper()
	env := override.Environment
	var paths []string
	if p := env["KEYORIX_CONFIG_PATH"]; p != "" {
		paths = append(paths, p, p+".tmp")
	}
	if p := env["KEYORIX_PUBLIC_CA_FILE"]; p != "" {
		paths = append(paths, p, p+".tmp")
	}
	if env["KEYORIX_INIT_SECURE_FILES"] == "true" {
		var cfg struct {
			Server struct {
				HTTP struct {
					TLS struct {
						CertFile string `yaml:"cert_file"`
						KeyFile  string `yaml:"key_file"`
					} `yaml:"tls"`
					MetricsTokenFile string `yaml:"metrics_token_file"`
				} `yaml:"http"`
			} `yaml:"server"`
		}
		if err := yaml.Unmarshal([]byte(readRepoFile(t, "keyorix.docker.secure.yaml")), &cfg); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{cfg.Server.HTTP.TLS.CertFile, cfg.Server.HTTP.TLS.KeyFile, cfg.Server.HTTP.MetricsTokenFile} {
			if p == "" {
				t.Fatal("keyorix.docker.secure.yaml names no cert_file/key_file/metrics_token_file; the writability check would be vacuous")
			}
			paths = append(paths, p, p+".tmp")
		}
	}
	if len(paths) == 0 {
		t.Fatal("docker-compose.secure.yml has the entrypoint write no files; the writability check would be vacuous")
	}
	for _, p := range paths {
		if !path.IsAbs(p) {
			t.Fatalf("%s is not an absolute path", p)
		}
	}
	return paths
}

func TestComposeSecureBackend_EntrypointWritesLandOnWritableMounts(t *testing.T) {
	base := loadComposeBackend(t, readRepoFile(t, "docker-compose.yml"))
	override := loadComposeBackend(t, readRepoFile(t, "docker-compose.secure.yml"))
	if !base.ReadOnly {
		t.Skip("the base backend is no longer read_only; revisit this guard")
	}
	paths := entrypointWrittenPaths(t, override)
	if bad := notWritable(base, override, paths); len(bad) > 0 {
		t.Fatalf("the backend is read_only but the entrypoint writes %v outside any writable mount (tmpfs or non-:ro volume); cp fails and the backend restart-loops", bad)
	}
}

// The control: the override without its tmpfs (the shape this PR had before the
// fix) is reported, so the test above is not vacuously green.
func TestComposeSecureBackend_WritabilityCheckSeesAReadOnlyConfigDir(t *testing.T) {
	base := loadComposeBackend(t, readRepoFile(t, "docker-compose.yml"))
	override := loadComposeBackend(t, readRepoFile(t, "docker-compose.secure.yml"))
	paths := entrypointWrittenPaths(t, override)
	override.Tmpfs = nil
	bad := notWritable(base, override, paths)
	if len(bad) == 0 {
		t.Skip("the override needs no tmpfs: every written path is on a volume")
	}
	if !strings.Contains(strings.Join(bad, " "), override.Environment["KEYORIX_CONFIG_PATH"]) {
		t.Fatalf("expected the config copy path to be reported without the tmpfs, got %v", bad)
	}
}

// The override mounts web/nginx.conf from this checkout so that any web image
// version works (the pinned 0.95.3 predates the keyorix-backend.conf include).
// Every file that nginx.conf includes must then also come from the checkout or
// be generated by a script the override mounts, or an old image fails to start
// ("open() ... nginx-hsts.conf failed"): the HSTS conf is generated at start by
// a script only newer images ship.
func TestComposeSecureWeb_MountedNginxConfIncludesAreProvided(t *testing.T) {
	var f struct {
		Services struct {
			Web struct {
				Volumes []string `yaml:"volumes"`
				Tmpfs   []string `yaml:"tmpfs"`
			} `yaml:"web"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "docker-compose.secure.yml")), &f); err != nil {
		t.Fatal(err)
	}
	var base struct {
		Services struct {
			Web struct {
				Tmpfs []string `yaml:"tmpfs"`
			} `yaml:"web"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "docker-compose.yml")), &base); err != nil {
		t.Fatal(err)
	}
	mountedNginxConf := false
	mountedSources := map[string]string{} // container target -> repo-relative source
	for _, v := range f.Services.Web.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		mountedSources[parts[1]] = strings.TrimPrefix(parts[0], "./")
		if parts[1] == "/etc/nginx/nginx.conf" {
			mountedNginxConf = true
		}
	}
	if !mountedNginxConf {
		t.Skip("the override no longer mounts nginx.conf; the web image brings its own includes")
	}
	includes := regexp.MustCompile(`(?m)^\s*include\s+(/etc/nginx/[^;\s]+);`).FindAllStringSubmatch(readRepoFile(t, "web/nginx.conf"), -1)
	if len(includes) == 0 {
		t.Fatal("web/nginx.conf has no include of a /etc/nginx file; the check would be vacuous")
	}
	var generators []string // content of mounted /docker-entrypoint.d scripts
	for target, src := range mountedSources {
		if strings.HasPrefix(target, "/docker-entrypoint.d/") {
			generators = append(generators, readRepoFile(t, src))
		}
	}
	for _, m := range includes {
		inc := m[1]
		if inc == "/etc/nginx/mime.types" { // part of the nginx base image, every version
			continue
		}
		if _, ok := mountedSources[inc]; ok {
			continue
		}
		generated := false
		for _, g := range generators {
			if strings.Contains(g, inc) {
				generated = true
			}
		}
		if !generated {
			t.Errorf("web/nginx.conf includes %s, but docker-compose.secure.yml neither mounts it nor mounts a /docker-entrypoint.d script that generates it; a web image without it fails to start", inc)
		}
	}
	// A generated include needs a writable directory (the base web is read_only).
	hasTmpfs := false
	for _, spec := range base.Services.Web.Tmpfs {
		if strings.HasPrefix(spec, "/etc/nginx/keyorix:") {
			hasTmpfs = true
		}
	}
	if len(generators) > 0 && !hasTmpfs {
		t.Error("the override mounts a generator for /etc/nginx/keyorix/*, but the base web has no tmpfs there")
	}
}
