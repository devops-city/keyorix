package deploy

import (
	"path"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The compose backend is read_only: true, and the secure baseline (folded into
// docker-compose.yml at v0.96.0) makes its entrypoint write files: the private
// config copy, the generated certificate, key and metrics token, the public CA
// copy. On a read-only root filesystem each of those must land on a writable
// mount, or `cp` fails under `set -e` and the backend restart-loops (#3053
// review). This checks every written path.
//
// What this does not cover: that the mount's owner lets uid 1001 write (verified
// on the e2e VM, see the release PR), or any other service.

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

// writableMount is one mount of the backend: a tmpfs, a named volume or a
// read-write bind mount.
type writableMount struct {
	target   string
	writable bool
}

func backendMounts(b composeBackend) []writableMount {
	var mounts []writableMount
	for _, spec := range b.Tmpfs {
		mounts = append(mounts, writableMount{target: strings.SplitN(spec, ":", 2)[0], writable: true})
	}
	for _, spec := range b.Volumes {
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
		mounts = append(mounts, m)
	}
	return mounts
}

// notWritable returns the files in paths that cannot be created on the backend:
// on a read-only root filesystem, the longest mount containing the file must be
// writable.
func notWritable(b composeBackend, paths []string) []string {
	if !b.ReadOnly {
		return nil
	}
	mounts := backendMounts(b)
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

// entrypointWrittenPaths lists the files the secure baseline has the entrypoint
// create. The config copy goes through "<path>.tmp" in the same directory.
func entrypointWrittenPaths(t *testing.T, b composeBackend) []string {
	t.Helper()
	env := b.Environment
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
		if err := yaml.Unmarshal([]byte(readRepoFile(t, "keyorix.docker.yaml")), &cfg); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{cfg.Server.HTTP.TLS.CertFile, cfg.Server.HTTP.TLS.KeyFile, cfg.Server.HTTP.MetricsTokenFile} {
			if p == "" {
				t.Fatal("keyorix.docker.yaml names no cert_file/key_file/metrics_token_file; the writability check would be vacuous")
			}
			paths = append(paths, p, p+".tmp")
		}
	}
	if len(paths) == 0 {
		t.Fatal("docker-compose.yml has the entrypoint write no files; the writability check would be vacuous")
	}
	for _, p := range paths {
		if !path.IsAbs(p) {
			t.Fatalf("%s is not an absolute path", p)
		}
	}
	return paths
}

func TestComposeBackend_EntrypointWritesLandOnWritableMounts(t *testing.T) {
	b := loadComposeBackend(t, readRepoFile(t, "docker-compose.yml"))
	if !b.ReadOnly {
		t.Skip("the backend is no longer read_only; revisit this guard")
	}
	paths := entrypointWrittenPaths(t, b)
	if bad := notWritable(b, paths); len(bad) > 0 {
		t.Fatalf("the backend is read_only but the entrypoint writes %v outside any writable mount (tmpfs or non-:ro volume); cp fails and the backend restart-loops", bad)
	}
}

// The control: the backend without its /app/data tmpfs (the shape #3053 had
// before the fix) is reported, so the test above is not vacuously green.
func TestComposeBackend_WritabilityCheckSeesAReadOnlyConfigDir(t *testing.T) {
	b := loadComposeBackend(t, readRepoFile(t, "docker-compose.yml"))
	paths := entrypointWrittenPaths(t, b)
	b.Tmpfs = nil
	bad := notWritable(b, paths)
	if len(bad) == 0 {
		t.Skip("the backend needs no tmpfs: every written path is on a volume")
	}
	if !strings.Contains(strings.Join(bad, " "), b.Environment["KEYORIX_CONFIG_PATH"]) {
		t.Fatalf("expected the config copy path to be reported without the tmpfs, got %v", bad)
	}
}
