package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// #2939/#2946: the server binds 127.0.0.1 unless server.http.host says
// otherwise. A config that is mounted into a container whose port is reached
// from outside it (published port, compose network) must therefore set the
// host explicitly, or the stack comes up unreachable. This family test covers
// every such checked-in config; add new container configs to the list.
func TestContainerConfigsBindAllInterfaces(t *testing.T) {
	root := filepath.Join("..")
	for _, rel := range []string{
		"keyorix.docker.yaml",            // docker-compose.yml backend, nginx reaches backend:8080
		"scripts/dast/keyorix-dast.yaml", // scripts/dast/docker-compose.yml, scanners reach keyorix:8080
	} {
		t.Run(rel, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- fixed repo-relative test fixtures
			if err != nil {
				t.Fatal(err)
			}
			var cfg struct {
				Server struct {
					HTTP struct {
						Host string `yaml:"host"`
					} `yaml:"http"`
				} `yaml:"server"`
			}
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Server.HTTP.Host != "0.0.0.0" {
				t.Fatalf("%s: server.http.host = %q; a containerised server reached from outside needs \"0.0.0.0\" (default is 127.0.0.1)", rel, cfg.Server.HTTP.Host)
			}
		})
	}
}

// The demo's host insert is a sed; if it silently matched nothing the demo
// would come up unreachable. up.sh must re-check after the sed and abort.
func TestDemoUpScriptVerifiesHostInsert(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "scripts", "demo", "up.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	sedAt := strings.Index(src, `sed -i "s|^    port:`)
	if sedAt < 0 {
		t.Fatal("up.sh no longer inserts server.http.host; update this test with the new mechanism")
	}
	after := src[sedAt:]
	checkAt := strings.Index(after, `grep -q "^    host: \"0.0.0.0\""`)
	exitAt := strings.Index(after, "exit 1")
	if checkAt < 0 || exitAt < 0 || exitAt < checkAt {
		t.Fatal("up.sh must grep for the inserted host line after the sed and exit 1 when it is missing")
	}
}
