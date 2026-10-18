// Command cfgkeys prints every configuration key of the Keyorix config struct
// tree (internal/config.Config), one per line: "<yaml.path>\tdefault" or
// "<yaml.path>\tno-default".
//
// A key counts as having a default when its value is non-zero in either
//   - the config produced by config.Load of an empty file (defaults the loader
//     sets, including the secure-by-default booleans), or
//   - the secure baseline config that "keyorix-server admin init" writes
//     (configs.DefaultConfigTemplate), i.e. what a fresh install actually gets.
//
// A default applied later, at the key's use site, is not visible to either and
// the key reports no-default; that is a stated limit of the metric.
//
// scripts/metrics/complexity.sh copies this directory into a temporary
// worktree of the ref being measured, so the same source measures old releases.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/keyorixhq/keyorix/configs"
	"github.com/keyorixhq/keyorix/internal/config"
)

func main() {
	dir, err := os.MkdirTemp("", "cfgkeys-")
	if err != nil {
		fail(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	empty, err := load(dir, "empty.yaml", nil)
	if err != nil {
		// Without defaults every key would read "no-default": a silently wrong
		// number. Fail instead.
		fail(fmt.Errorf("loading an empty config to read defaults: %w", err))
	}
	baseline, err := load(dir, "baseline.yaml", configs.DefaultConfigTemplate)
	if err != nil {
		fail(fmt.Errorf("loading the admin-init baseline config: %w", err))
	}

	typ := reflect.TypeOf(*empty)
	fromEmpty := walkKeys(typ, reflect.ValueOf(*empty), "")
	fromBaseline := walkKeys(typ, reflect.ValueOf(*baseline), "")
	hasBaseline := map[string]bool{}
	for _, k := range fromBaseline {
		hasBaseline[k.Path] = k.HasDefault
	}
	for _, k := range fromEmpty {
		state := "no-default"
		if k.HasDefault || hasBaseline[k.Path] {
			state = "default"
		}
		fmt.Printf("%s\t%s\n", k.Path, state)
	}
}

func load(dir, name string, content []byte) (*config.Config, error) {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		return nil, err
	}
	return config.Load(p)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cfgkeys:", err)
	os.Exit(1)
}
