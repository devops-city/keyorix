package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

type inner struct {
	Port    int    `yaml:"port"`
	Host    string `yaml:"host"`
	Skipped string `yaml:"-"`
	hidden  string //nolint:unused // unexported fields are not config keys
}

type base struct {
	Shared bool `yaml:"shared"`
}

type fixture struct {
	Name     string            `yaml:"name"`
	NoTag    string            // yaml.v3 lower-cases the field name
	Inner    inner             `yaml:"inner"`
	Ptr      *inner            `yaml:"ptr,omitempty"`
	List     []inner           `yaml:"list"`
	Tags     []string          `yaml:"tags"`
	Labels   map[string]string `yaml:"labels"`
	ByName   map[string]inner  `yaml:"by_name"`
	Timeout  time.Duration     `yaml:"timeout"`
	When     time.Time         `yaml:"when"`
	Any      any               `yaml:"any"`
	Embedded base              `yaml:",inline"`
}

func paths(keys []key) []string {
	var p []string
	for _, k := range keys {
		p = append(p, k.Path)
	}
	return p
}

func TestWalkKeys_ShapesAndNames(t *testing.T) {
	got := paths(walkKeys(reflect.TypeFor[fixture](), reflect.Value{}, ""))
	want := []string{
		"any",
		"by_name.*.host", "by_name.*.port",
		"inner.host", "inner.port",
		"labels",
		"list[].host", "list[].port",
		"name",
		"notag",
		"ptr.host", "ptr.port",
		"shared",
		"tags",
		"timeout",
		"when",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestWalkKeys_DefaultsComeFromNonZeroValues(t *testing.T) {
	v := fixture{Name: "x", Inner: inner{Port: 8080}, Ptr: &inner{Host: "h"}, Timeout: time.Second}
	got := map[string]bool{}
	for _, k := range walkKeys(reflect.TypeOf(v), reflect.ValueOf(v), "") {
		got[k.Path] = k.HasDefault
	}
	for path, want := range map[string]bool{
		"name": true, "inner.port": true, "inner.host": false,
		"ptr.host": true, "ptr.port": false, "timeout": true,
		"tags":        false,
		"list[].port": false, // element keys never carry a default
	} {
		if got[path] != want {
			t.Errorf("%s: HasDefault = %v, want %v", path, got[path], want)
		}
	}
}

func TestWalkKeys_NilPointerContributesKeysWithoutDefault(t *testing.T) {
	v := fixture{}
	var found bool
	for _, k := range walkKeys(reflect.TypeOf(v), reflect.ValueOf(v), "") {
		if k.Path == "ptr.port" {
			found = true
			if k.HasDefault {
				t.Error("nil pointer field must not report a default")
			}
		}
	}
	if !found {
		t.Fatal("keys behind a nil pointer must still be counted")
	}
}

type node struct {
	Value string  `yaml:"value"`
	Next  *node   `yaml:"next"`
	Kids  []*node `yaml:"kids"`
}

func TestWalkKeys_SelfReferencingTypeTerminates(t *testing.T) {
	got := paths(walkKeys(reflect.TypeFor[node](), reflect.Value{}, ""))
	want := []string{"kids[]", "next", "value"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Guards the real struct: if the walk silently collapsed (a tag convention
// change, an unsupported shape that turns the whole tree into one leaf) the
// count would fall to a handful. The floor is far below today's number so it
// does not need updating as config grows; it only trips on a broken walk.
func TestWalkKeys_RealConfigIsWalkedDeeply(t *testing.T) {
	keys := walkKeys(reflect.TypeFor[config.Config](), reflect.ValueOf(config.Config{}), "")
	if len(keys) < 150 {
		t.Fatalf("config.Config walked to only %d keys; the walk is broken", len(keys))
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k.Path] {
			t.Errorf("duplicate key path %q", k.Path)
		}
		seen[k.Path] = true
	}
	for _, must := range []string{"server.http.port", "storage.type", "security.require_mfa"} {
		if !seen[must] {
			t.Errorf("expected well-known key %q in the walk", must)
		}
	}
}
