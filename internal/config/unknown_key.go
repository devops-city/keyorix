package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// unknownFieldRE matches yaml.v3's strict-decode message for a key the target
// struct has no field for: "field webauthn not found in type config.SecurityConfig".
var unknownFieldRE = regexp.MustCompile(`field (\S+) not found in type ([\w.]+)`)

// describeUnknownKeys rewrites yaml.v3's "field X not found in type
// config.SomeGoType" into the YAML section an operator writes ("unknown key "X"
// under security"), keeping the "line N:" prefix (BOOT-REFUSALS-1 item 5: the Go
// type name made the operator guess which section was meant). Any other error, and
// any type this config does not reach, is returned unchanged.
func describeUnknownKeys(err error) error {
	te, ok := errors.AsType[*yaml.TypeError](err)
	if !ok {
		return err
	}
	sections := yamlSections()
	out := make([]string, len(te.Errors))
	changed := false
	for i, e := range te.Errors {
		out[i] = unknownFieldRE.ReplaceAllStringFunc(e, func(m string) string {
			sm := unknownFieldRE.FindStringSubmatch(m)
			paths := sections[sm[2]]
			if len(paths) == 0 {
				return m
			}
			changed = true
			where := "at the top level of the file"
			if paths[0] != "" {
				where = "under " + strings.Join(paths, " or ")
			}
			return fmt.Sprintf("unknown key %q %s (check its spelling and section in docs/CONFIGURATION.md)", sm[1], where)
		})
	}
	if !changed {
		return err
	}
	return &yaml.TypeError{Errors: out}
}

var (
	yamlSectionsOnce sync.Once
	yamlSectionsMap  map[string][]string
)

// yamlSections maps each struct type reachable from Config (by its reflect name,
// e.g. "config.SecurityConfig") to the dotted YAML paths it is decoded at, sorted
// ("" is the top level). A slice of structs is written "path[]", a map of structs
// "path.<name>". Derived from the yaml tags, so it cannot drift from the struct.
func yamlSections() map[string][]string {
	yamlSectionsOnce.Do(func() {
		yamlSectionsMap = map[string][]string{}
		walkYAMLSections(reflect.TypeFor[Config](), "", nil)
		for k := range yamlSectionsMap {
			slices.Sort(yamlSectionsMap[k])
			yamlSectionsMap[k] = slices.Compact(yamlSectionsMap[k])
		}
	})
	return yamlSectionsMap
}

func walkYAMLSections(t reflect.Type, path string, stack []reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || slices.Contains(stack, t) {
		return // a recursive type (key_provider.fallbacks) is recorded at its first path only
	}
	yamlSectionsMap[t.String()] = append(yamlSectionsMap[t.String()], path)
	walkYAMLFields(t, path, append(stack, t))
}

// walkYAMLFields walks t's fields at path; an inlined struct's fields share it.
func walkYAMLFields(t reflect.Type, path string, stack []reflect.Type) {
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if strings.Contains(opts, "inline") && ft.Kind() == reflect.Struct {
			walkYAMLFields(ft, path, stack)
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		child := name
		if path != "" {
			child = path + "." + name
		}
	unwrap:
		for {
			switch ft.Kind() {
			case reflect.Pointer:
			case reflect.Slice, reflect.Array:
				child += "[]"
			case reflect.Map:
				child += ".<name>"
			default:
				break unwrap
			}
			ft = ft.Elem()
		}
		walkYAMLSections(ft, child, stack)
	}
}
