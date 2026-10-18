package main

import (
	"encoding"
	"reflect"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// key is one settable configuration key: a leaf of the config struct tree.
type key struct {
	Path       string
	HasDefault bool // value is non-zero in the config produced by loading an empty file
}

var (
	textUnmarshaler = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	yamlUnmarshaler = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()
	timeType        = reflect.TypeOf(time.Time{})
)

// walkKeys returns every leaf key reachable from t, using the yaml tags the
// config loader decodes with (yaml.v3 rules: tag name, else lower-cased field
// name; "-" skips; ",inline" flattens). def is the value carrying the defaults
// (may be the zero Value, meaning "no defaults known": every key reports false).
//
// Shapes, stated because an enumeration is only as complete as the shapes it knows:
//   - struct: recursed into, the struct itself is not a key
//   - pointer: followed; a nil pointer contributes its fields with no default
//   - slice/array of struct: keys of the element appear once as "path[].child"
//   - map with struct values: keys of the value appear once as "path.*.child"
//   - everything else (scalars, slices of scalars, maps of scalars, interface,
//     time.Time, any type with its own YAML/text unmarshaller): one leaf key
func walkKeys(t reflect.Type, def reflect.Value, prefix string) []key {
	var out []key
	walkInto(t, def, prefix, &out, map[reflect.Type]bool{})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func isLeafType(t reflect.Type) bool {
	if t == timeType {
		return true
	}
	for _, iface := range []reflect.Type{textUnmarshaler, yamlUnmarshaler} {
		if t.Implements(iface) || reflect.PointerTo(t).Implements(iface) {
			return true
		}
	}
	return false
}

func walkInto(t reflect.Type, def reflect.Value, path string, out *[]key, onPath map[reflect.Type]bool) {
	if t.Kind() == reflect.Pointer {
		var inner reflect.Value
		if def.IsValid() && !def.IsNil() {
			inner = def.Elem()
		}
		walkInto(t.Elem(), inner, path, out, onPath)
		return
	}
	leaf := func() {
		d := def.IsValid() && !def.IsZero()
		*out = append(*out, key{Path: path, HasDefault: d})
	}
	if isLeafType(t) {
		leaf()
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		// A struct type that contains itself (directly or through a pointer,
		// slice or map) would recurse forever; its own recurrence is one leaf.
		if onPath[t] {
			leaf()
			return
		}
		onPath[t] = true
		defer delete(onPath, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, inline, skip := yamlName(f)
			if skip {
				continue
			}
			var fd reflect.Value
			if def.IsValid() {
				fd = def.Field(i)
			}
			child := path
			if !inline {
				child = join(path, name)
			}
			walkInto(f.Type, fd, child, out, onPath)
		}
	case reflect.Slice, reflect.Array:
		if elem := derefType(t.Elem()); elem.Kind() == reflect.Struct && !isLeafType(elem) {
			walkInto(elem, reflect.Value{}, path+"[]", out, onPath)
			return
		}
		leaf()
	case reflect.Map:
		if elem := derefType(t.Elem()); elem.Kind() == reflect.Struct && !isLeafType(elem) {
			walkInto(elem, reflect.Value{}, path+".*", out, onPath)
			return
		}
		leaf()
	default:
		leaf()
	}
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// yamlName applies yaml.v3's field naming: the tag's first element, else the
// lower-cased field name; "-" skips the field; the "inline" option flattens it.
func yamlName(f reflect.StructField) (name string, inline, skip bool) {
	tag := f.Tag.Get("yaml")
	if tag == "-" {
		return "", false, true
	}
	parts := strings.Split(tag, ",")
	for _, opt := range parts[1:] {
		if opt == "inline" {
			inline = true
		}
	}
	name = parts[0]
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	return name, inline, false
}
