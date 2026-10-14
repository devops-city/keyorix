package handlers

import (
	"reflect"
	"time"
)

// needsUTC reports whether utcTimesValue would change anything in v: it follows
// exactly the traversal rules of utcTimesValue (same depth cap, same Marshaler
// and canHoldTime skips) but only reads, so a response whose times are already
// at a zero offset is encoded without the reflective copy. A time at a zero
// offset marshals to the same bytes ("Z") whatever its Location, so skipping the
// UTC() call for it cannot change the wire output.
func needsUTC(v reflect.Value, depth int) bool {
	if !v.IsValid() || depth > utcTimesMaxDepth {
		return false
	}
	t := v.Type()
	if t == timeType {
		_, off := v.Interface().(time.Time).Zone()
		return off != 0
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || !canHoldTime(t.Elem(), 0) {
			return false
		}
		if t.Implements(marshalerType) && t.Elem() != timeType && !utcTimesWalkMarshalers[t.Elem()] {
			return false
		}
		return needsUTC(v.Elem(), depth+1)
	case reflect.Interface:
		if v.IsNil() {
			return false
		}
		return needsUTC(v.Elem(), depth+1)
	case reflect.Struct:
		if !canHoldTime(t, 0) || (t.Implements(marshalerType) && !utcTimesWalkMarshalers[t]) {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() && needsUTC(v.Field(i), depth+1) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		if (v.Kind() == reflect.Slice && v.IsNil()) || !canHoldTime(t.Elem(), 0) {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if needsUTC(v.Index(i), depth+1) {
				return true
			}
		}
	case reflect.Map:
		if v.IsNil() || !canHoldTime(t.Elem(), 0) {
			return false
		}
		iter := v.MapRange()
		for iter.Next() {
			if needsUTC(iter.Value(), depth+1) {
				return true
			}
		}
	}
	return false
}
