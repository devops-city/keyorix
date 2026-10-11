package handlers

import (
	"encoding/json"
	"io"
	"reflect"
	"time"

	"gorm.io/gorm"
)

// Every JSON response this package writes carries UTC RFC 3339 times
// (docs/API_REFERENCE.md, "Timestamps"). encodeJSONResponse is the one place a
// handler encodes JSON onto an http.ResponseWriter, and it runs utcTimes first.
// Guards: server/faultops TestUTCResponseGuard (every GET route, seeded world,
// non-UTC process zone) and utc_response_structural_guard_test.go (no encoder
// bypasses encodeJSONResponse; every json.Marshaler a response can reach is
// reviewed).
//
// Times read back from the database carry whatever zone they were stored in
// (gorm stamps CreatedAt/UpdatedAt in the server's local zone, SQLite hands the
// offset back), so one response could mix "+02:00" and "Z" for the same kind of
// field (#2951). sendSuccess/sendCreated pass their payload through utcTimes so
// every time.Time in a response is emitted in UTC. This is display only: it
// returns a converted COPY, never mutates the caller's data, and nothing stored
// (including anything hashed, such as audit event_time) changes.

var (
	timeType      = reflect.TypeOf(time.Time{})
	marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
)

// utcTimesWalkMarshalers are json.Marshaler types whose MarshalJSON renders
// their own exported time fields, so utcTimes converts those fields like a plain
// struct's. Any other Marshaler is left alone (its wire format is its own); the
// structural guard requires every Marshaler a response can reach to be either
// listed here or reviewed as carrying no local time.
var utcTimesWalkMarshalers = map[reflect.Type]bool{
	reflect.TypeOf(gorm.DeletedAt{}): true, // MarshalJSON emits .Time when .Valid
}

// encodeJSONResponse writes v as the JSON body of w, with every time.Time in it
// converted to UTC. Every JSON response in this package goes through here
// (TestUTCStructural_EveryResponseEncoderIsEncodeJSONResponse).
func encodeJSONResponse(w io.Writer, v interface{}) error {
	return json.NewEncoder(w).Encode(utcTimes(v))
}

const utcTimesMaxDepth = 12

// utcTimes returns v with every time.Time (and *time.Time) reachable through
// exported struct fields, slices, arrays, maps, pointers and interfaces
// converted to UTC. Values that carry their own json.Marshaler (other than
// time.Time) are left alone so custom wire formats are not second-guessed.
func utcTimes(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	return utcTimesValue(reflect.ValueOf(v), 0).Interface()
}

func utcTimesValue(v reflect.Value, depth int) reflect.Value {
	if !v.IsValid() || depth > utcTimesMaxDepth {
		return v
	}
	t := v.Type()
	if t == timeType {
		return reflect.ValueOf(v.Interface().(time.Time).UTC())
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || !canHoldTime(t.Elem(), 0) {
			return v
		}
		if t.Implements(marshalerType) && t.Elem() != timeType && !utcTimesWalkMarshalers[t.Elem()] {
			return v
		}
		nv := reflect.New(t.Elem())
		nv.Elem().Set(utcTimesValue(v.Elem(), depth+1))
		return nv
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		nv := reflect.New(t).Elem()
		nv.Set(utcTimesValue(v.Elem(), depth+1))
		return nv
	case reflect.Struct:
		if !canHoldTime(t, 0) || (t.Implements(marshalerType) && !utcTimesWalkMarshalers[t]) {
			return v
		}
		nv := reflect.New(t).Elem()
		nv.Set(v) // shallow copy keeps unexported fields as they were
		for i := 0; i < t.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			nv.Field(i).Set(utcTimesValue(v.Field(i), depth+1))
		}
		return nv
	case reflect.Slice:
		if v.IsNil() || !canHoldTime(t.Elem(), 0) {
			return v
		}
		nv := reflect.MakeSlice(t, v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			nv.Index(i).Set(utcTimesValue(v.Index(i), depth+1))
		}
		return nv
	case reflect.Array:
		if !canHoldTime(t.Elem(), 0) {
			return v
		}
		nv := reflect.New(t).Elem()
		for i := 0; i < v.Len(); i++ {
			nv.Index(i).Set(utcTimesValue(v.Index(i), depth+1))
		}
		return nv
	case reflect.Map:
		if v.IsNil() || !canHoldTime(t.Elem(), 0) {
			return v
		}
		nv := reflect.MakeMapWithSize(t, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			nv.SetMapIndex(iter.Key(), utcTimesValue(iter.Value(), depth+1))
		}
		return nv
	}
	return v
}

// canHoldTime reports whether a value of type t could contain a time.Time, so
// the walk skips plain strings, numbers and byte slices (secret values, hashes)
// without copying them. Interfaces can hold anything, so they always qualify.
func canHoldTime(t reflect.Type, depth int) bool {
	if depth > utcTimesMaxDepth {
		return true
	}
	if t == timeType {
		return true
	}
	switch t.Kind() {
	case reflect.Interface:
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return canHoldTime(t.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() && canHoldTime(t.Field(i).Type, depth+1) {
				return true
			}
		}
	}
	return false
}
