package handlers

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
)

// The no-change fast path (needsUTC) must emit byte-identical JSON to the full
// reflective walk for every shape of response, in every zone mix.
func TestUTCTimes_FastPathBytesMatchFullWalk(t *testing.T) {
	plus2 := time.FixedZone("", 2*3600)
	zeroOff := time.FixedZone("Zero", 0)
	base := time.Date(2026, 10, 10, 3, 53, 40, 123456789, time.UTC)
	zones := map[string]*time.Location{"utc": time.UTC, "local-fixed-zero": zeroOff, "plus2": plus2, "time.Local": time.Local}

	for zname, loc := range zones {
		ts := base.In(loc)
		del := ts.Add(time.Hour)
		p := utcTimesPayload{Name: "n", LastActivity: ts, DeletedAt: &del, secret: "x"}
		p.Nested.At = ts
		p.Items = []utcTimesItem{{ExpiresAt: ts}}
		p.Any = map[string]interface{}{"t": ts, "ptr": &del, "s": "2026-10-10T03:53:40+02:00"}
		payloads := map[string]interface{}{
			"envelope":  map[string]interface{}{"data": p, "list": []*utcTimesPayload{&p}},
			"nil":       nil,
			"scalar":    "x",
			"bytes":     []byte("secret"),
			"time":      ts,
			"ptrtime":   &ts,
			"nilptr":    (*utcTimesPayload)(nil),
			"deleted":   utcOuter{Deleted: gorm.DeletedAt{Time: ts, Valid: true}},
			"emptyList": []utcTimesItem{},
		}
		for pname, v := range payloads {
			var fast, full bytes.Buffer
			if err := json.NewEncoder(&fast).Encode(utcTimes(v)); err != nil {
				t.Fatalf("%s/%s: %v", zname, pname, err)
			}
			ref := any(v)
			if v != nil {
				ref = utcTimesValue(reflectValueOf(v), 0).Interface()
			}
			if err := json.NewEncoder(&full).Encode(ref); err != nil {
				t.Fatalf("%s/%s: %v", zname, pname, err)
			}
			if !bytes.Equal(fast.Bytes(), full.Bytes()) {
				t.Errorf("%s/%s: fast path differs\nfast: %s\nfull: %s", zname, pname, fast.String(), full.String())
			}
		}
	}
}

func BenchmarkEncodeJSONResponse_UTCData(b *testing.B) {
	p := utcTimesPayload{Name: "n", LastActivity: time.Now().UTC()}
	p.Items = []utcTimesItem{{ExpiresAt: time.Now().UTC()}}
	v := map[string]interface{}{"success": true, "data": p}
	var buf bytes.Buffer
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = encodeJSONResponse(&buf, v)
	}
}

func BenchmarkEncodeJSONResponse_FullWalkReference(b *testing.B) {
	p := utcTimesPayload{Name: "n", LastActivity: time.Now().UTC()}
	p.Items = []utcTimesItem{{ExpiresAt: time.Now().UTC()}}
	v := map[string]interface{}{"success": true, "data": p}
	var buf bytes.Buffer
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = json.NewEncoder(&buf).Encode(utcTimesValue(reflectValueOf(v), 0).Interface())
	}
}

func reflectValueOf(v interface{}) reflect.Value { return reflect.ValueOf(v) }
