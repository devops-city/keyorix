package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

type utcTimesPayload struct {
	Name         string
	LastActivity time.Time
	DeletedAt    *time.Time
	Nested       struct{ At time.Time }
	Items        []utcTimesItem
	Any          map[string]interface{}
	secret       string
}

type utcTimesItem struct{ ExpiresAt time.Time }

// #2951 item 4: one zone in every API payload. A time read back in the server's
// local offset must be emitted as UTC RFC 3339 ("Z"), wherever it sits in the
// response, while strings that merely look like timestamps are left alone.
func TestSendSuccessAndCreated_EmitEveryTimeInUTC(t *testing.T) {
	plus2 := time.FixedZone("", 2*3600)
	local := time.Date(2026, 10, 10, 3, 53, 40, 0, plus2)
	del := local.Add(time.Hour)
	look := "2026-10-10T03:53:40+02:00" // a secret value / description: not a time, must survive

	build := func() utcTimesPayload {
		p := utcTimesPayload{Name: look, LastActivity: local, DeletedAt: &del, secret: "x"}
		p.Nested.At = local
		p.Items = []utcTimesItem{{ExpiresAt: local}}
		p.Any = map[string]interface{}{"t": local, "ptr": &del, "s": look}
		return p
	}

	for name, send := range map[string]func(w *httptest.ResponseRecorder, d interface{}){
		"sendSuccess": func(w *httptest.ResponseRecorder, d interface{}) { sendSuccess(w, d, "") },
		"sendCreated": func(w *httptest.ResponseRecorder, d interface{}) { sendCreated(w, d, "") },
	} {
		p := build()
		w := httptest.NewRecorder()
		send(w, map[string]interface{}{"project": p, "list": []*utcTimesPayload{&p}})
		body := w.Body.String()

		if strings.Contains(body, "+02:00\"") && strings.Count(body, "+02:00") != strings.Count(body, look) {
			t.Errorf("%s: a time was emitted with a +02:00 offset: %s", name, body)
		}
		if !strings.Contains(body, `"LastActivity":"2026-10-10T01:53:40Z"`) {
			t.Errorf("%s: LastActivity not UTC: %s", name, body)
		}
		if !strings.Contains(body, `"DeletedAt":"2026-10-10T02:53:40Z"`) || !strings.Contains(body, `"ExpiresAt":"2026-10-10T01:53:40Z"`) ||
			!strings.Contains(body, `"At":"2026-10-10T01:53:40Z"`) || !strings.Contains(body, `"t":"2026-10-10T01:53:40Z"`) ||
			!strings.Contains(body, `"ptr":"2026-10-10T02:53:40Z"`) {
			t.Errorf("%s: nested/pointer/slice/map times not UTC: %s", name, body)
		}
		if !strings.Contains(body, `"Name":"`+look+`"`) || !strings.Contains(body, `"s":"`+look+`"`) {
			t.Errorf("%s: a string that looks like a timestamp was rewritten: %s", name, body)
		}
		// display only: the caller's own data is not mutated
		if p.LastActivity.Location() != plus2 || del.Location() != plus2 {
			t.Errorf("%s: payload was mutated in place", name)
		}
	}
}

type utcEmbedded struct{ CreatedAt time.Time }

type UTCEmbeddedExported struct{ UpdatedAt time.Time }

type utcOuter struct {
	UTCEmbeddedExported
	Deleted gorm.DeletedAt
	Raw     json.RawMessage
}

// AUDIT-UX-2: the encoders that bypassed utcTimes (the secret, folder, share and
// rotation-policy handlers' own helpers) now go through encodeJSONResponse, and
// utcTimes now converts a gorm.DeletedAt (a json.Marshaler that renders its own
// Time field) and the fields of an exported embedded struct. A raw JSON value
// (the stored audit diff) is passed through untouched.
func TestEncodeJSONResponse_ConvertsDeletedAtAndEmbeddedLeavesRawJSON(t *testing.T) {
	plus2 := time.FixedZone("", 2*3600)
	local := time.Date(2026, 10, 10, 3, 53, 40, 0, plus2)
	raw := json.RawMessage(`{"before":{"updated_at":"2026-10-10T03:53:40+02:00"}}`)
	v := utcOuter{UTCEmbeddedExported: UTCEmbeddedExported{UpdatedAt: local}, Deleted: gorm.DeletedAt{Time: local, Valid: true}, Raw: raw}

	var b strings.Builder
	if err := encodeJSONResponse(&b, SuccessResponse{Success: true, Data: v}); err != nil {
		t.Fatal(err)
	}
	body := b.String()
	for _, want := range []string{`"UpdatedAt":"2026-10-10T01:53:40Z"`, `"Deleted":"2026-10-10T01:53:40Z"`, `"updated_at":"2026-10-10T03:53:40+02:00"`} {
		if !strings.Contains(body, want) {
			t.Errorf("want %s in %s", want, body)
		}
	}
	if v.Deleted.Time.Location() != plus2 {
		t.Error("payload mutated in place")
	}
}

// utcTimes cannot rewrite an unexported embedded struct (reflection cannot set
// it, while encoding/json still promotes its fields): this pins that limit, which
// is why TestUTCStructural_ResponseTypesAreSeenByUTCTimes forbids the shape.
func TestUTCTimes_UnexportedEmbeddedIsALimitTheStructuralGuardCovers(t *testing.T) {
	type outer struct{ utcEmbedded }
	local := time.Date(2026, 10, 10, 3, 53, 40, 0, time.FixedZone("", 2*3600))
	var b strings.Builder
	if err := encodeJSONResponse(&b, outer{utcEmbedded{CreatedAt: local}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "+02:00") {
		t.Fatalf("utcTimes now converts unexported embedded structs (%s): relax the structural guard's embed rule", b.String())
	}
}
