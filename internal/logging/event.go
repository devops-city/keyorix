package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// Event logs msg at level with the context's request fields and the extra key/value
// pairs kv (alternating string keys and values). In JSON mode it writes one JSON
// object:
//
//	{"ts":...,"level":...,"msg":...,"request_id":...,"principal_type":...,"route":...,<kv>}
//
// with request_id, principal_type and route present only when known. In text mode it
// writes the familiar single line `LEVEL msg request_id=.. principal_type=.. route=..
// key=value`, so the same call site serves both formats. msg and every string value
// pass through Redact. Extra keys that would shadow a reserved field are dropped.
func Event(ctx context.Context, level, msg string, kv ...any) {
	log.Print(Line(ctx, level, msg, kv...))
}

// Line is Event without the write: it returns the line Event would log (including
// the internal marker in JSON mode, so the standard logger's JSON adapter passes it
// through verbatim). It exists for writers that bypass the standard logger's mutex,
// such as the HTTP access log; pass its result to the same destination Event uses
// (log.Writer()) and to nothing else.
func Line(ctx context.Context, level, msg string, kv ...any) string {
	f := FromContext(ctx)
	if jsonMode.Load() {
		return lineMarker + eventJSON(level, msg, f, kv)
	}
	var b strings.Builder
	b.WriteString(strings.ToUpper(level))
	b.WriteByte(' ')
	b.WriteString(Redact(msg))
	writeKV(&b, "request_id", f.RequestID)
	writeKV(&b, "principal_type", f.PrincipalType)
	writeKV(&b, "route", f.Route)
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok || reserved[k] {
			continue
		}
		writeKV(&b, k, fmt.Sprint(kv[i+1]))
	}
	return b.String()
}

var reserved = map[string]bool{
	"ts": true, "level": true, "msg": true, "request_id": true, "principal_type": true, "route": true,
}

func writeKV(b *strings.Builder, k, v string) {
	if v == "" {
		return
	}
	b.WriteByte(' ')
	b.WriteString(k)
	b.WriteByte('=')
	b.WriteString(Redact(strings.NewReplacer("\n", " ", "\r", " ").Replace(v)))
}

// eventJSON builds the object by hand so field order is stable (ts, level, msg, request
// fields, then kv in call order), which keeps lines greppable and diffable.
func eventJSON(level, msg string, f Fields, kv []any) string {
	var b bytes.Buffer
	b.WriteByte('{')
	put := func(k string, v any, first bool) {
		if !first {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		if s, ok := v.(string); ok {
			v = Redact(s)
		}
		vb, err := json.Marshal(v)
		if err != nil {
			vb, _ = json.Marshal(fmt.Sprint(v))
		}
		b.Write(vb)
	}
	put("ts", now(), true)
	put("level", level, false)
	put("msg", msg, false)
	if f.RequestID != "" {
		put("request_id", f.RequestID, false)
	}
	if f.PrincipalType != "" {
		put("principal_type", f.PrincipalType, false)
	}
	if f.Route != "" {
		put("route", f.Route, false)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok || reserved[k] {
			continue
		}
		put(k, kv[i+1], false)
	}
	b.WriteByte('}')
	return b.String()
}
