package backupfmt

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// rowFieldsToMarshal returns every field on row's struct type that GORM
// persists as a real column, keyed by its Go field name -- NOT by that
// field's own `json` struct tag, and specifically NOT skipping a
// `json:"-"` field.
//
// Why this is its own encoder rather than plain json.Marshal(row):
// internal/storage/models uses `json:"-"` extensively (35+ fields) to keep
// sensitive/internal columns out of HTTP API responses -- SecretVersion.
// EncryptedValue, User.PasswordHash, Role.NameFolded, every *TokenHash,
// MFASecret.SecretEnc, and more. That tag means exactly what it says for an
// API response; it does NOT mean "this column doesn't need to be backed
// up". A backup/restore row encoding built on plain json.Marshal/Unmarshal
// silently drops every one of those columns on write and leaves them at
// their Go zero value on read -- found live via a version-skip upgrade
// proof (H6) that restored a real, multi-role database into Postgres and
// hit a UNIQUE constraint violation on Role.NameFolded (every restored role
// row had NameFolded="", since json:"-" dropped it) -- and confirmed via a
// direct SecretVersion.EncryptedValue round-trip test that a real
// encrypted secret VALUE came back completely empty. This was present
// since H1 and went undetected through H3's and H5's round-trip tests
// because neither ever created a real row in a `json:"-"`-bearing table
// with unique/multi-row content and checked its value survived.
//
// Skips only genuinely non-persisted fields (gorm:"-") and unexported
// fields -- the same two exclusions storage.AllModels()'s own doc comment
// and this package's property-test seeder (server/admin) already use, so
// "every real DB column, nothing else" is applied consistently everywhere
// this codebase enumerates a model's fields.
func rowFieldsToMarshal(row any) (map[string]any, error) {
	v := reflect.ValueOf(row)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, fmt.Errorf("row is a nil pointer")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("row must be a struct or pointer to struct, got %s", v.Kind())
	}
	t := v.Type()
	out := make(map[string]any, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		gormTag := f.Tag.Get("gorm")
		if gormTag == "-" || strings.HasPrefix(gormTag, "-:") {
			continue
		}
		out[f.Name] = normalizeTimesToUTC(v.Field(i)).Interface()
	}
	return out, nil
}

var timeType = reflect.TypeFor[time.Time]()

// normalizeTimesToUTC returns v with every time.Time reachable through it
// (directly, behind a pointer, or inside a struct such as sql.NullTime /
// gorm.DeletedAt) converted to UTC. v itself is never mutated.
//
// Why: a database driver hands back times in time.Local. For instants whose
// Local offset is a seconds-resolution local-mean-time offset (any pre-1900
// instant, notably the zero time.Time that audit rows written without an
// EventTime carry, e.g. Europe/Berlin +00:53:28), encoding/json's RFC 3339
// output has only minute resolution, so the written offset is truncated and the
// decoded instant is shifted by the dropped seconds (FIX-3088: Postgres
// restore on a non-UTC host corrupted audit row 1 and verify-audit reported
// BROKEN). UTC has a zero offset everywhere, so the instant survives exactly
// and the encoding no longer depends on the host's TZ (which also keeps the
// manifest's per-table hash host-independent). This applies to every model and
// column, not to any one table.
func normalizeTimesToUTC(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Struct:
		if v.Type() == timeType {
			return reflect.ValueOf(v.Interface().(time.Time).UTC())
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(v) // keeps unexported fields as they are
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			out.Field(i).Set(normalizeTimesToUTC(v.Field(i)))
		}
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		p := reflect.New(v.Type().Elem())
		p.Elem().Set(normalizeTimesToUTC(v.Elem()))
		return p
	default:
		return v
	}
}

// marshalRow encodes row (a model struct or pointer to one) as a JSON
// object keyed by Go field name via rowFieldsToMarshal -- every real column,
// regardless of any `json:"-"`/`json:"othername"` tag on the model. Map key
// order in encoding/json is always alphabetical for map[string]any, so this
// is deterministic across runs/builds, matching writer.go's own
// determinism requirement for the manifest's per-table hash.
func marshalRow(row any) ([]byte, error) {
	fields, err := rowFieldsToMarshal(row)
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

// unmarshalRow decodes one marshalRow-encoded JSON object into dest (a
// pointer to a model struct), matching keys by Go field name -- the exact
// inverse of marshalRow, and the reason loadTable can rely on a field like
// SecretVersion.EncryptedValue actually being restored rather than left at
// its Go zero value. A key present in data but absent from dest's current
// struct fields (an archive written by a newer binary carrying a field this
// binary's model doesn't have) is ignored; a struct field with no
// corresponding key in data (a model field newer than the archive, §8's
// version-skipping-upgrade case) is simply left at its zero value -- both
// matching plain encoding/json's own missing-field behavior.
func unmarshalRow(data []byte, dest any) error {
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("dest must be a non-nil pointer, got %T", dest)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("dest must point to a struct, got %s", v.Kind())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode row as a JSON object: %w", err)
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		gormTag := f.Tag.Get("gorm")
		if gormTag == "-" || strings.HasPrefix(gormTag, "-:") {
			continue
		}
		fieldData, ok := raw[f.Name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(fieldData, v.Field(i).Addr().Interface()); err != nil {
			return fmt.Errorf("field %s: %w", f.Name, err)
		}
	}
	return nil
}
