package solewriter

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
)

// TestClassifyStatement covers the statement shapes this codebase sends
// (GORM's quoted identifiers, raw SQL, transaction control) and the two
// exclusions the triggers share (bookkeeping-only UPDATE; system_metadata rows
// other than the fenced key).
func TestClassifyStatement(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		args []any
		want stmtKind
	}{
		{"begin isolation level read committed", nil, stmtBegin},
		{"BEGIN", nil, stmtBegin},
		{"commit", nil, stmtEnd},
		{"rollback", nil, stmtEnd},
		{"ROLLBACK TO SAVEPOINT sp0x1", nil, stmtRead}, // GORM's failed nested Transaction: the outer one goes on
		{"rollback to sp1", nil, stmtRead},
		{"ROLLBACK TRANSACTION TO SAVEPOINT sp1;", nil, stmtRead},
		{"rollback work to sp1", nil, stmtRead},
		{"ROLLBACK AND CHAIN", nil, stmtEndChain},
		{"commit and chain;", nil, stmtEndChain},
		{"COMMIT AND NO CHAIN", nil, stmtEnd},
		{"end", nil, stmtEnd},
		{"abort", nil, stmtEnd},
		{`SELECT * FROM "machine_identity_credentials" WHERE token_hash = $1`, nil, stmtRead},
		{`SELECT * FROM roles WHERE id = $1 FOR UPDATE`, nil, stmtRead},
		{`WITH RECURSIVE a AS (SELECT id FROM secret_nodes) SELECT * FROM a`, nil, stmtRead},
		{`WITH d AS (DELETE FROM role_permissions WHERE role_id = 1 RETURNING *) SELECT count(*) FROM d`, nil, stmtFencedWrite},
		{`INSERT INTO "role_permissions" ("role_id","permission_id") VALUES ($1,$2)`, nil, stmtFencedWrite},
		{`UPDATE "machine_identity_credentials" SET "revoked"=$1 WHERE id = $2`, nil, stmtFencedWrite},
		{`UPDATE "machine_identity_credentials" SET "last_used_at"=$1 WHERE id = $2 AND (last_used_at IS NULL OR last_used_at < $3)`, nil, stmtOtherWrite},
		{`UPDATE "machine_identity_credentials" SET "last_used_at"=$1,"revoked"=$2 WHERE id = $3`, nil, stmtFencedWrite},
		{`DELETE FROM "projects" WHERE "projects"."id" = $1`, nil, stmtFencedWrite},
		{`UPDATE "sw_1"."roles" SET description = 'x'`, nil, stmtFencedWrite},
		{`TRUNCATE secret_versions`, nil, stmtFencedWrite},
		{`INSERT INTO "audit_events" ("event_type") VALUES ($1)`, nil, stmtOtherWrite},
		{`UPDATE "secret_node_tags" SET x = 1`, nil, stmtOtherWrite}, // not secret_nodes: a word match, not a prefix
		{`INSERT INTO "system_metadata" ("key","value","updated_at") VALUES ($1,$2,$3)`, []any{"schema_epoch", "2", nil}, stmtOtherWrite},
		{`UPDATE "system_metadata" SET "value"=CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = $1`, []any{"role_permissions_generation"}, stmtFencedWrite},
		{"-- comment\nDELETE FROM environments WHERE id = 1", nil, stmtFencedWrite},
		{"/* c */ UPDATE secret_access_schedules SET start_hour = 1", nil, stmtFencedWrite},
		// A subquery's own WHERE must not end the SET list early.
		{`UPDATE "machine_identity_credentials" SET "last_used_at"=(SELECT now() WHERE true),"revoked"=true WHERE id = $1`, nil, stmtFencedWrite},
		{`UPDATE "machine_identity_credentials" SET "last_used_at"=coalesce($1, now()) WHERE id = $2`, nil, stmtFencedWrite},
		// The fenced key in a bind argument of any string-like shape.
		{metaUpd, []any{"3", metaKey(sysKey)}, stmtFencedWrite},
		{metaUpd, []any{"3", &sysKeyStr}, stmtFencedWrite},
		{metaUpd, []any{"3", []byte(sysKey)}, stmtFencedWrite},
		{metaUpd, []any{"3", sql.NullString{String: sysKey, Valid: true}}, stmtFencedWrite},
		{metaUpd, []any{"3", failingValuer{}}, stmtFencedWrite},
		{`DELETE FROM "system_metadata" WHERE key = ANY($1)`, []any{[]string{"schema_epoch", sysKey}}, stmtFencedWrite},
		{metaUpd, []any{"3", metaKey("schema_epoch"), (*string)(nil), sql.NullString{}}, stmtOtherWrite},
		// Several statements in one string: not parsed one by one.
		{`UPDATE audit_events SET x = 1; UPDATE roles SET description = 'x'`, nil, stmtFencedWrite},
		{`SELECT 1; DELETE FROM roles`, nil, stmtFencedWrite},
	} {
		if got := classifyStatement(tc.sql, tc.args); got != tc.want {
			t.Errorf("classifyStatement(%q) = %d, want %d", tc.sql, got, tc.want)
		}
	}
}

func TestFill_RejectsAnOverlappingWrite(t *testing.T) {
	tr := NewTracker()
	f := tr.BeginFill()
	if !f.Store() || !tr.Valid(f.Gen()) {
		t.Fatal("an undisturbed fill must be storable and valid")
	}
	f = tr.BeginFill()
	tr.inflight.Add(1)
	if f.Store() {
		t.Fatal("a fill overlapping an in-flight write must not be stored")
	}
	tr.gen.Add(1)
	tr.inflight.Add(-1)
	if f.Store() || tr.Valid(f.Gen()) {
		t.Fatal("a fill read before a write finished must not be stored or served")
	}
	g := tr.BeginFill()
	tr.inflight.Add(1)
	if tr.Valid(g.Gen()) {
		t.Fatal("no entry is valid while a write is in flight")
	}
}

const (
	metaUpd = `UPDATE "system_metadata" SET "value"=$1 WHERE key = $2`
	sysKey  = "role_permissions_generation"
)

var sysKeyStr = sysKey

type metaKey string

type failingValuer struct{}

func (failingValuer) Value() (driver.Value, error) { return nil, errors.New("no value") }
