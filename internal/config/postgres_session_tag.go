package config

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgconn"
)

// SoleWriterSessionSetting is the PostgreSQL custom setting a single-writer
// server stamps on every one of its database sessions. The write fence
// (internal/solewriter) lets a session write the security tables while that
// server runs only if the setting hashes to the value the server recorded
// at boot.
const SoleWriterSessionSetting = "keyorix.sole_writer_nonce"

// soleWriterSessionTag is the per-boot tag, or nil when this process is not a
// single-writer server (every other process, admin commands included).
var soleWriterSessionTag atomic.Pointer[string]

// SetSoleWriterSessionTag makes every PostgreSQL connection opened from
// ResolvePostgresConnConfig after this call set SoleWriterSessionSetting to
// tag when it connects. Called once by a single-writer server's boot, before
// it opens any pool. tag must be lowercase hex (it is written into a SET
// statement); anything else is refused.
func SetSoleWriterSessionTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("single-writer session tag is empty")
	}
	for _, r := range tag {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return fmt.Errorf("single-writer session tag must be lowercase hex")
		}
	}
	soleWriterSessionTag.Store(&tag)
	return nil
}

// ClearSoleWriterSessionTagForTest undoes SetSoleWriterSessionTag.
func ClearSoleWriterSessionTagForTest() { soleWriterSessionTag.Store(nil) }

// soleWriterAfterConnect returns the connection set-up that stamps the tag, or
// nil when no tag is set. A session-level SET: it lasts as long as the
// connection, which is what a pooled connection needs (behind PgBouncer this
// requires session pooling; transaction pooling would hand the setting to
// another client's backend, so single_writer is not supported there).
func soleWriterAfterConnect() pgconn.AfterConnectFunc {
	tag := soleWriterSessionTag.Load()
	if tag == nil {
		return nil
	}
	stmt := "SET " + SoleWriterSessionSetting + " = '" + *tag + "'"
	return func(ctx context.Context, conn *pgconn.PgConn) error {
		return conn.Exec(ctx, stmt).Close()
	}
}
