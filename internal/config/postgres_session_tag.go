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
// it opens any pool. tag must be lowercase hex (a nonce; defence in depth
// now that it travels as a bind parameter); anything else is refused.
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
// nil when no tag is set. A session-level setting: it lasts as long as the
// connection, which is what a pooled connection needs (behind PgBouncer this
// requires session pooling; transaction pooling would hand the setting to
// another client's backend, so single_writer is not supported there).
//
// The tag travels as a bind parameter of set_config, never in the statement
// text, so it is not in pg_stat_activity.query or pg_stat_statements
// (REVIEW-SINGLE-WRITER-1 F2). A server logging every statement with its
// parameters (log_statement = all and log_parameter_max_length <> 0) still
// writes it to the log: docs/single-writer.md "Residual risks".
func soleWriterAfterConnect() pgconn.AfterConnectFunc {
	tag := soleWriterSessionTag.Load()
	if tag == nil {
		return nil
	}
	params := [][]byte{[]byte(SoleWriterSessionSetting), []byte(*tag)}
	return func(ctx context.Context, conn *pgconn.PgConn) error {
		_, err := conn.ExecParams(ctx, soleWriterSetConfigSQL, params, nil, nil, nil).Close()
		return err
	}
}

// soleWriterSetConfigSQL is the whole text of the tagging statement.
const soleWriterSetConfigSQL = "SELECT set_config($1, $2, false)"
