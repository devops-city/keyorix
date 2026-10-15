package http

// single_writer_sql_bypass_test.go — REVIEW-SINGLE-WRITER-2 N1–N3 end to end:
// a memoized machine read on an authoritative single-writer server, then a
// foreign session tries to end the credential through SQL without any trigger
// change. Either the fence refuses the write, or the server stops serving the
// credential within the lease and a poll. Before the fix each case left the
// revoked (or deleted) credential reading the secret from the memo with the
// guard still authoritative.

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/solewriter"
)

func TestSingleWriter_SQLBypassDoesNotServeAnEndedCredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stmts run in one foreign transaction.
		stmts []string
		// tagged: the session carries the server's tag (a copied tag, the
		// documented residual) but not its write tracker, so it passes the
		// fence and must be seen. Otherwise the fence must refuse it.
		tagged bool
	}{
		{"temp-pg_database-shadow-and-epoch-rewind", []string{
			"CREATE TEMP TABLE pg_database (oid oid, datname name)",
			"UPDATE machine_identity_credentials SET revoked = true WHERE id = ?",
			"UPDATE keyorix_write_epoch SET n = n - 1 WHERE id = 1",
		}, false},
		{"delete-through-a-new-parent", []string{
			"CREATE TABLE sw_bypass_parent (id bigint)",
			"ALTER TABLE machine_identity_credentials INHERIT sw_bypass_parent",
			"DELETE FROM sw_bypass_parent WHERE id = ?",
			"ALTER TABLE machine_identity_credentials NO INHERIT sw_bypass_parent",
			"DROP TABLE sw_bypass_parent",
		}, false},
		{"copied-tag-and-net-zero-epoch", []string{
			"UPDATE machine_identity_credentials SET revoked = true WHERE id = ?",
			"UPDATE keyorix_write_epoch SET n = n - 1 WHERE id = 1",
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := svStorageConfig(t, "postgres")
			w, g := newSWAuthWorldFromConfig(t, 1, cfg)
			sec, v1 := w.newSecret(t, nil)
			swCaughtUp(t, w, g)
			fcWarm(t, w, w.a, sec, v1, true)
			tok := w.tokens["machine"]
			cred := fcMachineCred(t, w)
			got, confirming := fcReadObserved(w.a, tok, sec.ID)
			require.Equal(t, "200 "+v1, got)
			require.False(t, confirming, "the read before the bypass must be a memo hit")

			foreign, err := gorm.Open(postgres.Open(cfg.Storage.Database.DSN), &gorm.Config{Logger: logger.Discard})
			require.NoError(t, err)
			writer := foreign
			if tc.tagged {
				cc, err := config.ResolvePostgresConnConfig(&cfg.Storage.Database)
				require.NoError(t, err)
				cc.Tracer = nil
				writer, err = gorm.Open(postgres.New(postgres.Config{Conn: stdlib.OpenDB(*cc)}), &gorm.Config{Logger: logger.Discard})
				require.NoError(t, err)
			}
			t.Cleanup(func() {
				for _, db := range []*gorm.DB{foreign, writer} {
					if d, err := db.DB(); err == nil {
						_ = d.Close()
					}
				}
			})
			err = writer.Transaction(func(tx *gorm.DB) error {
				for _, s := range tc.stmts {
					args := []any{}
					if strings.Contains(s, "?") {
						args = append(args, cred.ID)
					}
					if err := tx.Exec(s, args...).Error; err != nil {
						return err
					}
				}
				return nil
			})
			var live int64
			require.NoError(t, foreign.Raw("SELECT count(*) FROM machine_identity_credentials WHERE id = ? AND NOT revoked", cred.ID).Scan(&live).Error)
			if !tc.tagged {
				require.Error(t, err, "the fence must refuse the bypass")
				require.Contains(t, err.Error(), "keyorix single_writer")
				require.EqualValues(t, 1, live, "the refused write must not have landed")
				require.Equal(t, "200 "+v1, fcRead(w.a, tok, sec.ID), "the credential is still good")
				return
			}
			require.NoError(t, err)
			require.Zero(t, live, "the copied tag passes the fence")
			time.Sleep(solewriter.LeaseDuration + 2*solewriter.PollInterval)
			require.NotEqual(t, "200 "+v1, fcRead(w.a, tok, sec.ID),
				"the ended credential still reads the secret from the memo (guard authoritative=%v, epoch %d)", g.Authoritative(), g.Epoch())
		})
	}
}
