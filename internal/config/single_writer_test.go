package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidate_SingleWriterTopology: storage.database.single_writer runs only
// with one PostgreSQL server reached directly or through session pooling.
func TestValidate_SingleWriterTopology(t *testing.T) {
	pg := func() *Config {
		c := &Config{}
		c.Storage.Type = "postgres"
		c.Storage.Database.DSN = "host=db user=keyorix dbname=keyorix sslmode=require"
		c.Storage.Database.SingleWriter = true
		return c
	}
	require.NoError(t, pg().Validate(), "one PostgreSQL server: allowed")

	c := pg()
	c.Storage.Database.Pooler = "pgbouncer-session"
	require.NoError(t, c.Validate(), "session pooling keeps one backend per session: allowed")

	c = pg()
	c.Storage.Database.Pooler = "pgbouncer-transaction"
	require.ErrorContains(t, c.Validate(), "not supported with storage.database.pooler pgbouncer-transaction")

	c = pg()
	c.Security.AuthRateLimitFallback.Replicas = 2
	require.ErrorContains(t, c.Validate(), "allows exactly one server")

	sq := &Config{}
	sq.Storage.Type = "local"
	sq.Storage.Database.Path = "/tmp/x.db"
	sq.Storage.Database.SingleWriter = true
	require.ErrorContains(t, sq.Validate(), "only supported with storage.type postgres")

	off := pg()
	off.Storage.Database.SingleWriter = false
	off.Storage.Database.Pooler = "pgbouncer-transaction"
	require.NoError(t, off.Validate(), "the refusals apply only with the setting on")
}

// TestResolvePostgresConnConfig_SoleWriterTag: no tag, no AfterConnect (every
// process but a single-writer server); a tag adds the SET; non-hex is refused.
func TestResolvePostgresConnConfig_SoleWriterTag(t *testing.T) {
	t.Cleanup(ClearSoleWriterSessionTagForTest)
	d := &DatabaseConfig{DSN: "host=127.0.0.1 user=keyorix dbname=keyorix sslmode=disable"}
	cc, err := ResolvePostgresConnConfig(d)
	require.NoError(t, err)
	require.Nil(t, cc.AfterConnect, "without a tag no connection set-up is added")

	require.Error(t, SetSoleWriterSessionTag("abc'; DROP TABLE x; --"))
	require.Error(t, SetSoleWriterSessionTag(""))
	require.NoError(t, SetSoleWriterSessionTag("00ff"))
	cc, err = ResolvePostgresConnConfig(d)
	require.NoError(t, err)
	require.NotNil(t, cc.AfterConnect)
}
