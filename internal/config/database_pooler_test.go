package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestValidatePooler(t *testing.T) {
	for _, tc := range []struct {
		storageType, pooler, wantErr string
	}{
		{"postgres", "", ""},
		{"postgres", "none", ""},
		{"postgres", "pgbouncer-session", ""},
		{"postgresql", "pgbouncer-transaction", ""},
		{"local", "", ""},
		{"local", "none", ""},
		{"local", "pgbouncer-transaction", "applies only to storage.type postgres"},
		{"remote", "pgbouncer-session", "applies only to storage.type postgres"},
		{"postgres", "pgbouncer", "is not supported"},
		{"postgres", "PgBouncer-Transaction", "is not supported"},
		{"postgres", "pgbouncer-statement", "is not supported"},
	} {
		err := validatePooler(tc.storageType, &DatabaseConfig{Pooler: tc.pooler})
		if tc.wantErr == "" {
			require.NoError(t, err, "%s/%q", tc.storageType, tc.pooler)
			continue
		}
		require.Error(t, err, "%s/%q", tc.storageType, tc.pooler)
		require.True(t, strings.Contains(err.Error(), tc.wantErr), "%v", err)
	}
}

// TestValidate_RefusesUnknownPooler: the refusal is reached through Validate.
func TestValidate_RefusesUnknownPooler(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "postgres"
	c.Storage.Database.DSN = "host=db user=keyorix dbname=keyorix sslmode=require"
	c.Storage.Database.Pooler = "pgbouncer-statement"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.database.pooler")
}

// TestResolvePostgresConnConfig_PoolerExecMode: only pgbouncer-transaction
// changes the pgx execution mode; every other value keeps pgx's default
// (cached prepared statements).
func TestResolvePostgresConnConfig_PoolerExecMode(t *testing.T) {
	for pooler, want := range map[string]pgx.QueryExecMode{
		"":                      pgx.QueryExecModeCacheStatement,
		"none":                  pgx.QueryExecModeCacheStatement,
		"pgbouncer-session":     pgx.QueryExecModeCacheStatement,
		"pgbouncer-transaction": pgx.QueryExecModeExec,
	} {
		d := &DatabaseConfig{DSN: "host=127.0.0.1 user=keyorix dbname=keyorix sslmode=disable", Pooler: pooler}
		cc, err := ResolvePostgresConnConfig(d)
		require.NoError(t, err, pooler)
		require.Equal(t, want, cc.DefaultQueryExecMode, pooler)
		if want == pgx.QueryExecModeExec {
			require.Zero(t, cc.StatementCacheCapacity, pooler)
			require.Zero(t, cc.DescriptionCacheCapacity, pooler)
		} else {
			require.NotZero(t, cc.StatementCacheCapacity, pooler)
		}
	}
}

// TestPinnedLockTxSetupSQL: transaction_timeout is only set from PostgreSQL 17
// (earlier servers reject the unknown parameter); idle_in_transaction_session_timeout
// always.
func TestPinnedLockTxSetupSQL(t *testing.T) {
	const idle = "SET LOCAL idle_in_transaction_session_timeout = 0"
	const txTimeout = "SET LOCAL transaction_timeout = 0"
	for _, tc := range []struct {
		v    int
		want []string
	}{
		{90600, []string{idle}},
		{160013, []string{idle}},
		{169999, []string{idle}},
		{170000, []string{idle, txTimeout}},
		{170005, []string{idle, txTimeout}},
		{180001, []string{idle, txTimeout}},
	} {
		if got := PinnedLockTxSetupSQL(tc.v); !slices.Equal(got, tc.want) {
			t.Errorf("PinnedLockTxSetupSQL(%d) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// TestPoolerStartupParamWarning: with a pooler declared, startup parameters
// PgBouncer refuses are named; tracked ones, no pooler, and unparsable settings
// are quiet.
func TestPoolerStartupParamWarning(t *testing.T) {
	const base = "host=pgb user=kx dbname=keyorix sslmode=disable"
	for _, tc := range []struct {
		name, pooler, dsn string
		want              []string // names the warning must contain; nil: no warning
	}{
		{"none declared", "", base + " search_path=kx", nil},
		{"explicit none", "none", base + " search_path=kx", nil},
		{"transaction, clean", "pgbouncer-transaction", base, nil},
		{"transaction, application_name and time zone", "pgbouncer-transaction", base + " application_name=keyorix TimeZone=UTC", nil},
		{"transaction, search_path", "pgbouncer-transaction", base + " search_path=kx", []string{"search_path"}},
		{"session, options and search_path", "pgbouncer-session", base + " search_path=kx options=-cstatement_timeout=5s", []string{"options", "search_path"}},
		{"url form", "pgbouncer-transaction", "postgres://kx@pgb/keyorix?sslmode=disable&search_path=kx", []string{"search_path"}},
		{"unparsable", "pgbouncer-transaction", "host=pgb sslmode=banana", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := PoolerStartupParamWarning(&DatabaseConfig{DSN: tc.dsn, Pooler: tc.pooler})
			if tc.want == nil {
				require.Empty(t, got)
				return
			}
			require.NotEmpty(t, got)
			require.Contains(t, got, "WARNING: storage.database.pooler is "+tc.pooler)
			require.Contains(t, got, strings.Join(tc.want, ", "))
			require.Contains(t, got, "docs/postgresql-poolers.md")
		})
	}
}
