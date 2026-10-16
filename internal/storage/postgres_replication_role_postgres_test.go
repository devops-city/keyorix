package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// TestCreateStorage_Postgres_RefusesNonOriginReplicationRole (#3361): the
// server must not start on database sessions whose session_replication_role
// is not 'origin', whichever source sets it: a per-database default, a
// per-role default in that database, or a startup parameter in the DSN (the
// same effect as Helm's postgresql.settings server default or PGOPTIONS).
// In 'replica' mode foreign keys and ordinary triggers do not run.
//
// The same database with the setting removed starts normally, so the refusal
// is about the setting, not about the fixture.
func TestCreateStorage_Postgres_RefusesNonOriginReplicationRole(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	cases := []struct {
		name  string
		setup func(t *testing.T, dsn, dbName string) string // returns the DSN the server uses
	}{
		{"per-database default", func(t *testing.T, dsn, dbName string) string {
			require.NoError(t, pgRawOpen(t, base).Exec("ALTER DATABASE "+dbName+" SET session_replication_role = replica").Error)
			return dsn
		}},
		{"per-role default in the database", func(t *testing.T, dsn, dbName string) string {
			require.NoError(t, pgRawOpen(t, base).Exec("ALTER ROLE CURRENT_USER IN DATABASE "+dbName+" SET session_replication_role = replica").Error)
			return dsn
		}},
		{"startup parameter in the DSN", func(t *testing.T, dsn, _ string) string {
			sep := "?"
			if strings.Contains(dsn, "?") {
				sep = "&"
			}
			return dsn + sep + "session_replication_role=replica"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dsn := pgIsolatedDatabaseDSN(t, base)
			dbName := pgDatabaseName(t, dsn)
			cfg := &config.Config{}
			cfg.Storage.Type = "postgres"
			cfg.Storage.Database.DSN = c.setup(t, dsn, dbName)

			st, err := NewStorageFactory().CreateStorage(cfg)
			if st != nil {
				if cl, ok := st.(interface{ Close() error }); ok {
					_ = cl.Close()
				}
			}
			require.Error(t, err, "the server started on sessions in session_replication_role=replica, where foreign keys and the cache-epoch trigger do not run (#3361)")
			require.Contains(t, err.Error(), "session_replication_role")

			_, err = OpenGormDB(cfg)
			require.Error(t, err, "the DEK rotation admin path opened a database in session_replication_role=replica (#3361)")

			// Remove the setting: the same database now starts.
			admin := pgRawOpen(t, base)
			require.NoError(t, admin.Exec("ALTER DATABASE "+dbName+" RESET session_replication_role").Error)
			require.NoError(t, admin.Exec("ALTER ROLE CURRENT_USER IN DATABASE "+dbName+" RESET session_replication_role").Error)
			cfg.Storage.Database.DSN = dsn
			st, err = NewStorageFactory().CreateStorage(cfg)
			require.NoError(t, err, "with session_replication_role back to origin the server must start")
			if cl, ok := st.(interface{ Close() error }); ok {
				_ = cl.Close()
			}
		})
	}
}

// pgDatabaseName reads the database name a DSN connects to.
func pgDatabaseName(t *testing.T, dsn string) string {
	t.Helper()
	var name string
	require.NoError(t, pgRawOpen(t, dsn).Raw("SELECT current_database()").Scan(&name).Error)
	return name
}
