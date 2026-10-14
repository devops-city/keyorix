package storage

import "github.com/keyorixhq/keyorix/internal/config"

// setTestPooler sets storage.database.pooler. Its own file so the PgBouncer
// slice (pgbouncer_postgres_test.go) can be run against a tree that predates
// the setting, with this one function stubbed out.
func setTestPooler(d *config.DatabaseConfig, pooler string) {
	d.Pooler = pooler
}
