package serverguard

import "github.com/keyorixhq/keyorix/internal/config"

// setTestPooler sets storage.database.pooler. Its own file so the pooler tests
// can be run against a tree that predates the setting, with this stubbed out.
func setTestPooler(d *config.DatabaseConfig, pooler string) {
	d.Pooler = pooler
}
