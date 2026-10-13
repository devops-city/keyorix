package main

import (
	"strings"
	"testing"
)

// PG-VERIFYFULL-1: a server configured for storage.database.ssl_mode:
// verify-full with no CA named in the config refuses to start, with an error
// that names the missing key -- before it opens any database connection.
// RED before the fix: config validation accepted it and the boot went on to
// connect, verifying the database's certificate against whatever trust store
// pgx found (PGSSLROOTCERT, ~/.postgresql/root.crt, or the OS store).
func TestInitializeCoreService_PostgresVerifyFullWithoutCA_RefusesToStart(t *testing.T) {
	initI18n(t)
	for _, mode := range []string{"verify-full", "verify-ca"} {
		t.Run(mode, func(t *testing.T) {
			cfg := newMinimalCfg(t)
			cfg.Storage.Type = "postgres"
			cfg.Storage.Database.Host = "127.0.0.1"
			cfg.Storage.Database.Port = "1" // nothing listens: a connection attempt fails differently
			cfg.Storage.Database.Name = "keyorix"
			cfg.Storage.Database.User = "keyorix"
			cfg.Storage.Database.SSLMode = mode

			_, _, err := initializeCoreService(cfg)
			if err == nil {
				t.Fatal("expected the server to refuse to start on " + mode + " with no CA, got nil error")
			}
			if !strings.Contains(err.Error(), "invalid configuration") || !strings.Contains(err.Error(), "ssl_root_cert") {
				t.Fatalf("expected a config-validation refusal naming storage.database.ssl_root_cert, got: %v", err)
			}
		})
	}
}
