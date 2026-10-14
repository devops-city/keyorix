package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// openPostgresGorm opens the configured PostgreSQL database through GORM from
// the parsed connection config (config.ResolvePostgresConnConfig), never from
// a DSN string: the resolved password is set on that config, so it cannot
// change the host, sslmode or any other setting the DSN names.
//
// Handing GORM a ready *sql.DB skips the DSN-based setup postgres.Open does in
// its Initialize; the one part of it that depends on the DSN, the timestamp
// scan location for a TimeZone/timezone/time_zone setting, is reproduced
// here from the parsed runtime parameters.
func openPostgresGorm(d *config.DatabaseConfig, gcfg *gorm.Config) (*gorm.DB, error) {
	sqlDB, cc, err := openPostgresSQLDB(d)
	if err != nil {
		return nil, err
	}
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), gcfg)
	if err != nil {
		_ = sqlDB.Close()
		return nil, postgresConnectError(err, cc)
	}
	return db, nil
}

// openPostgresSQLDB builds the *sql.DB openPostgresGorm hands to GORM. It does
// not connect: database/sql dials lazily on first use. createPostgresStorage
// also calls it for the scheduler lock pool, so both pools reach the same
// server and database with the same credentials.
func openPostgresSQLDB(d *config.DatabaseConfig) (*sql.DB, *pgx.ConnConfig, error) {
	cc, err := config.ResolvePostgresConnConfig(d)
	if err != nil {
		return nil, nil, err
	}
	var opts []stdlib.OptionOpenDB
	if afterConnect := postgresAfterConnect(cc); afterConnect != nil {
		opts = append(opts, stdlib.OptionAfterConnect(afterConnect))
	}
	return stdlib.OpenDB(*cc, opts...), cc, nil
}

// postgresAfterConnect is the per-connection setup every pool opened from cc
// runs: the timestamp scan location for a DSN time zone setting. nil when
// there is nothing to set up.
func postgresAfterConnect(cc *pgx.ConnConfig) func(context.Context, *pgx.Conn) error {
	tz := postgresTimeZone(cc)
	if tz == "" {
		return nil
	}
	return func(_ context.Context, conn *pgx.Conn) error {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return err
		}
		conn.TypeMap().RegisterType(&pgtype.Type{
			Name:  "timestamp",
			OID:   pgtype.TimestampOID,
			Codec: &pgtype.TimestampCodec{ScanLocation: loc},
		})
		return nil
	}
}

// openPostgresNativeReadPool opens the pgxpool the storage layer runs its
// hottest read statements on (store.LocalStorage.SetNativeReadPool). Same
// connection config as every other pool here (config.ResolvePostgresConnConfig:
// the parsed DSN, the password set on it, the TLS check), the same
// per-connection setup, and pgx's default statement cache, as the request pool
// uses. It does not connect: pgxpool dials on first use.
func openPostgresNativeReadPool(d *config.DatabaseConfig, maxConns int) (*pgxpool.Pool, error) {
	cc, err := config.ResolvePostgresConnConfig(d)
	if err != nil {
		return nil, err
	}
	// pgxpool only accepts a config made by its own ParseConfig. The parsed
	// string is a placeholder that loads no TLS files; its ConnConfig is
	// replaced by the resolved one below, so nothing of it reaches a connection.
	pc, err := pgxpool.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, err
	}
	pc.ConnConfig = cc
	pc.AfterConnect = postgresAfterConnect(cc)
	pc.MaxConns = int32(maxConns) // #nosec G115 -- at most NativeReadPoolMaxSize (nativeReadPoolSize)
	pc.MinConns = 0
	if d.ConnMaxLifetimeMinutes > 0 {
		pc.MaxConnLifetime = time.Duration(d.ConnMaxLifetimeMinutes) * time.Minute
	}
	return pgxpool.NewWithConfig(context.Background(), pc)
}

// postgresTimeZone returns the time zone a DSN sets under one of the keys
// gorm.io/driver/postgres recognises (time_zone, TimeZone, timezone).
func postgresTimeZone(cc *pgx.ConnConfig) string {
	for _, k := range []string{"time_zone", "TimeZone", "timezone"} {
		if tz := cc.RuntimeParams[k]; tz != "" {
			return tz
		}
	}
	return ""
}
