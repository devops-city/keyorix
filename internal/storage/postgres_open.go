package storage

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
	cc, err := config.ResolvePostgresConnConfig(d)
	if err != nil {
		return nil, err
	}
	var opts []stdlib.OptionOpenDB
	if tz := postgresTimeZone(cc); tz != "" {
		opts = append(opts, stdlib.OptionAfterConnect(func(_ context.Context, conn *pgx.Conn) error {
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
		}))
	}
	sqlDB := stdlib.OpenDB(*cc, opts...)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), gcfg)
	if err != nil {
		_ = sqlDB.Close()
		return nil, postgresConnectError(err, cc)
	}
	return db, nil
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
