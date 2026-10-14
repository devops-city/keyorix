// Package sqlite is a GORM dialector for SQLite backed by modernc.org/sqlite
// (a pure-Go, CGO-free translation of the SQLite C library), instead of the
// CGO-based mattn/go-sqlite3 driver the official gorm.io/driver/sqlite package
// uses (ADR-048). The exported API is deliberately identical to
// gorm.io/driver/sqlite's — Open, New, Config, Dialector — so every existing
// call site only needs its import path changed, not its code.
//
// This is a fork of gorm.io/driver/sqlite (https://github.com/go-gorm/sqlite),
// MIT licensed, Copyright (c) 2013-NOW Jinzhu <wosmvp@gmail.com>. The only
// change from the upstream source is the driver import (mattn/go-sqlite3 ->
// modernc.org/sqlite) and the resulting default driver name ("sqlite3" ->
// "sqlite", modernc's self-registered database/sql driver name). Forked
// rather than depending on github.com/glebarez/sqlite (a community GORM
// wrapper around a modernc fork) because that package's last release was
// March 2024, ~2 years behind modernc.org/sqlite's actively maintained
// releases, and it has a documented double-registration conflict with
// importing modernc.org/sqlite directly.
package sqlite

import (
	"context"
	"database/sql"
	"strconv"

	"gorm.io/gorm/callbacks"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/migrator"
	"gorm.io/gorm/schema"

	// modernc.org/sqlite self-registers a database/sql driver named "sqlite"
	// (see DriverName below) as a side effect of import; it is never referenced
	// by name in this file (ADR-048's CGO-free driver swap).
	_ "modernc.org/sqlite"
)

// DriverName is the default driver name for SQLite (modernc.org/sqlite's
// self-registered database/sql driver name).
const DriverName = "sqlite"

type Dialector struct {
	DriverName string
	DSN        string
	Conn       gorm.ConnPool
}

type Config struct {
	DriverName string
	DSN        string
	Conn       gorm.ConnPool
}

func Open(dsn string) gorm.Dialector {
	return &Dialector{DSN: dsn}
}

func New(config Config) gorm.Dialector {
	return &Dialector{DSN: config.DSN, DriverName: config.DriverName, Conn: config.Conn}
}

func (dialector Dialector) Name() string {
	return "sqlite"
}

func (dialector Dialector) Initialize(db *gorm.DB) (err error) {
	if dialector.DriverName == "" {
		dialector.DriverName = DriverName
	}

	if dialector.Conn != nil {
		db.ConnPool = dialector.Conn
	} else {
		conn, err := sql.Open(dialector.DriverName, dialector.DSN)
		if err != nil {
			return err
		}
		db.ConnPool = conn
	}

	var version string
	if err := db.ConnPool.QueryRowContext(context.Background(), "select sqlite_version()").Scan(&version); err != nil {
		return err
	}
	// https://www.sqlite.org/releaselog/3_35_0.html
	if compareVersion(version, "3.35.0") >= 0 {
		callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
			CreateClauses:        []string{"INSERT", "VALUES", "ON CONFLICT", "RETURNING"},
			UpdateClauses:        []string{"UPDATE", "SET", "FROM", "WHERE", "RETURNING"},
			DeleteClauses:        []string{"DELETE", "FROM", "WHERE", "RETURNING"},
			LastInsertIDReversed: true,
		})
	} else {
		callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
			LastInsertIDReversed: true,
		})
	}

	for k, v := range dialector.ClauseBuilders() {
		if _, ok := db.ClauseBuilders[k]; !ok {
			db.ClauseBuilders[k] = v
		}
	}
	return
}

func (dialector Dialector) ClauseBuilders() map[string]clause.ClauseBuilder {
	return map[string]clause.ClauseBuilder{
		"INSERT": func(c clause.Clause, builder clause.Builder) {
			if insert, ok := c.Expression.(clause.Insert); ok {
				if stmt, ok := builder.(*gorm.Statement); ok {
					_, _ = stmt.WriteString("INSERT ")
					if insert.Modifier != "" {
						_, _ = stmt.WriteString(insert.Modifier)
						_ = stmt.WriteByte(' ')
					}

					_, _ = stmt.WriteString("INTO ")
					if insert.Table.Name == "" {
						stmt.WriteQuoted(stmt.Table)
					} else {
						stmt.WriteQuoted(insert.Table)
					}
					return
				}
			}

			c.Build(builder)
		},
		"LIMIT": func(c clause.Clause, builder clause.Builder) {
			if limit, ok := c.Expression.(clause.Limit); ok {
				var lmt = -1
				if limit.Limit != nil && *limit.Limit >= 0 {
					lmt = *limit.Limit
				}
				if lmt >= 0 || limit.Offset > 0 {
					_, _ = builder.WriteString("LIMIT ")
					_, _ = builder.WriteString(strconv.Itoa(lmt))
				}
				if limit.Offset > 0 {
					_, _ = builder.WriteString(" OFFSET ")
					_, _ = builder.WriteString(strconv.Itoa(limit.Offset))
				}
			}
		},
		"FOR": func(c clause.Clause, builder clause.Builder) {
			if _, ok := c.Expression.(clause.Locking); ok {
				// SQLite3 does not support row-level locking.
				return
			}
			c.Build(builder)
		},
	}
}

func (dialector Dialector) DefaultValueOf(field *schema.Field) clause.Expression {
	if field.AutoIncrement {
		return clause.Expr{SQL: "NULL"}
	}

	// doesn't work, will raise error
	return clause.Expr{SQL: "DEFAULT"}
}

func (dialector Dialector) Migrator(db *gorm.DB) gorm.Migrator {
	return Migrator{migrator.Migrator{Config: migrator.Config{
		DB:                          db,
		Dialector:                   dialector,
		CreateIndexAfterCreateTable: true,
	}}}
}

func (dialector Dialector) BindVarTo(writer clause.Writer, stmt *gorm.Statement, v any) {
	_ = writer.WriteByte('?')
}

func (dialector Dialector) QuoteTo(writer clause.Writer, str string) {
	var (
		underQuoted, selfQuoted bool
		continuousBacktick      int8
		shiftDelimiter          int8
	)

	for _, v := range []byte(str) {
		switch v {
		case '`':
			continuousBacktick++
			if continuousBacktick == 2 {
				_, _ = writer.WriteString("``")
				continuousBacktick = 0
			}
		case '.':
			if continuousBacktick > 0 || !selfQuoted {
				shiftDelimiter = 0
				underQuoted = false
				continuousBacktick = 0
				_, _ = writer.WriteString("`")
			}
			_ = writer.WriteByte(v)
			continue
		default:
			if shiftDelimiter-continuousBacktick <= 0 && !underQuoted {
				_, _ = writer.WriteString("`")
				underQuoted = true
				if selfQuoted = continuousBacktick > 0; selfQuoted {
					continuousBacktick -= 1
				}
			}

			for ; continuousBacktick > 0; continuousBacktick -= 1 {
				_, _ = writer.WriteString("``")
			}

			_ = writer.WriteByte(v)
		}
		shiftDelimiter++
	}

	if continuousBacktick > 0 && !selfQuoted {
		_, _ = writer.WriteString("``")
	}
	_, _ = writer.WriteString("`")
}

func (dialector Dialector) Explain(sql string, vars ...any) string {
	return logger.ExplainSQL(sql, nil, `"`, vars...)
}

func (dialector Dialector) DataTypeOf(field *schema.Field) string {
	switch field.DataType {
	case schema.Bool:
		return "numeric"
	case schema.Int, schema.Uint:
		if field.AutoIncrement {
			// doesn't check `PrimaryKey`, to keep backward compatibility
			// https://www.sqlite.org/autoinc.html
			return "integer PRIMARY KEY AUTOINCREMENT"
		} else {
			return "integer"
		}
	case schema.Float:
		return "real"
	case schema.String:
		return "text"
	case schema.Time:
		// Distinguish between schema.Time and tag time
		if val, ok := field.TagSettings["TYPE"]; ok {
			return val
		} else {
			return "datetime"
		}
	case schema.Bytes:
		return "blob"
	}

	return string(field.DataType)
}

func (dialectopr Dialector) SavePoint(tx *gorm.DB, name string) error {
	tx.Exec("SAVEPOINT " + name)
	return nil
}

func (dialectopr Dialector) RollbackTo(tx *gorm.DB, name string) error {
	tx.Exec("ROLLBACK TO SAVEPOINT " + name)
	return nil
}

func compareVersion(version1, version2 string) int {
	n, m := len(version1), len(version2)
	i, j := 0, 0
	for i < n || j < m {
		x := 0
		for ; i < n && version1[i] != '.'; i++ {
			x = x*10 + int(version1[i]-'0')
		}
		i++
		y := 0
		for ; j < m && version2[j] != '.'; j++ {
			y = y*10 + int(version2[j]-'0')
		}
		j++
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}
