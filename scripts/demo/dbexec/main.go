// Command dbexec is a tiny PostgreSQL client for the demo scenario scripts, so they need
// neither psql nor a Python driver on the presenter's machine. DEMO/TEST helper only; it is
// never part of a shipped binary.
//
//	dbexec query 'SELECT description FROM audit_events WHERE id = $1' 5
//	dbexec exec  'UPDATE audit_events SET description = $1 WHERE id = $2' TAMPERED 5
//
// The DSN is read from KEYORIX_DEMO_PG_DSN (never from argv); arguments after the statement
// are bound as text parameters. `query` prints one tab-separated line per row.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dbexec:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: dbexec query|exec <sql> [param...]  (DSN in KEYORIX_DEMO_PG_DSN)")
	}
	dsn := os.Getenv("KEYORIX_DEMO_PG_DSN")
	if dsn == "" {
		return fmt.Errorf("KEYORIX_DEMO_PG_DSN is not set")
	}
	mode, stmt := os.Args[1], os.Args[2]
	params := make([]any, 0, len(os.Args)-3)
	for _, a := range os.Args[3:] {
		params = append(params, a)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	switch mode {
	case "exec":
		res, err := db.ExecContext(ctx, stmt, params...) // #nosec G701 -- demo helper: the statement is the operator's own argv and the DSN is theirs too, no privilege boundary; values are bound parameters
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		fmt.Printf("%d row(s) affected\n", n)
		return nil
	case "query":
		rows, err := db.QueryContext(ctx, stmt, params...) // #nosec G701 -- demo helper: the statement is the operator's own argv and the DSN is theirs too, no privilege boundary; values are bound parameters
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		cols, err := rows.Columns()
		if err != nil {
			return err
		}
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return err
			}
			out := make([]string, len(cols))
			for i, v := range vals {
				out[i] = v.String
			}
			fmt.Println(strings.Join(out, "\t"))
		}
		return rows.Err()
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}
