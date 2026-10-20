//go:build ignore

// migratecheck is the Go half of scripts/migrate/sqlite-to-pg-check.sh. Like
// scripts/totpgen it is deliberately not part of any shipped binary or
// `go build ./...` target (the //go:build ignore tag).
//
//	migratecheck seed-audit  --config keyorix.yaml --count N --age-days D [--tag T] [--restamp-head K]
//	migratecheck table-sums  --config keyorix.yaml [--audit-max-id N] [--strict]
//	migratecheck meta        --config keyorix.yaml --key schema_epoch
//	migratecheck rows        --config keyorix.yaml --key <table> [--audit-max-id N]   (the canonical rows, for diffing)
//	migratecheck epoch                      (this binary's schema epoch)
//	migratecheck audit-tail  --config keyorix.yaml --after N   (event_type of audit rows with id > N)
//	migratecheck reset-pg    --config keyorix.yaml   (DROP SCHEMA public CASCADE + recreate: the
//	                                          stand-in for an operator's dropdb/createdb)
//
// seed-audit appends N chained audit events through the real store write path
// (so the hash chain stays valid) with event_time D days in the past. Chain
// hashing covers event_time, so backdating cannot be done with SQL; this is the
// only honest way to get events old enough for a retention purge. A purge
// removes only a contiguous id-prefix of old rows, and `admin init` / `admin
// encryption init` / `admin migrate` have already written the first rows with
// the current time, so --restamp-head K re-dates the first K rows to just before
// the seeded ones and re-chains every row with the exported
// store.ComputeAuditEntryHash: the state of an instance that has been running
// for a month. It is a fixture technique for a server that is NOT running.
//
// table-sums prints one JSON line per table: row count and an order-independent
// SHA-256 over a canonical rendering of every row. The rendering is independent
// of the backup format (it reads columns through database/sql and normalises
// the type differences between SQLite and PostgreSQL: bool vs 0/1, time zones,
// bytes), so it can compare a SQLite database with a PostgreSQL one. The
// config's database password comes from KEYORIX_DB_PASSWORD, as for the server.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Values a restore deliberately does NOT carry over, so a SQLite source and its
// restored PostgreSQL copy are compared without them (--strict compares them too):
//   - secret_nodes.cache_epoch: a read-path cache generation stamp maintained by a
//     database trigger and read-only to the application (models.SecretNode.CacheEpoch);
//     a fresh database starts its caches at 0.
//   - system_metadata schema_epoch, schema_min_compatible_epoch: written by the
//     TARGET's own migration, which runs before the load; the archive's copy must
//     never overwrite them (backupfmt/loader.go). The script compares their values.
//   - system_metadata role_permissions_generation: the target's own cache-invalidation
//     generation (backupfmt/loader.go).
var (
	deliberateColumns  = map[string]bool{"secret_nodes.cache_epoch": true}
	deliberateMetaKeys = map[string]bool{
		"schema_epoch": true, "schema_min_compatible_epoch": true, "role_permissions_generation": true,
	}
	strict bool
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "epoch" {
		fmt.Println(storage.CurrentSchemaEpoch())
		return
	}
	if len(os.Args) < 2 {
		fatalf("usage: migratecheck seed-audit|table-sums --config <file> ...")
	}
	sub := os.Args[1]
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	cfgPath := fs.String("config", "keyorix.yaml", "config file")
	count := fs.Int("count", 0, "seed-audit: number of events")
	ageDays := fs.Int("age-days", 0, "seed-audit: age of the events in days")
	tag := fs.String("tag", "seed", "seed-audit: description tag")
	restamp := fs.Int("restamp-head", 0, "seed-audit: re-date the first K existing audit rows to just before the seeded ones and re-chain")
	key := fs.String("key", "", "meta: system_metadata key to print")
	after := fs.Uint("after", 0, "audit-tail: print audit rows with id > N")
	fs.BoolVar(&strict, "strict", false, "table-sums/rows: also compare the values a restore deliberately does not carry over")
	auditMax := fs.Uint("audit-max-id", 0, "table-sums: only audit_events with id <= N (0 = all)")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	if err := i18n.Initialize(cfg); err != nil {
		fatalf("i18n: %v", err)
	}
	switch sub {
	case "seed-audit":
		seedAudit(cfg, *count, *ageDays, *tag, *restamp)
	case "table-sums":
		tableSums(cfg, *auditMax)
	case "rows":
		gdb, err := storage.OpenGormDB(cfg)
		if err != nil {
			fatalf("open db: %v", err)
		}
		for _, l := range tableRows(gdb, *key, *auditMax) {
			fmt.Println(strings.ReplaceAll(l, "\x1f", " | "))
		}
	case "audit-tail":
		gdb, err := storage.OpenGormDB(cfg)
		if err != nil {
			fatalf("open db: %v", err)
		}
		var rows []models.AuditEvent
		if err := gdb.Where("id > ?", *after).Order("id").Find(&rows).Error; err != nil {
			fatalf("audit-tail: %v", err)
		}
		for _, r := range rows {
			fmt.Printf("%d\t%s\t%s\n", r.ID, r.EventType, r.Description)
		}
	case "reset-pg":
		if cfg.Storage.Type != "postgres" {
			fatalf("reset-pg: config is not PostgreSQL")
		}
		gdb, err := storage.OpenGormDB(cfg)
		if err != nil {
			fatalf("open db: %v", err)
		}
		for _, q := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
			if err := gdb.Exec(q).Error; err != nil {
				fatalf("%s: %v", q, err)
			}
		}
	case "meta":
		var v models.SystemMetadata
		gdb, err := storage.OpenGormDB(cfg)
		if err != nil {
			fatalf("open db: %v", err)
		}
		if err := gdb.Where("key = ?", *key).Take(&v).Error; err != nil {
			fatalf("system_metadata[%s]: %v", *key, err)
		}
		fmt.Println(v.Value)
	default:
		fatalf("unknown subcommand %q", sub)
	}
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "migratecheck: "+f+"\n", a...)
	os.Exit(1)
}

func seedAudit(cfg *config.Config, n, ageDays int, tag string, restamp int) {
	if n <= 0 {
		fatalf("seed-audit needs --count > 0")
	}
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		fatalf("open storage: %v", err)
	}
	types := []string{"secret.read", "secret.updated", "auth.login", "share.created", "rbac.role_assigned", "project.created"}
	base := time.Now().UTC().AddDate(0, 0, -ageDays)
	ctx := context.Background()
	const workers = 16
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				ok := true
				ev := &models.AuditEvent{
					EventType:   types[i%len(types)],
					IPAddress:   "10.0.0." + strconv.Itoa(i%250+1),
					Description: fmt.Sprintf("%s event %d", tag, i),
					Success:     &ok,
					EventTime:   base.Add(time.Duration(i) * time.Second),
				}
				if err := st.LogAuditEvent(ctx, ev); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		fatalf("LogAuditEvent: %v", firstErr)
	}
	if restamp > 0 {
		restampHead(cfg, restamp, base.Add(-time.Hour))
	}
	fmt.Printf("seeded %d audit events (%d day(s) old, tag %q)\n", n, ageDays, tag)
}

func restampHead(cfg *config.Config, k int, to time.Time) {
	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		fatalf("open db: %v", err)
	}
	var rows []models.AuditEvent
	if err := gdb.Order("id").Find(&rows).Error; err != nil {
		fatalf("read audit events: %v", err)
	}
	if len(rows) < k {
		fatalf("restamp-head %d: only %d audit rows", k, len(rows))
	}
	err = gdb.Transaction(func(tx *gorm.DB) error {
		prev := ""
		for i := range rows {
			r := &rows[i]
			if i < k {
				r.EventTime = to.Add(time.Duration(i) * time.Second).UTC().Truncate(time.Microsecond)
			}
			if i == 0 {
				prev = r.PrevHash // the genesis constant, unchanged
			}
			r.PrevHash = prev
			r.EntryHash = store.ComputeAuditEntryHash(r, prev)
			prev = r.EntryHash
			if err := tx.Model(&models.AuditEvent{}).Where("id = ?", r.ID).
				Updates(map[string]any{"event_time": r.EventTime, "prev_hash": r.PrevHash, "entry_hash": r.EntryHash}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fatalf("restamp-head: %v", err)
	}
	fmt.Printf("re-dated the first %d audit rows and re-chained %d rows\n", k, len(rows))
}

// tableRows returns every row of table t rendered canonically, sorted.
func tableRows(gdb *gorm.DB, t string, auditMax uint) []string {
	q := "SELECT * FROM " + t
	if t == "audit_events" && auditMax > 0 {
		q += " WHERE id <= " + strconv.FormatUint(uint64(auditMax), 10)
	}
	rows, err := gdb.Raw(q).Rows()
	if err != nil {
		fatalf("select %s: %v", t, err)
	}
	cols, _ := rows.Columns()
	// Render columns in name order so a column-order difference between a
	// migrated SQLite file and a fresh PostgreSQL table cannot matter.
	var order []int
	for i := range cols {
		if !strict && deliberateColumns[t+"."+cols[i]] {
			continue
		}
		order = append(order, i)
	}
	sort.Slice(order, func(a, b int) bool { return cols[order[a]] < cols[order[b]] })
	keyCol := -1
	if t == "system_metadata" && !strict {
		for i := range cols {
			if cols[i] == "key" {
				keyCol = i
			}
		}
	}
	var lines []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			fatalf("scan %s: %v", t, err)
		}
		if keyCol >= 0 {
			if k, _ := vals[keyCol].(string); deliberateMetaKeys[k] {
				continue
			}
		}
		var sb strings.Builder
		for _, i := range order {
			sb.WriteString(cols[i])
			sb.WriteByte('=')
			sb.WriteString(canon(vals[i]))
			sb.WriteByte('\x1f')
		}
		lines = append(lines, sb.String())
	}
	if err := rows.Err(); err != nil {
		fatalf("rows %s: %v", t, err)
	}
	_ = rows.Close()
	sort.Strings(lines)
	return lines
}

type tableSum struct {
	Table  string `json:"table"`
	Count  int    `json:"count"`
	SHA256 string `json:"sha256"`
}

func tableSums(cfg *config.Config, auditMax uint) {
	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		fatalf("open db: %v", err)
	}
	var names []string
	for _, m := range storage.AllModels() {
		stmt := &gorm.Statement{DB: gdb}
		if err := stmt.Parse(m); err != nil {
			fatalf("parse model %T: %v", m, err)
		}
		names = append(names, stmt.Schema.Table)
	}
	sort.Strings(names)
	enc := json.NewEncoder(os.Stdout)
	for _, t := range names {
		lines := tableRows(gdb, t, auditMax)
		h := sha256.New()
		for _, l := range lines {
			h.Write([]byte(l))
			h.Write([]byte{'\n'})
		}
		_ = enc.Encode(tableSum{Table: t, Count: len(lines), SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	var maxID int64
	if err := gdb.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_events").Scan(&maxID).Error; err != nil {
		fatalf("max audit id: %v", err)
	}
	_ = enc.Encode(tableSum{Table: "__audit_max_id", Count: int(maxID)})
}

// canon renders one column value so SQLite and PostgreSQL agree on it.
func canon(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case bool:
		if x {
			return "1"
		}
		return "0"
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case time.Time:
		return "t" + strconv.FormatInt(x.UTC().UnixMicro(), 10)
	case []byte:
		if utf8.Valid(x) {
			return string(x)
		}
		return "hex:" + hex.EncodeToString(x)
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}
