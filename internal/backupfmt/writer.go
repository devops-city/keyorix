package backupfmt

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// walkTable streams every row of model's table, in primary-key-ascending
// order (design §3.3), calling fn once per row with a freshly-allocated,
// GORM-scanned instance of model's Go type -- the same typed scan GORM's own
// query path uses, so custom Scanner/Valuer columns (e.g. the JSON type in
// internal/storage/models/json.go) round-trip exactly like every other GORM
// read in this codebase, with no new marshal/unmarshal logic (design §3.3).
// Bounded memory: one row at a time, never the whole table.
//
// Orders by EVERY primary-key field (s.PrimaryFields, plural), not just a
// single "id" column: several join tables here have a composite primary key
// and no "id" column at all (RolePermission{RoleID, PermissionID}, UserRole,
// GroupRole, UserGroup) -- s.PrioritizedPrimaryField picks (or fails to
// pick) a single field for GORM's own internal purposes and is not a
// reliable proxy for "the columns that actually order this table's rows."
// Found live: an early version of this function defaulted to "id" whenever
// PrioritizedPrimaryField was nil, which round_permissions (composite key,
// no id column at all) hit immediately -- "no such column: id" -- confirmed
// via TestAdminBackupRestore_RoundTrip's real, full-registry backup.
func walkTable(db *gorm.DB, model any, fn func(row any) error) (rowCount int64, err error) {
	s, err := parseSchema(model)
	if err != nil {
		return 0, fmt.Errorf("parse schema for %T: %w", model, err)
	}
	if len(s.PrimaryFields) == 0 {
		return 0, fmt.Errorf("%s has no primary key field(s) -- cannot derive a stable row order", s.Table)
	}
	orderCols := make([]string, len(s.PrimaryFields))
	for i, f := range s.PrimaryFields {
		orderCols[i] = f.DBName + " ASC"
	}

	// Unscoped: a backup is every row, including soft-deleted ones (deleted_at
	// set). The default scope's `deleted_at IS NULL` dropped them, and restore
	// then refused the archive because append-only audit_events still named the
	// dropped project (#3164).
	rows, err := db.Unscoped().Model(model).Order(strings.Join(orderCols, ", ")).Rows()
	if err != nil {
		return 0, fmt.Errorf("query %s: %w", s.Table, err)
	}
	defer rows.Close() //nolint:errcheck

	elemType := reflect.TypeOf(model).Elem()
	for rows.Next() {
		dest := reflect.New(elemType).Interface()
		if err := db.ScanRows(rows, dest); err != nil {
			return rowCount, fmt.Errorf("scan row %d of %s: %w", rowCount, s.Table, err)
		}
		if err := fn(dest); err != nil {
			return rowCount, fmt.Errorf("row %d of %s: %w", rowCount, s.Table, err)
		}
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return rowCount, fmt.Errorf("iterate %s: %w", s.Table, err)
	}
	return rowCount, nil
}

// ndjsonLine marshalRow-encodes row (every real GORM column, not gated by
// any json:"-" tag -- see row_codec.go's doc comment) and appends the
// trailing newline every NDJSON line needs -- the one encoding used for
// both the hashing pass and the writing pass below, so they can never
// disagree about what "the bytes for this row" means.
func ndjsonLine(row any) ([]byte, error) {
	line, err := marshalRow(row)
	if err != nil {
		return nil, fmt.Errorf("encode row: %w", err)
	}
	return append(line, '\n'), nil
}

// hashTable is WriteBackup's pass 1 over one table: walk every row, hash and
// size its NDJSON encoding, without writing any of it to the archive yet --
// needed because MANIFEST.json is the archive's first tar entry (readable
// before any table payload, matching v1's existing convention and required
// by §5.3's stage-then-verify restore flow), but the manifest's own
// per-table hash can only be known after seeing every row.
func hashTable(db *gorm.DB, model any) (TableEntry, error) {
	s, err := parseSchema(model)
	if err != nil {
		return TableEntry{}, fmt.Errorf("parse schema for %T: %w", model, err)
	}

	h := sha256.New()
	var size int64
	rowCount, err := walkTable(db, model, func(row any) error {
		line, err := ndjsonLine(row)
		if err != nil {
			return err
		}
		n, werr := h.Write(line)
		size += int64(n)
		return werr
	})
	if err != nil {
		return TableEntry{}, err
	}
	return TableEntry{
		Name:             s.Table,
		TarName:          "tables/" + s.Table + ".ndjson",
		RowCount:         rowCount,
		UncompressedSize: size,
		SHA256:           hex.EncodeToString(h.Sum(nil)),
		Columns:          append([]string{}, s.DBNames...),
	}, nil
}

// writeTableEntry is WriteBackup's pass 2 over one table: re-walk it (same
// order, same encoding as hashTable's pass 1) and write its NDJSON straight
// into tw as one tar entry of entry's already-known size. Fails loudly,
// naming the byte counts, if this pass's total differs from pass 1's --
// the source data changed between the two passes, which must never happen
// under the exclusive lock (SQLite) / single REPEATABLE READ transaction
// (Postgres, §4) a real `admin backup` run holds for its whole duration, so
// a mismatch here means that invariant was violated, not a normal outcome
// to silently tolerate.
func writeTableEntry(db *gorm.DB, model any, entry TableEntry, tw *tar.Writer) error {
	if err := tw.WriteHeader(&tar.Header{Name: entry.TarName, Mode: 0600, Size: entry.UncompressedSize}); err != nil {
		return fmt.Errorf("write tar header for %s: %w", entry.TarName, err)
	}

	var written int64
	_, err := walkTable(db, model, func(row any) error {
		line, err := ndjsonLine(row)
		if err != nil {
			return err
		}
		n, werr := tw.Write(line)
		written += int64(n)
		return werr
	})
	if err != nil {
		return err
	}
	if written != entry.UncompressedSize {
		return fmt.Errorf("table %s: wrote %d bytes but the hashing pass measured %d -- "+
			"the source data changed between backup's two passes over it, which should never happen "+
			"while the backup lock/transaction is held", entry.Name, written, entry.UncompressedSize)
	}
	return nil
}

// WriteBackup writes a complete v2 logical-format archive (design §3) to w:
// MANIFEST.json first, then every table's NDJSON entry, in RestoreOrder()'s
// derived sequence. db must be a connection/transaction that will observe a
// STABLE view of the data across both the hashing and the writing pass --
// for SQLite, the caller's existing exclusive admin lock already guarantees
// this for the whole `admin backup` run; for Postgres (§4, H4), db must be
// inside the single REPEATABLE READ transaction that spans this entire call.
// schemaEpoch and auditHighWater are the caller's own already-computed
// values (ADR-097's currentSchemaEpoch, and the raw system_metadata
// "audit_checkpoint_highwater" value respectively) -- reading Either is
// backend/connection-specific enough that this package leaves it to the
// caller rather than re-deriving it here.
// keyFiles/keyBlobs are the same key-material bundling `admin backup` has
// always done (internal/keyfiles.Registry, unchanged by the logical-format
// switch -- design §1 "no new subcommands," only the database payload's own
// shape changes) -- the caller reads them off disk and computes keyFiles'
// checksums exactly as v1 did; this function only writes them into the
// archive at the right point and records them in the manifest.
func WriteBackup(db *gorm.DB, schemaEpoch int, auditHighWater string, manifestKey []byte,
	keyFiles []KeyFileEntry, keyBlobs [][]byte, w io.Writer) (Manifest, error) {
	order, err := RestoreOrder()
	if err != nil {
		return Manifest{}, fmt.Errorf("derive restore order: %w", err)
	}
	return writeBackupModels(db, modelsInOrder(order), schemaEpoch, auditHighWater, manifestKey, keyFiles, keyBlobs, w)
}

// writeBackupModels is WriteBackup's actual implementation, parameterized
// over the model list (and its order) rather than always deriving both from
// the live registry -- WriteBackup itself always passes RestoreOrder()'s
// full result; tests use a small explicit subset so they can exercise this
// exact code path without paying for a full 78-table migration per test.
func writeBackupModels(db *gorm.DB, models []any, schemaEpoch int, auditHighWater string, manifestKey []byte,
	keyFiles []KeyFileEntry, keyBlobs [][]byte, w io.Writer) (Manifest, error) {
	if len(keyFiles) != len(keyBlobs) {
		return Manifest{}, fmt.Errorf("internal error: %d key file entries but %d key blobs", len(keyFiles), len(keyBlobs))
	}
	manifest := Manifest{
		FormatVersion: FormatVersion,
		Backend:       Backend,
		CreatedAt:     time.Now().UTC(),
		SchemaEpoch:   schemaEpoch,
		KeyFiles:      keyFiles,
	}

	if auditHighWater != "" {
		cp, sig, ok := auditverify.ParseHighWater(auditHighWater)
		if !ok {
			return Manifest{}, fmt.Errorf("audit high-water value does not parse -- refusing rather than " +
				"write a manifest with a malformed checkpoint")
		}
		manifest.Checkpoint = &auditverify.ExternalAnchorBundle{
			ChainedEvents: cp.ChainedEvents,
			HeadID:        cp.HeadID,
			HeadHash:      cp.HeadHash,
			KeyVersion:    cp.KeyVersion,
			Signature:     sig,
		}
	}

	for _, m := range models {
		entry, err := hashTable(db, m)
		if err != nil {
			return Manifest{}, fmt.Errorf("hash table for %T: %w", m, err)
		}
		manifest.Tables = append(manifest.Tables, entry)
	}

	dangling, err := CheckDanglingReferences(db, models)
	if err != nil {
		return Manifest{}, fmt.Errorf("check dangling references: %w", err)
	}
	manifest.DanglingReferences = dangling

	if err := SignManifest(&manifest, manifestKey); err != nil {
		return Manifest{}, fmt.Errorf("sign manifest: %w", err)
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, fmt.Errorf("encode manifest: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "MANIFEST.json", Mode: 0600, Size: int64(len(manifestJSON))}); err != nil {
		return Manifest{}, fmt.Errorf("write manifest tar header: %w", err)
	}
	if _, err := tw.Write(manifestJSON); err != nil {
		return Manifest{}, fmt.Errorf("write manifest: %w", err)
	}

	for i, kf := range keyFiles {
		if err := tw.WriteHeader(&tar.Header{Name: kf.TarName, Mode: 0600, Size: int64(len(keyBlobs[i]))}); err != nil {
			return Manifest{}, fmt.Errorf("write tar header for key file %q: %w", kf.TarName, err)
		}
		if _, err := tw.Write(keyBlobs[i]); err != nil {
			return Manifest{}, fmt.Errorf("write key file %q: %w", kf.TarName, err)
		}
	}

	for i, m := range models {
		if err := writeTableEntry(db, m, manifest.Tables[i], tw); err != nil {
			return Manifest{}, fmt.Errorf("write table for %T: %w", m, err)
		}
	}

	if err := tw.Close(); err != nil {
		return Manifest{}, fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return Manifest{}, fmt.Errorf("close gzip writer: %w", err)
	}
	return manifest, nil
}
