package store

import (
	"fmt"

	"gorm.io/gorm"
)

// CheckAuditIDSequenceCache refuses a Postgres database whose audit_events id
// sequence caches more than one value.
//
// The pipelined audit commit (runAuditPipeline) reserves a batch's ids with
// nextval under the audit advisory lock and requires them to sort after the
// chain head. With CACHE n > 1 each session pre-allocates a private block of
// n ids, so a session that took the lock later can hand out ids BELOW the head
// another session already committed; the commit would then be rejected
// ("first allocated id ... does not sort after the chain head"). The in-flight
// checks keep the chain intact, but every audit write would fail: we fail
// closed at startup with an actionable message instead of at the first write.
//
// No-op on other dialects and when audit_events does not exist yet (a fresh
// install creates it through AutoMigrate with the default CACHE 1).
func CheckAuditIDSequenceCache(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" {
		return nil
	}
	var exists bool
	if err := db.Raw("SELECT to_regclass('audit_events') IS NOT NULL").Scan(&exists).Error; err != nil {
		return fmt.Errorf("audit_events id sequence check: %w", err)
	}
	if !exists {
		return nil
	}
	var seq *string
	if err := db.Raw("SELECT pg_get_serial_sequence('audit_events', 'id')").Scan(&seq).Error; err != nil {
		return fmt.Errorf("audit_events id sequence check: %w", err)
	}
	if seq == nil {
		return fmt.Errorf("audit_events.id has no owned sequence: the audit chain needs a serial/identity id column handing out ids in order")
	}
	var cache int64
	if err := db.Raw("SELECT seqcache FROM pg_sequence WHERE seqrelid = ?::regclass", *seq).Scan(&cache).Error; err != nil {
		return fmt.Errorf("audit_events id sequence check: %w", err)
	}
	if cache > 1 {
		return fmt.Errorf("sequence %s has CACHE %d: the audit chain needs CACHE 1 so ids are handed out in lock order; run: ALTER SEQUENCE %s CACHE 1", *seq, cache, *seq)
	}
	return nil
}
