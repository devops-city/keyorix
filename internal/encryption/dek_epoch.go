// dek_epoch.go — cross-replica DEK epoch (#3337).
//
// dek.lock (exclusive_lock.go) is a flock on ONE host's key directory. With
// several server replicas on one PostgreSQL database (ADR-039; Helm
// server.replicas > 1), each replica may hold its own copy of dek.key, and a
// DEK rotation on one host tells no other replica anything. A replica still
// holding the old DEK (started again with its old dek.key after the rotation,
// or left running when the database presence guard is bypassed or lost) would
// commit new rows under the old DEK, and those rows become undecryptable as
// soon as the operator distributes the new key set and the old DEK is gone.
//
// The database therefore records which DEK it is encrypted under: the DEK
// epoch, system_metadata[dekEpochKey] = the DEK's fingerprint
// (aead.EncryptionService.Fingerprint, an HMAC, not key material), or
// "rotating:<old fingerprint>" while a rotation's sweep is in flight.
//
//   - Server start-up (StartDEKEpochGuard): refuse to start unless the epoch is
//     this server's own fingerprint. An absent epoch (first boot, or the first
//     boot after upgrading) is seeded with this server's fingerprint, but only
//     after this DEK decrypts the newest encrypted secret version, so a stale
//     replica that happens to boot first cannot claim the epoch.
//   - Runtime (dekEpochWatch): a goroutine re-reads the epoch every
//     dekEpochPollInterval. Encrypt* refuse with ErrDEKWriteFenced unless a
//     poll that started at most dekEpochMaxStaleness ago saw this server's own
//     fingerprint. Decrypt is never fenced, and no revocation path encrypts, so
//     reads and revocations keep working on a fenced replica.
//   - Rotation (Service.RotateDEKWithSweep, fenceDEKEpochForRotation): commit
//     "rotating:<old>" first (every replica's writes are refused from then on),
//     wait dekEpochFenceWait (> dekEpochMaxStaleness: by then no replica can
//     still be encrypting under the old DEK), then sweep in a transaction that
//     holds every swept table in SHARE ROW EXCLUSIVE mode (waits for in-flight writers,
//     blocks new ones until commit) and swaps the epoch to the new fingerprint
//     with a compare-and-set in the same transaction as the re-encryption.
//
// PostgreSQL only. SQLite is single-node (one process holds the database and
// dek.lock), so none of this runs there and its behaviour is unchanged.
//
// What this does not cover (stated, per this repo's convention): a write
// whose encryption happened before its replica saw the fence and whose INSERT
// starts more than dekEpochFenceWait - dekEpochMaxStaleness later (a stall of
// several seconds between the two). That needs the presence guard to have
// been bypassed or lost as well: `admin encryption rotate` normally refuses
// while any server is attached to the database (internal/serverguard). A
// server binary that predates this file does not check the epoch at all;
// upgrade every replica before rotating.
package encryption

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// dekEpochKey is the system_metadata key holding the DEK epoch. Not secret.
const dekEpochKey = "dek.epoch"

// DEKEpochMetadataKey is dekEpochKey for callers outside the package: the
// presence of this row means some replica already generated the deployment's DEK.
const DEKEpochMetadataKey = dekEpochKey

// dekEpochRotatingPrefix marks an epoch fenced by an in-flight rotation; the
// fingerprint after it is the DEK being rotated away from.
const dekEpochRotatingPrefix = "rotating:"

// Timing of the fence. dekEpochFenceWait must exceed dekEpochMaxStaleness: a
// replica that last confirmed the epoch just before the fence committed can
// keep encrypting for up to dekEpochMaxStaleness; the rest is grace for an
// encrypted write to reach the database. Vars so tests can shorten them.
var (
	dekEpochPollInterval     = 2 * time.Second
	dekEpochMaxStaleness     = 5 * time.Second
	dekEpochFenceWait        = 10 * time.Second
	dekEpochSweepLockTimeout = "30s"
)

// ErrDEKWriteFenced is returned by Encrypt* while this replica cannot confirm
// that its DEK is the database's current DEK: a rotation is in flight or has
// completed elsewhere, or the epoch could not be read recently. Fail closed:
// the write is refused, reads are not affected.
var ErrDEKWriteFenced = errors.New("encryption refused: this server cannot confirm that its DEK is the database's current DEK (a DEK rotation is in progress or finished on another host, or the database is unreachable)")

// ErrDEKEpochMismatch means this server's DEK is not the DEK the database is
// encrypted under.
var ErrDEKEpochMismatch = errors.New("this server's DEK is not the DEK the database is encrypted under")

// dekEpochApplies reports whether the DEK epoch is enforced on db: PostgreSQL
// only (see the file comment).
func dekEpochApplies(db *gorm.DB) bool {
	return db != nil && db.Dialector != nil && db.Name() == "postgres"
}

// readDEKEpoch returns the stored epoch, found=false when there is none.
func readDEKEpoch(db *gorm.DB) (value string, found bool, err error) {
	var rows []models.SystemMetadata
	if err := db.Where("key = ?", dekEpochKey).Limit(1).Find(&rows).Error; err != nil {
		return "", false, fmt.Errorf("read DEK epoch: %w", err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0].Value, true, nil
}

// casDEKEpoch sets the epoch to next only if it is currently from, and reports
// whether it did.
func casDEKEpoch(db *gorm.DB, from, next string) (bool, error) {
	res := db.Model(&models.SystemMetadata{}).Where("key = ? AND value = ?", dekEpochKey, from).
		Updates(map[string]any{"value": next, "updated_at": time.Now().UTC()})
	if res.Error != nil {
		return false, fmt.Errorf("update DEK epoch: %w", res.Error)
	}
	return res.RowsAffected == 1, nil
}

// dekEpochWatch is a running replica's view of the epoch. lastMatch holds the
// start time (nanoseconds since base, +1 so 0 means "fenced") of the newest
// poll that read this replica's own fingerprint.
type dekEpochWatch struct {
	db        *gorm.DB
	own       string
	release   func()
	base      time.Time
	lastMatch atomic.Int64
	observed  atomic.Pointer[string] // the epoch the last fencing poll read
	fenced    atomic.Bool            // last poll outcome, for transition logging only
	// readFailing is set while polls fail to read the epoch, for logging only.
	readFailing atomic.Bool
	stop        chan struct{}
	done        chan struct{}
	stopOnce    sync.Once
}

func (w *dekEpochWatch) markMatch(start time.Duration) { w.lastMatch.Store(int64(start) + 1) }

// allowWrite is the Encrypt* gate. Atomics only: no I/O on the write path.
func (w *dekEpochWatch) allowWrite() error {
	lm := w.lastMatch.Load()
	if lm == 0 {
		obs := ""
		if p := w.observed.Load(); p != nil {
			obs = *p
		}
		return fmt.Errorf("%w (database DEK epoch %q, this server %q)", ErrDEKWriteFenced, obs, w.own)
	}
	if age := time.Since(w.base) - time.Duration(lm-1); age > dekEpochMaxStaleness {
		return fmt.Errorf("%w (DEK epoch last confirmed %s ago)", ErrDEKWriteFenced, age.Round(time.Millisecond))
	}
	return nil
}

func (w *dekEpochWatch) poll() {
	start := time.Since(w.base)
	ctx, cancel := context.WithTimeout(context.Background(), dekEpochMaxStaleness)
	defer cancel()
	v, found, err := readDEKEpoch(w.db.WithContext(ctx))
	if err != nil {
		// Leave lastMatch alone: allowWrite fences once it is older than
		// dekEpochMaxStaleness. Logged once per outage, not every poll.
		if !w.readFailing.Swap(true) {
			log.Printf("[WARN] DEK epoch check failed (encrypted writes stop if this persists for %s): %v", dekEpochMaxStaleness, err)
		}
		return
	}
	if w.readFailing.Swap(false) {
		log.Printf("DEK epoch check succeeded again")
	}
	if found && v == w.own {
		w.markMatch(start)
		if w.fenced.Swap(false) {
			log.Printf("DEK epoch matches this server's DEK again: encrypted writes resumed")
		}
		return
	}
	w.observed.Store(&v)
	w.lastMatch.Store(0)
	if !w.fenced.Swap(true) {
		log.Printf("[WARN] DEK epoch is now %q, this server's DEK is %q: refusing encrypted writes (reads continue). "+
			"A DEK rotation is in progress or finished on another host; restart this server with the current key set.", v, w.own)
	}
}

func (w *dekEpochWatch) run() {
	defer close(w.done)
	t := time.NewTicker(dekEpochPollInterval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.poll()
		}
	}
}

func (w *dekEpochWatch) close() {
	w.stopOnce.Do(func() {
		close(w.stop)
		<-w.done
		if w.release != nil {
			w.release()
		}
	})
}

// StartDEKEpochGuard checks, at server start-up, that this server's DEK is the
// database's DEK, and then keeps checking it (see the file comment). db is a
// handle the guard may keep for the server's lifetime; release, if non-nil,
// is called once the guard stops (Shutdown). A no-op returning nil, without
// calling release, when db is not PostgreSQL: the caller keeps the handle.
//
// Must run after Initialize and after the schema is migrated. Returns an
// error wrapping ErrDEKEpochMismatch when the server must not start.
func (s *Service) StartDEKEpochGuard(db *gorm.DB, release func()) error {
	if !dekEpochApplies(db) {
		return nil
	}
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return fmt.Errorf("DEK epoch guard: encryption service not initialized")
	}
	own, err := s.encryptionService.Fingerprint()
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	base := time.Now()
	if err := s.verifyOrSeedDEKEpoch(db, own); err != nil {
		return err
	}
	w := &dekEpochWatch{db: db, own: own, release: release, base: base, stop: make(chan struct{}), done: make(chan struct{})}
	w.markMatch(0) // verified just now, after base
	s.mu.Lock()
	if s.epoch != nil {
		s.mu.Unlock()
		return fmt.Errorf("DEK epoch guard already running")
	}
	s.epoch = w
	s.mu.Unlock()
	go w.run()
	return nil
}

func (s *Service) verifyOrSeedDEKEpoch(db *gorm.DB, own string) error {
	v, found, err := readDEKEpoch(db)
	if err != nil {
		return err
	}
	if !found {
		if err := s.probeDecryptsNewestSecretVersion(db); err != nil {
			return fmt.Errorf("%w: the database has no DEK epoch yet and this server's DEK cannot decrypt its newest secret version (%v). "+
				"Start a replica that holds the current key set first", ErrDEKEpochMismatch, err)
		}
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&models.SystemMetadata{Key: dekEpochKey, Value: own}).Error; err != nil {
			return fmt.Errorf("seed DEK epoch: %w", err)
		}
		if v, _, err = readDEKEpoch(db); err != nil {
			return err
		}
		if v == own {
			log.Printf("DEK epoch recorded for this database: %s", own)
		}
	}
	if v == dekEpochRotatingPrefix+own {
		// This server holds the database presence lock (taken before encryption
		// starts), so no `admin encryption rotate` is running: the fence is left
		// over from a rotation that stopped before its sweep committed, and the
		// old DEK (this one) is still the database's DEK. Lifting it is safe even
		// against a --force rotation: its final compare-and-set then fails and it
		// rolls back.
		if _, err := casDEKEpoch(db, v, own); err != nil {
			return err
		}
		log.Printf("[WARN] lifted a DEK rotation fence left by an interrupted rotation (the database is still under this server's DEK)")
		if v, _, err = readDEKEpoch(db); err != nil {
			return err
		}
	}
	if v != own {
		return fmt.Errorf("%w: the database's DEK epoch is %q, this server's DEK fingerprint is %q. "+
			"The DEK was rotated on another host (or this host has another installation's key files): copy the current key files "+
			"(dek.key, kek.salt) from the host that rotated before starting this server. Starting with this DEK would write rows "+
			"nobody can decrypt once the old DEK is gone", ErrDEKEpochMismatch, v, own)
	}
	return nil
}

// probeDecryptsNewestSecretVersion checks that this server's DEK decrypts the
// newest encrypted secret version, if there is one. Rows whose metadata names
// no algorithm (written while encryption was disabled) are skipped.
func (s *Service) probeDecryptsNewestSecretVersion(db *gorm.DB) error {
	if !db.Migrator().HasTable(&models.SecretVersion{}) {
		return nil
	}
	var rows []models.SecretVersion
	if err := db.Order("id DESC").Limit(50).Find(&rows).Error; err != nil {
		return fmt.Errorf("read newest secret versions: %w", err)
	}
	for _, r := range rows {
		var meta struct {
			Algorithm string `json:"algorithm"`
		}
		if len(r.EncryptedValue) == 0 || json.Unmarshal(r.EncryptionMetadata, &meta) != nil || meta.Algorithm == "" {
			continue
		}
		var node models.SecretNode
		if err := db.Unscoped().Select("id, project_id").Where("id = ?", r.SecretNodeID).Limit(1).Find(&node).Error; err != nil {
			return fmt.Errorf("read secret node %d: %w", r.SecretNodeID, err)
		}
		pt, err := s.DecryptSecretWithAAD(r.EncryptedValue, SecretAAD(r.SecretNodeID, node.ProjectID, r.VersionNumber))
		if err != nil {
			return fmt.Errorf("secret version id=%d: %w", r.ID, err)
		}
		wipeBytes(pt)
		return nil
	}
	return nil
}

// checkWriteEpoch is called by every Encrypt* method with s.mu held (read).
func (s *Service) checkWriteEpoch() error {
	if s.epoch == nil {
		return nil
	}
	return s.epoch.allowWrite()
}

// sweptModels are the models whose rows SweepAllTables re-encrypts. The
// rotation holds their tables in SHARE ROW EXCLUSIVE mode for the sweep.
// TestSweptModels_MatchSweptFields keeps this in step with the sweep.
func sweptModels() []any {
	return []any{
		&models.SecretVersion{}, &models.APIToken{}, &models.APIClient{}, &models.PasswordReset{},
		&models.MFASecret{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.NotificationChannel{},
	}
}

// rotationEpochFence is a committed "rotating:<old>" fence held by one rotation.
type rotationEpochFence struct {
	fenced   string // "rotating:<old fingerprint>"
	restore  string // value to restore on failure; "" means delete (there was no epoch)
	released bool
}

// fenceDEKEpochForRotation commits the rotation fence and waits for every
// replica to stop encrypting under the old DEK. Refuses when the database's
// epoch is not this host's DEK.
func fenceDEKEpochForRotation(db *gorm.DB, oldSvc *EncryptionService) (*rotationEpochFence, error) {
	old, err := oldSvc.Fingerprint()
	if err != nil {
		return nil, err
	}
	f := &rotationEpochFence{fenced: dekEpochRotatingPrefix + old, restore: old}
	err = db.Transaction(func(tx *gorm.DB) error {
		var rows []models.SystemMetadata
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("key = ?", dekEpochKey).Limit(1).Find(&rows).Error; err != nil {
			return fmt.Errorf("read DEK epoch: %w", err)
		}
		if len(rows) == 0 {
			res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SystemMetadata{Key: dekEpochKey, Value: f.fenced})
			if res.Error != nil {
				return fmt.Errorf("write DEK rotation fence: %w", res.Error)
			}
			if res.RowsAffected != 1 {
				return fmt.Errorf("the DEK epoch was written concurrently; retry the rotation")
			}
			f.restore = ""
			return nil
		}
		if v := rows[0].Value; v != old && v != f.fenced {
			return fmt.Errorf("%w: refusing to rotate: the database's DEK epoch is %q but this host's DEK fingerprint is %q, "+
				"so this host's key files are not the database's current key set", ErrDEKEpochMismatch, v, old)
		}
		return tx.Model(&models.SystemMetadata{}).Where("key = ?", dekEpochKey).
			Updates(map[string]any{"value": f.fenced, "updated_at": time.Now().UTC()}).Error
	})
	if err != nil {
		return nil, err
	}
	log.Printf("DEK rotation: encrypted writes are now refused on every replica; waiting %s for replicas to observe it", dekEpochFenceWait)
	time.Sleep(dekEpochFenceWait)
	return f, nil
}

// lockSweptTables holds every swept table in SHARE ROW EXCLUSIVE mode for the rest of tx:
// it waits for in-flight writers to commit (their rows are then visible to the
// sweep) and blocks new writes until the sweep commits. Reads continue.
func (f *rotationEpochFence) lockSweptTables(tx *gorm.DB) error {
	if err := tx.Exec("SELECT set_config('lock_timeout', ?, true)", dekEpochSweepLockTimeout).Error; err != nil {
		return fmt.Errorf("set sweep lock timeout: %w", err)
	}
	var quoted []string
	for _, m := range sweptModels() {
		stmt := &gorm.Statement{DB: tx}
		if err := stmt.Parse(m); err != nil {
			return fmt.Errorf("resolve swept table: %w", err)
		}
		if !tx.Migrator().HasTable(stmt.Schema.Table) {
			continue
		}
		quoted = append(quoted, tx.Statement.Quote(stmt.Schema.Table))
	}
	if len(quoted) == 0 {
		return nil
	}
	if err := tx.Exec("LOCK TABLE " + strings.Join(quoted, ", ") + " IN SHARE ROW EXCLUSIVE MODE").Error; err != nil {
		return fmt.Errorf("lock swept tables for the re-encryption sweep (a long-running write transaction holds one?): %w", err)
	}
	return nil
}

// commitNewEpoch swaps the fence for the new DEK's fingerprint inside the
// sweep transaction. Fails (and the sweep rolls back) if the fence is gone.
func (f *rotationEpochFence) commitNewEpoch(tx *gorm.DB, newSvc *EncryptionService) error {
	next, err := newSvc.Fingerprint()
	if err != nil {
		return err
	}
	ok, err := casDEKEpoch(tx, f.fenced, next)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the DEK rotation fence was lifted while the sweep ran (a server restarted and cleared it); the old DEK stays active, retry the rotation")
	}
	return nil
}

// lift restores the epoch after a failed rotation, if the fence is still ours.
func (f *rotationEpochFence) lift(db *gorm.DB) {
	if f == nil || f.released {
		return
	}
	f.released = true
	var err error
	if f.restore == "" {
		err = db.Where("key = ? AND value = ?", dekEpochKey, f.fenced).Delete(&models.SystemMetadata{}).Error
	} else {
		_, err = casDEKEpoch(db, f.fenced, f.restore)
	}
	if err != nil {
		log.Printf("[WARN] DEK rotation failed and its write fence could not be lifted (%v): encrypted writes stay refused until a server restarts with the current key set or the rotation is re-run", err)
	}
}

// DEKEpochGuardRunning reports whether StartDEKEpochGuard started a guard
// (PostgreSQL) that now owns its database handle.
func (s *Service) DEKEpochGuardRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.epoch != nil
}
