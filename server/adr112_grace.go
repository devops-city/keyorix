// adr112_grace.go — decides whether a boot is inside ADR-112's upgrade grace
// period for security.enable_file_permission_check and security.require_mfa,
// and ratchets a deployment out of it.
//
// ADR-112 flips both keys' defaults to true. "Absent from the config file"
// (…ImplicitDefault) is true for a fresh install and for an upgraded one alike,
// so it cannot by itself decide whether the grace period applies: a fresh
// install must be enforced from its first start, and only an existing
// deployment that relied on the old implicit-false default gets warnings
// instead. The fact that separates the two lives in the database:
//
//   - no database yet, or a database with no users: a fresh install -> enforced;
//   - the key's adr112.*.enforced system_metadata marker is present: this
//     deployment has already been enforced once -> enforced. The markers are
//     written after a boot that enforced the key (recordADR112Markers), so the
//     grace period never comes back once it has ended (a ratchet, not a timer);
//   - users exist and the marker is absent: an upgraded deployment still inside
//     the grace period.
//
// What ends the grace period: for enable_file_permission_check, the first boot
// whose checks pass with nothing softened; for require_mfa (#2923), the first
// administrator MFA enrolment or 30 days after the grace start, whichever comes
// first (or setting the key explicitly). The require_mfa start is recorded in
// system_metadata by the first graced boot (beginADR112MFAGrace), never derived
// from the clock alone, and the running server ends the grace period without a
// restart (internal/core/mfa_upgrade_grace.go). Any error while deciding fails
// closed (no grace).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// The system_metadata markers recording that this deployment is past (or was
// never in) ADR-112's grace period for that setting; defined in internal/config
// so the posture report (server/admin) reads the same keys.
const (
	adr112FilePermEnforcedKey   = config.ADR112FilePermEnforcedMarker
	adr112RequireMFAEnforcedKey = config.ADR112RequireMFAEnforcedMarker
)

// adr112MFAWindow is the require_mfa grace window beginADR112MFAGrace read and
// recorded for this boot; armADR112MFAGrace hands it to core. Zero unless
// RequireMFAUpgradeGrace was set.
var adr112MFAWindow core.MFAUpgradeGraceWindow

// adr112Now is the boot's wall clock (no monotonic reading); replaced in tests.
var adr112Now = func() time.Time { return time.Now().Round(0) }

// adr112MFAReason is applyADR112UpgradeGrace's reason for the require_mfa
// decision, for logWarnOnImplicitRequireMFADefault's start-up message.
var adr112MFAReason string

// adr112GraceSoftened is set when a grace-period branch (runStartupValidation or
// enforceKeyFilePermissions) turned a real failure into a warning during this
// boot. recordADR112Markers then leaves the deployment in the grace
// period instead of ratcheting it to enforced.
var adr112GraceSoftened atomic.Bool

// applyADR112UpgradeGrace decides both grace periods from one look at the
// database and logs the decisions for keys left at their implicit default.
// Under the require_mfa grace it records the grace start and clock
// (beginADR112MFAGrace) and sets RequireMFAUpgradeGrace; RequireMFA stays true,
// and every MFA gate subtracts the running grace period through
// core.KeyorixCore.MFARequired once armADR112MFAGrace installed it.
func applyADR112UpgradeGrace(cfg *config.Config) {
	sec := &cfg.Security
	fileImplicit := sec.EnableFilePermissionCheck && sec.EnableFilePermissionCheckImplicitDefault
	mfaImplicit := sec.RequireMFA && sec.RequireMFAImplicitDefault
	if !fileImplicit && !mfaImplicit {
		return
	}
	st := inspectADR112State(cfg)

	if fileImplicit {
		eligible, why := st.grace(st.fileMarker)
		sec.EnableFilePermissionCheckUpgradeGrace = eligible
		if eligible {
			log.Printf("WARNING: ADR-112 grace period: security.enable_file_permission_check now defaults to true and this config never set it; %s. A problem the startup checks find is logged as a warning instead of refusing to start until this deployment boots clean once (it is then enforced for good) or sets the key explicitly.", why)
		} else {
			log.Printf("INFO: security.enable_file_permission_check is enforcing on its ADR-112 secure-by-default value (never set in this config); %s, so a problem with key material or the database refuses to start.", why)
		}
	}
	if mfaImplicit {
		eligible, why := st.grace(st.mfaMarker)
		if eligible {
			eligible, why = beginADR112MFAGrace(cfg, adr112Now())
		}
		sec.RequireMFAUpgradeGrace = eligible
		adr112MFAReason = why
	}
}

// beginADR112MFAGrace records the require_mfa grace start (first graced boot
// only: an existing start is kept) and the grace clock, and decides whether the
// window is still open at now. The grace clock is max(now, the recorded clock,
// the start): a clock stepped backwards since the last boot reads as the
// recorded time, so it cannot extend the window. Any failure to record or read
// the facts fails closed (no grace).
func beginADR112MFAGrace(cfg *config.Config, now time.Time) (bool, string) {
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		return false, "could not open the database to record the grace period start (" + err.Error() + "), failing closed"
	}
	defer closeGormDB(db)
	w, clockBehind, err := recordADR112MFAGraceWindow(db, now)
	if err != nil {
		return false, "could not record the grace period start (" + err.Error() + "), failing closed"
	}
	if clockBehind > 0 {
		log.Printf("WARNING: ADR-112 grace period: the system clock reads %s, %s earlier than this deployment last recorded (%s); the grace period counts from the recorded time, a clock set back does not extend it.", now.UTC().Format(time.RFC3339), clockBehind.Round(time.Second), w.Floor.UTC().Format(time.RFC3339))
	}
	if !w.Floor.Before(w.Deadline) {
		return false, "this upgraded deployment's 30-day grace period ended at " + w.Deadline.UTC().Format(time.RFC3339)
	}
	adr112MFAWindow = w
	return true, "this is an upgraded deployment (its database already has users)"
}

// recordADR112MFAGraceWindow is beginADR112MFAGrace's database half. It returns
// the window (Floor = the grace clock at now) and how far now is behind the
// recorded clock (0 when it is not).
func recordADR112MFAGraceWindow(db *gorm.DB, now time.Time) (core.MFAUpgradeGraceWindow, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db = db.WithContext(ctx)
	if !db.Migrator().HasTable(&models.SystemMetadata{}) {
		return core.MFAUpgradeGraceWindow{}, 0, errors.New("no system_metadata table")
	}
	if err := recordADR112Enforced(db, config.ADR112RequireMFAGraceStartedKey, now); err != nil {
		return core.MFAUpgradeGraceWindow{}, 0, err
	}
	start, found, err := readADR112Time(db, config.ADR112RequireMFAGraceStartedKey)
	if err != nil {
		return core.MFAUpgradeGraceWindow{}, 0, err
	}
	if !found {
		return core.MFAUpgradeGraceWindow{}, 0, errors.New("the grace start did not persist")
	}
	clock, found, err := readADR112Time(db, config.ADR112RequireMFAGraceClockKey)
	if err != nil {
		return core.MFAUpgradeGraceWindow{}, 0, err
	}
	floor := start
	if found && clock.After(floor) {
		floor = clock
	}
	var behind time.Duration
	if now.Before(floor) {
		behind = floor.Sub(now)
	} else {
		floor = now
	}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemMetadata{
		Key: config.ADR112RequireMFAGraceClockKey, Value: floor.UTC().Format(time.RFC3339), UpdatedAt: now,
	}).Error; err != nil {
		return core.MFAUpgradeGraceWindow{}, 0, err
	}
	return core.MFAUpgradeGraceWindow{
		Start: start, Deadline: start.Add(config.ADR112RequireMFAGracePeriod), Floor: floor,
		EnforcedMarkerKey: adr112RequireMFAEnforcedKey, ClockKey: config.ADR112RequireMFAGraceClockKey,
	}, behind, nil
}

// readADR112Time reads an RFC 3339 system_metadata value. A value that does not
// parse is an error (fail closed), not "absent".
func readADR112Time(db *gorm.DB, key string) (time.Time, bool, error) {
	var row models.SystemMetadata
	err := db.Where("key = ?", key).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse(time.RFC3339, row.Value)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("%s holds %q, not an RFC 3339 time", key, row.Value)
	}
	return t, true, nil
}

// armADR112MFAGrace installs this boot's require_mfa grace window into core and
// evaluates it once, so the start-up log says how many days are left, or that
// it just ended (an administrator had already enrolled). An end at this point
// clears RequireMFAUpgradeGrace, so the settings diff and the markers record
// this boot as enforced.
func armADR112MFAGrace(cfg *config.Config, coreService *core.KeyorixCore) {
	if !cfg.Security.RequireMFAUpgradeGrace {
		return
	}
	coreService.StartMFAUpgradeGrace(adr112MFAWindow)
	coreService.MFAUpgradeGraceActive()
	if coreService.MFAUpgradeGraceEnded() {
		cfg.Security.RequireMFAUpgradeGrace = false
	}
}

// adr112State is what the database says about this deployment.
type adr112State struct {
	fresh                 bool
	fileMarker, mfaMarker string // the marker's value, "" when absent
	why                   string // fresh / undecidable reason, or "" for an upgrade
	failClosed            bool
}

// grace reports whether a key whose marker is marker gets the grace period.
func (st adr112State) grace(marker string) (bool, string) {
	switch {
	case st.failClosed || st.fresh:
		return false, st.why
	case marker != "":
		return false, "this deployment has been enforced since " + marker
	default:
		return true, "this is an upgraded deployment (its database already has users)"
	}
}

// adr112UpgradeGraceEligible reports whether this boot is an upgraded deployment
// inside the enable_file_permission_check grace period, with a reason either way.
func adr112UpgradeGraceEligible(cfg *config.Config) (bool, string) {
	sec := cfg.Security
	if !sec.EnableFilePermissionCheck || !sec.EnableFilePermissionCheckImplicitDefault {
		return false, "the key is set explicitly"
	}
	st := inspectADR112State(cfg)
	return st.grace(st.fileMarker)
}

// inspectADR112State reads the database facts. It never creates the database: a
// local SQLite file that does not exist yet is a fresh install, and is left for
// the normal boot path to create with its own permissions.
func inspectADR112State(cfg *config.Config) adr112State {
	switch cfg.Storage.Type {
	case "postgres", "postgresql":
	default: // "local", "sqlite", ""
		if _, err := os.Stat(cfg.Storage.Database.Path); errors.Is(err, os.ErrNotExist) {
			return adr112State{fresh: true, why: "this is a fresh install (no database yet)"}
		} else if err != nil {
			return adr112State{failClosed: true, why: "could not inspect the database file (" + err.Error() + "), failing closed"}
		}
	}
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		return adr112State{failClosed: true, why: "could not open the database to tell a fresh install from an upgrade (" + err.Error() + "), failing closed"}
	}
	defer closeGormDB(db)
	return adr112StateFromDB(db)
}

// adr112StateFromDB is inspectADR112State's database half.
func adr112StateFromDB(db *gorm.DB) adr112State {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db = db.WithContext(ctx)
	m := db.Migrator()
	if !m.HasTable(&models.User{}) {
		return adr112State{fresh: true, why: "this is a fresh install (no schema yet)"}
	}
	var users int64
	if err := db.Unscoped().Model(&models.User{}).Count(&users).Error; err != nil {
		return adr112State{failClosed: true, why: "could not count users (" + err.Error() + "), failing closed"}
	}
	if users == 0 {
		return adr112State{fresh: true, why: "this is a fresh install (no users yet)"}
	}
	st := adr112State{}
	if !m.HasTable(&models.SystemMetadata{}) {
		return st
	}
	for key, dst := range map[string]*string{adr112FilePermEnforcedKey: &st.fileMarker, adr112RequireMFAEnforcedKey: &st.mfaMarker} {
		var row models.SystemMetadata
		err := db.Where("key = ?", key).Take(&row).Error
		switch {
		case err == nil:
			*dst = row.Value
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return adr112State{failClosed: true, why: "could not read the ADR-112 enforcement markers (" + err.Error() + "), failing closed"}
		}
	}
	return st
}

// recordADR112Markers writes the enforcement markers for the keys this boot
// enforced: adr112FilePermEnforcedKey once the startup checks ran and nothing was
// softened by the grace period, adr112RequireMFAEnforcedKey whenever require_mfa
// is in force and not in its grace period (a grace period that ends while the
// server runs writes the marker itself, internal/core/mfa_upgrade_grace.go). A later boot of the same deployment (a fresh install's second
// start included) is then enforced. Best-effort: a failure leaves the deployment
// in whatever state it was (a fresh install stays enforced through its user count
// until the next boot that manages to write it).
func recordADR112Markers(cfg *config.Config) {
	var keys []string
	if cfg.Security.EnableFilePermissionCheck && !adr112GraceSoftened.Load() {
		keys = append(keys, adr112FilePermEnforcedKey)
	}
	if cfg.Security.RequireMFA && !cfg.Security.RequireMFAUpgradeGrace {
		keys = append(keys, adr112RequireMFAEnforcedKey)
	}
	if len(keys) == 0 {
		return
	}
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		log.Printf("ADR-112: could not record the enforcement markers: %v (continuing)", err)
		return
	}
	defer closeGormDB(db)
	for _, k := range keys {
		if err := recordADR112Enforced(db, k, time.Now()); err != nil {
			log.Printf("ADR-112: could not record the %s marker: %v (continuing)", k, err)
		}
	}
}

// recordADR112Enforced inserts the marker if it is not already there; the first
// recorded time is kept.
func recordADR112Enforced(db *gorm.DB, key string, now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SystemMetadata{
		Key:       key,
		Value:     now.UTC().Format(time.RFC3339),
		UpdatedAt: now,
	}).Error
}

func closeGormDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
