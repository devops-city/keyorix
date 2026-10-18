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
// whose checks pass with nothing softened; for require_mfa, setting the key
// explicitly (ADR-112 names no compliance condition for MFA; an end condition
// is tracked as a follow-up issue). Any error while deciding fails closed (no
// grace).
//
// The same decision, with its own marker (adr112.scim_token_strength.enforced),
// covers the SCIM token shape checks added by #3397 (scim_token_strength.go):
// they end with the first boot that did not soften them.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
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
	adr112SCIMTokenEnforcedKey  = config.ADR112SCIMTokenEnforcedMarker
)

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
// Under the require_mfa grace it sets RequireMFA to false for this boot: that is
// the value the HTTP router, the gRPC interceptors and the settings endpoint all
// read, so the effective setting and what the server reports agree.
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
			sec.RequireMFA = false
			sec.RequireMFAUpgradeGrace = true
		}
		adr112MFAReason = why
	}
}

// adr112State is what the database says about this deployment.
type adr112State struct {
	fresh                             bool
	fileMarker, mfaMarker, scimMarker string // the marker's value, "" when absent
	why                               string // fresh / undecidable reason, or "" for an upgrade
	failClosed                        bool
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
	for key, dst := range map[string]*string{adr112FilePermEnforcedKey: &st.fileMarker, adr112RequireMFAEnforcedKey: &st.mfaMarker, adr112SCIMTokenEnforcedKey: &st.scimMarker} {
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
// is in force, adr112SCIMTokenEnforcedKey whenever enforceSCIMTokenStrength did
// not soften a weak SCIM token (#3397; also when SCIM is off: the grace period
// is for a token that was already in use, not one configured later). A later
// boot of the same deployment (a fresh install's second
// start included) is then enforced. Best-effort: a failure leaves the deployment
// in whatever state it was (a fresh install stays enforced through its user count
// until the next boot that manages to write it).
func recordADR112Markers(cfg *config.Config) {
	var keys []string
	if cfg.Security.EnableFilePermissionCheck && !adr112GraceSoftened.Load() {
		keys = append(keys, adr112FilePermEnforcedKey)
	}
	if cfg.Security.RequireMFA {
		keys = append(keys, adr112RequireMFAEnforcedKey)
	}
	if !adr112SCIMTokenSoftened.Load() {
		keys = append(keys, adr112SCIMTokenEnforcedKey)
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
