// snapshot_test.go builds a canonical, hashable dump of every table in
// models.AllTestModels() — the "logical-state snapshot, taken with faults off"
// STEP 0 asked for. It exists so an oracle can compare pre-fault and post-fault
// (or post-drop-fault) database state without depending on a hand-maintained
// shadow model that can drift from the real schema (models.AllTestModels() is
// this repo's own single source of truth for the SQLite test schema — see its
// doc comment — so this snapshot can never silently miss a table that gets
// migrated).
package faultops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// timeType/timePtrType back the STRUCTURAL timestamp exclusion below: every
// time.Time/*time.Time field is wall-clock and run-relative by construction, so
// it is excluded by TYPE rather than by hand-enumerated field name. An earlier
// version of this file excluded timestamps by name (CreatedAt, UpdatedAt, ...)
// and missed LastSeenAt, LastLoginAt, PasswordChangedAt, LastFailedLoginAt,
// LoginLockedUntil, AbsoluteExpiresAt, ImpersonationStartedAt one at a time as
// each caused a false "state differs" oracle failure between two independently
// bootstrapped worlds — textbook "enumeration only as complete as the idioms it
// knows about" (CLAUDE.md). Excluding by type closes the whole class at once;
// see timeFieldOverrides below for the (currently empty) escape hatch if a
// future op ever needs to assert on a specific timestamp's VALUE.
var timeType = reflect.TypeOf(time.Time{})
var timePtrType = reflect.TypeOf(&time.Time{})

// timeFieldOverrides lists time.Time/*time.Time fields that ARE logically
// meaningful and must NOT be excluded by the structural rule above — empty
// today because no opCatalog operation asserts on a specific timestamp value.
var timeFieldOverrides = map[string]bool{}

// excludedFields are dropped entirely before hashing for reasons OTHER than
// "it's a timestamp" (that whole class is handled structurally by type, see
// above): PrevHash/EntryHash/HeadHash are derived from other excluded,
// run-relative fields and therefore run-relative too. One justification each,
// per STEP 0's requirement.
var excludedFields = map[string]string{
	"PrevHash":  "audit hash-chain link (ADR-029): SHA256 over every prior row's content, which itself includes excluded run-relative fields — comparing it is comparing excluded data transitively",
	"EntryHash": "see PrevHash",
	"HeadHash":  "audit checkpoint hash — see PrevHash",
}

// presenceOnlyFields are reduced to a "was a value written at all" boolean
// instead of compared byte-for-byte: each holds AEAD ciphertext, a salted hash,
// or authenticator-generated key material, so an identical logical operation
// legitimately produces different bytes on every run (a fresh random nonce/salt
// each time). Derived by grepping internal/storage/models/models.go for every
// field whose name ends in Hash/Enc, or that holds WebAuthn credential material
// (2026-09-21) — not guessed; extend this list the same way if a new one
// appears, per CLAUDE.md's "state which call forms the enumeration recognizes."
//
// 2026-09-29 (Session Z, Z1): that enumeration only knew "ends in Hash/Enc" and
// missed each *Enc field's own metadata sibling. c.encryptAuthSecret's callers
// (internal/core/service.go) marshal an EncryptionMetadata struct
// (internal/encryption/encryption.go) into a `*Meta []byte` column alongside
// every `*Enc` column it produces; that struct embeds a random per-encryption
// Nonce AND a wall-clock EncryptedAt timestamp, JSON-encoded into a []byte
// field the structural time.Time exclusion above cannot see. SecretMeta
// (models.go:525) was found live: FuzzStorageFaultOperations
// (op="REST POST /api/v1/auth/mfa/enroll", fault=LogAuditEvent#1/error)
// reported ORACLE (a) VIOLATION, "Differing tables: [MFASecret AuditEvent]" —
// but BeginMFAEnrollment's MFASecret write is not in the fault's path at all
// (it already committed before the faulted LogAuditEvent call); the MFASecret
// diff was entirely this gap, confirmed by toggling SecretMeta into this map
// and rerunning the exact same input, which then correctly resolves to
// ACCEPTABLE-BY-DESIGN with the diff reduced to [AuditEvent] alone (LogAuditEvent
// is best-effort everywhere it's called; see bestEffortTables below). The other
// two `*Meta []byte` fields sharing the identical EncryptionMetadata shape
// (AdminDSNMeta/CredentialMeta, dynamic_secrets.go's own encryptAuthSecret
// callers) have the same gap and are added alongside SecretMeta rather than
// left for the next fuzz burst to find one at a time.
var presenceOnlyFields = map[string]string{
	"PasswordHash":   "bcrypt includes a random salt per hash",
	"TokenHash":      "the raw token is randomly generated before hashing",
	"CodeHash":       "the raw MFA recovery code is randomly generated before hashing",
	"TokenPrefix":    "leading characters of the same randomly generated raw token TokenHash hashes (PAT and machine credentials, models.go) -- two independently bootstrapped worlds never mint the same token, so never the same prefix; found by FuzzStorageFaultOperations (REST DELETE machine token, GetUser#1 error) on PR #2195's CI",
	"SecretEnc":      "AEAD ciphertext includes a random nonce",
	"SecretMeta":     "EncryptionMetadata JSON blob embeds a random per-encryption Nonce plus a wall-clock EncryptedAt timestamp (internal/encryption/encryption.go) -- found by FuzzStorageFaultOperations (REST POST /api/v1/auth/mfa/enroll, LogAuditEvent#1/error), Session Z Z1",
	"AdminDSNEnc":    "AEAD ciphertext includes a random nonce",
	"AdminDSNMeta":   "same EncryptionMetadata shape as SecretMeta -- see that entry",
	"CredentialEnc":  "AEAD ciphertext includes a random nonce",
	"CredentialMeta": "same EncryptionMetadata shape as SecretMeta -- see that entry",
	"CredentialID":   "authenticator-generated WebAuthn credential identifier",
	"CredentialBlob": "authenticator-generated WebAuthn public key material",
	"SessionToken":   "SHA-256 hash of a randomly generated per-login session token (models.go:1217) — two independent bootstrap logins (reference world vs fault world) never produce the same raw token, so never the same hash",
	"FamilyID":       "randomly generated per-login refresh-token family identifier (models.go:1243) — same reasoning as SessionToken; found via this file's own Session-row debug dump when the structural timestamp fix alone didn't make two independently-bootstrapped worlds' Session tables match",
	// LastUsedStep (models.go:530, MFASecret): the TOTP time-step (unix/period)
	// of the most recently accepted code -- wall-clock derived (validateTOTPStep,
	// internal/core/mfa.go), not randomly generated, but the same class of
	// problem for a cross-pass comparison: two independent MFA-verify calls
	// separated by real elapsed time (e.g. TestWorldReuseSoundness's baseline
	// loop runs the WHOLE corpus once before the forward/reversed passes even
	// start) can legitimately straddle a 30-second step boundary and compute a
	// step number differing by exactly 1 -- not a state leak, just two
	// snapshots taken seconds apart of a value that changes every 30 seconds.
	// Found live: TestWorldReuseSoundness flagged "MFASecret.LastUsedStep
	// differs (N vs N-1)" on PR #2392's rebase (fuzz/mfa-reauth-ops, the first
	// PR to wire an op that calls validateTOTPStep into this corpus) -- did not
	// reproduce locally on a fast run, consistent with a timing-window flake
	// rather than a deterministic defect in the new MFA wiring. Presence-only
	// (nil vs non-nil) still correctly distinguishes "a code was accepted" from
	// "never verified" for every oracle that cares about that distinction; only
	// the exact step NUMBER is exempted.
	"LastUsedStep": "wall-clock TOTP time-step (unix/period) of the most recently accepted code -- changes every 30s, so two snapshots of the same logical state taken seconds apart can legitimately differ by 1 step",
}

// typeScopedPresenceOnlyFields is presenceOnlyFields' table-scoped sibling,
// for a field name that is randomized/non-deterministic on ONE model but
// carries real, must-stay-byte-compared business state on another — adding
// it to the global, name-only presenceOnlyFields map above would silently
// hide a genuine divergence on every OTHER model sharing that field name.
// Checked in canonicalRow BEFORE the global map, so a (type, field) match
// here takes precedence.
//
// LeaseID and RoleName were originally added to the GLOBAL presenceOnlyFields
// map (DynamicSecretLease.LeaseID/RoleName, models.go:1153/1156, both random
// per IssueLease/engine.Issue call — see models.go for the exact generators).
// LeaseID alone is a safe global entry (it's the only LeaseID field in the
// schema), but RoleName is NOT: BreakGlassActivation.RoleName (models.go:285,
// which role an emergency break-glass activation granted) and
// AccessReviewItem.RoleName (models.go:389, a role-name snapshot in an
// access-review campaign entry) are both DETERMINISTIC, security-relevant
// values that must keep failing the oracle if they ever diverge — the global
// entry silently reduced both to presence-only ("was anything written",
// not "is the value correct") repo-wide. Moved both fields here, scoped to
// DynamicSecretLease only, so the exemption can never leak onto an unrelated
// model again regardless of what future field happens to share a name.
// Red-proofed by TestCanonicalRow_BreakGlassAndAccessReviewRoleNameStillCompared
// (this file's own test): asserts a changed RoleName on each of those two
// OTHER models still produces a different canonicalRow() output -- i.e. the
// oracle can still see it.
var typeScopedPresenceOnlyFields = map[string]map[string]string{
	"LoginAttempt": {
		"ReservationKey": "generateSecureToken()-random reservation identifier minted by core.ReserveLoginAttempt per request (#2956 follow-up, models.go LoginAttempt.ReservationKey) — the reference and fault worlds never mint the same one, so without this every reserved LoginAttempt row differs byte-for-byte. Presence still compared: a reservation row versus a plain RecordLoginAttempt row (nil key) stays distinguishable.",
	},
	"DynamicSecretLease": {
		"LeaseID":  "generateSecureToken()-random opaque public identifier (internal/core/dynamic_secrets.go:535, models.go:1153) — two independent IssueLease calls never mint the same lease ID, so DynamicSecretLease rows never match byte-for-byte even when nothing else differs; missed by the original \"ends in Hash/Enc\" enumeration since this field holds the raw token itself, not a hash of it. Found live: FuzzStorageFaultOperations (GRPC keyorix.v1.DynamicSecretService.IssueLease, fault=LogAuditEvent#1/error), Session CR round 2.",
		"RoleName": "the generated role/username on the target DB (models.go:1156) — every engine.Issue (both the real backend engines, e.g. internal/dynamic/postgres.go's \"kx_dyn_\"+randString(16), and dynamictest.FakeEngine's \"kx_fake_\"+randString(8)) mints a fresh random suffix per call, so two independent issues never produce the same role name. Same root cause and found alongside LeaseID above. Table-scoped (not global) because BreakGlassActivation.RoleName and AccessReviewItem.RoleName are unrelated, deterministic fields that must stay byte-compared — see this map's own doc comment.",
	},
}

// tableSnapshot is one table's canonical dump: Hash over every row's
// (excluded-stripped, presence-redacted) JSON encoding, sorted so row order
// never affects the hash, plus the rows themselves for readable tracing when an
// oracle fails.
type tableSnapshot struct {
	Table string
	Hash  string
	Rows  []string // canonical per-row JSON, sorted
}

// dbSnapshot is the full logical-state snapshot: one tableSnapshot per model in
// models.AllTestModels(), plus a combined Hash over all of them so two snapshots
// can be compared with one string equality check before drilling into per-table
// detail.
type dbSnapshot struct {
	Hash   string
	Tables map[string]tableSnapshot
}

// snapshotDB dumps every table in models.AllTestModels() from db. It never
// touches models.AllTestModels() by name — using the same slice this repo's
// AutoMigrate calls use means a new model added there is picked up here
// automatically, with no separate list to keep in sync.
func snapshotDB(db *gorm.DB) (dbSnapshot, error) {
	snap := dbSnapshot{Tables: make(map[string]tableSnapshot)}
	var tableLines []string

	for _, m := range models.AllTestModels() {
		mt := reflect.TypeOf(m).Elem() // m is a *models.X zero value
		sliceType := reflect.SliceOf(reflect.PointerTo(mt))
		rowsPtr := reflect.New(sliceType)
		if err := db.Find(rowsPtr.Interface()).Error; err != nil {
			return dbSnapshot{}, fmt.Errorf("dumping %s: %w", mt.Name(), err)
		}
		rows := rowsPtr.Elem()

		var canon []string
		for i := 0; i < rows.Len(); i++ {
			line, err := canonicalRow(rows.Index(i).Interface())
			if err != nil {
				return dbSnapshot{}, fmt.Errorf("canonicalizing %s row %d: %w", mt.Name(), i, err)
			}
			canon = append(canon, line)
		}
		sort.Strings(canon)

		h := sha256.Sum256([]byte(strings.Join(canon, "\n")))
		ts := tableSnapshot{Table: mt.Name(), Hash: hex.EncodeToString(h[:]), Rows: canon}
		snap.Tables[mt.Name()] = ts
		tableLines = append(tableLines, ts.Table+":"+ts.Hash)
	}

	sort.Strings(tableLines)
	overall := sha256.Sum256([]byte(strings.Join(tableLines, "\n")))
	snap.Hash = hex.EncodeToString(overall[:])
	return snap, nil
}

// canonicalRow walks row's exported struct fields directly via reflection
// (NOT a json.Marshal round-trip, which silently drops any `json:"-"` field —
// several of this schema's sensitive fields carry that tag specifically to
// keep them out of API responses, which is irrelevant to what this snapshot
// needs to see) and produces a stable, sorted-key JSON-ish encoding: a
// time.Time/*time.Time field is dropped (structural timestamp exclusion,
// unless overridden in timeFieldOverrides), a field in excludedFields is
// dropped, a field in presenceOnlyFields becomes a boolean, everything else is
// marshaled as-is.
func canonicalRow(row interface{}) (string, error) {
	rv := reflect.ValueOf(row)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	rt := rv.Type()

	out := make(map[string]interface{}, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := f.Name
		fv := rv.Field(i)

		if (f.Type == timeType || f.Type == timePtrType) && !timeFieldOverrides[name] {
			continue
		}
		if _, excluded := excludedFields[name]; excluded {
			continue
		}
		if scoped, ok := typeScopedPresenceOnlyFields[rt.Name()]; ok {
			if _, presence := scoped[name]; presence {
				out[name] = !isGoZero(fv)
				continue
			}
		}
		if _, presence := presenceOnlyFields[name]; presence {
			out[name] = !isGoZero(fv)
			continue
		}
		out[name] = fv.Interface()
	}

	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(out[k])
		if err != nil {
			return "", fmt.Errorf("marshaling field %s.%s: %w", rt.Name(), k, err)
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// isGoZero reports whether v holds its type's zero value — used by
// presenceOnlyFields to reduce a randomized field to "was anything written at
// all" without depending on JSON's looser empty-string/empty-array notion,
// which a []byte ciphertext field doesn't naturally produce.
func isGoZero(v reflect.Value) bool {
	return v.IsZero()
}
