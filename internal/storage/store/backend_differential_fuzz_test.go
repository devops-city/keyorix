package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	storagefactory "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// scope + role IDs the differential drives. There is no FK from user_roles to a
// roles table at this layer, so we assign fixed role IDs directly (the target hunts
// engine divergence in the write/read path, not business validation). diffFixedOwnerID
// is likewise a fixed, possibly-nonexistent value stamped on every created secret
// node so CreateShareRecord's own ownership check (share.OwnerID must equal
// secret.OwnerID) has something non-zero to compare — models.ValidateShareRecord
// rejects OwnerID == 0 outright.
const (
	diffFixedProjectID = 1
	diffFixedEnvID     = 1
	diffFixedOwnerID   = 999
)

var diffRoleIDs = []uint{501, 502}

// diffAuditBaseTime anchors every audit event this harness appends to a fixed,
// non-wall-clock instant (offset by the step index) so the SAME event content —
// including EventTime, which the tamper-evidence hash chain covers — is hashed on
// both backends. Using time.Now() here would make every "identical" event actually
// differ by backend-call latency, producing a chain-head mismatch that is a test
// artifact, not a real divergence.
var diffAuditBaseTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// FuzzStorageBackendDifferential runs the SAME sequence of storage operations against
// a SQLite backend and a PostgreSQL backend in lockstep and asserts they AGREE after
// normalising away legitimate engine differences. The two backends are each other's
// oracle — no correct answer is hand-specified — so this catches the "passes on SQLite,
// breaks on Postgres" class: ordering without ORDER BY, NULL vs empty-string, unique/
// upsert semantics, case/collation, composite-key upsert, typed-error mapping.
//
// It is a differential harness, not an in-wall one: it needs a real Postgres, so it
// SKIPS unless $KEYORIX_TEST_PG_DSN is set (a rig with PG, or the demo container). CI
// and dev without PG skip cleanly.
//
// Soundness lives entirely in the normalisation: we compare only genuine contracts —
// error CLASS agreement (both nil / both error), value equality by NATURAL KEY (ids
// and timestamps zeroed), and list/table results as SETS. A differing row ORDER is NOT
// a hard failure here (order without ORDER BY is engine-defined); we stick to
// set/value agreement to stay false-positive-free.
//
// Phase 2 grows the command set from projects/users to also cover the two tables that
// carry a secrets product's crown jewels and its authorization state: secret_nodes
// (CreateSecret / GetSecretByName) and user_roles (AssignRole, whose composite primary
// key exercises each engine's upsert/duplicate-grant path inside a transaction).
//
// Schema provenance (2026-09-25 hardening — see the 2026-09-20 divergence triage,
// docs/security-closures.tsv): earlier versions of this harness brought each backend up
// via a bare db.AutoMigrate() per model. That created the tables but NONE of production's
// partial unique indexes (uniq_users_username_folded_active,
// uniq_users_email_folded_active, uniq_projects_name_active,
// uniq_secret_nodes_project_env_name_active, ...) — those are created by
// migrateDatabase's own ensure*Index helpers (internal/storage/factory.go), not by any
// gorm struct tag, specifically so a case/collation divergence between backends couldn't
// hide behind a plain uniqueIndex tag (see models.User's own doc comment). A harness
// schema missing every one of those indexes cannot see the constraint-level divergences
// it exists to find — the same "test world doesn't match the real one" gap #1991's fault
// world hit. Both backends are now migrated through the REAL production entry point,
// storagefactory.NewStorageFactory().CreateStorage(cfg), exactly as server startup does —
// not a re-implementation of it. TestBackendDifferentialHarnessSchema_MatchesProduction
// (backend_differential_schema_guard_test.go) pins this so it can't silently drift back.
func FuzzStorageBackendDifferential(f *testing.F) {
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		f.Skip("KEYORIX_TEST_PG_DSN not set — differential fuzzing needs a real Postgres (rig-only)")
	}

	// --- SQLite backend (shared-cache in-memory so the single logical DB persists) ---
	// The factory migrates it and sdb below must reach the SAME database, so only
	// the DSN comes from sqlitetest; sdb caps its own pool to one connection.
	sqliteDSN := sqlitetest.DSN("difffuzz_")
	if _, err := storagefactory.NewStorageFactory().CreateStorage(&config.Config{
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqliteDSN}},
	}); err != nil {
		f.Fatalf("sqlite production migration: %v", err)
	}
	sdb, err := gorm.Open(sqlite.Open(sqliteDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if s, e := sdb.DB(); e == nil {
		s.SetMaxOpenConns(1)
	}

	// --- Postgres backend, isolated in a fresh schema for this process ---
	schema := fmt.Sprintf("difffuzz_%d_%d", os.Getpid(), pgSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open pg admin: %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		f.Fatalf("pg drop schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		f.Fatalf("pg create schema: %v", err)
	}
	f.Cleanup(func() {
		if c, e := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard}); e == nil {
			_ = c.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		}
	})
	pgTargetDSN := pgdsn.PGSearchPathDSN(pgDSN, schema)
	if _, err := storagefactory.NewStorageFactory().CreateStorage(&config.Config{
		Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: pgTargetDSN}},
	}); err != nil {
		f.Fatalf("pg production migration: %v", err)
	}
	pdb, err := gorm.Open(postgres.Open(pgTargetDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open pg: %v", err)
	}
	// Pinned to 1, matching sdb above. This harness applies every op to both backends
	// SEQUENTIALLY on one goroutine — there is no concurrency here for an unbounded pool
	// to legitimately exercise, only room for connection-pool-visibility noise (a stale
	// read from a different pooled connection) to masquerade as a false "backend
	// divergence." Genuine concurrency divergence (advisory locks, FOR UPDATE, contended
	// upsert) already has its own dedicated coverage: the concurrency_*_postgres_test.go
	// suite in this package, which deliberately uses MULTIPLE independent connections
	// because that is what it exists to exercise. Not this harness's job.
	if p, e := pdb.DB(); e == nil {
		p.SetMaxOpenConns(1)
	}

	sls, pls := store.NewLocalStorage(sdb), store.NewLocalStorage(pdb)

	// wipe resets both backends to an identical empty state (child tables first).
	// There is no FK enforcement anywhere in this schema (no Go-level association
	// fields, only bare *ID columns — see the diffRoleIDs comment above), so this
	// order is for clarity, not correctness: no DELETE here can ever fail on a
	// foreign-key violation.
	wipe := func(db *gorm.DB) {
		for _, tbl := range []string{
			"audit_events", "share_records", "secret_acls", "secret_versions", "secret_nodes",
			"sessions", "machine_identity_credentials", "machine_identities",
			"user_groups", "group_roles", "groups",
			"user_roles", "environments", "users", "projects",
		} {
			_ = db.Exec("DELETE FROM " + tbl).Error
		}
	}

	// errClass collapses an error to the only thing both engines must agree on.
	errClass := func(e error) bool { return e == nil }

	f.Add([]byte{0, 1, 0, 1, 2, 1, 0, 1})
	f.Add([]byte{3, 3, 4, 3, 1, 3, 5, 3, 3, 4}) // create-secret, get-secret, create-user, assign-role

	f.Fuzz(func(t *testing.T, program []byte) {
		wipe(sdb)
		wipe(pdb)
		ctx := context.Background()

		// small alphabets so keys collide → unique/dup/case paths are actually hit.
		names := []string{"alpha", "Alpha", "", "beta", "beta "}

		// lastSQLiteErr/lastPGErr/lastCall record the actual error each backend returned
		// from the most recent op, purely for the divergence Fatalf below — the
		// error-CLASS comparison itself doesn't need them. Added after the 2026-09-20
		// non-reproducing divergence (op=1 operand=48) had to be triaged from a bare
		// true/false log line with no error text at all; a recurrence now reports the
		// real driver error instead of requiring this same archaeology again.
		var lastSQLiteErr, lastPGErr error
		var lastCall string
		steps := 0                               // current step index — declared before apply so it can be captured for deterministic audit-event timestamps
		apply := func(op, a byte) (bool, bool) { // returns (sqliteOK, pgOK)
			name := names[int(a)%len(names)]
			switch op % 16 {
			case 0: // CreateProject
				_, se := sls.CreateProject(ctx, &models.Project{Name: name})
				_, pe := pls.CreateProject(ctx, &models.Project{Name: name})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateProject(%q)", name)
				return errClass(se), errClass(pe)
			case 1: // CreateUser
				su := &models.User{Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io", IsActive: true}
				pu := &models.User{Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io", IsActive: true}
				_, se := sls.CreateUser(ctx, su)
				_, pe := pls.CreateUser(ctx, pu)
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateUser(%q)", name)
				return errClass(se), errClass(pe)
			case 2: // GetProjectByName
				sp, se := sls.GetProjectByName(ctx, name)
				pp, pe := pls.GetProjectByName(ctx, name)
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("GetProjectByName(%q)", name)
				if errClass(se) != errClass(pe) {
					return errClass(se), errClass(pe)
				}
				if se == nil && pe == nil && sp != nil && pp != nil && sp.Name != pp.Name {
					t.Fatalf("BACKEND DIVERGENCE: GetProjectByName(%q) name mismatch sqlite=%q pg=%q", name, sp.Name, pp.Name)
				}
				return errClass(se), errClass(pe)
			case 3: // CreateSecret (storage-layer node insert, fixed scope, fixed owner)
				sn := &models.SecretNode{Name: name, ProjectID: diffFixedProjectID, EnvironmentID: diffFixedEnvID, OwnerID: diffFixedOwnerID}
				pn := &models.SecretNode{Name: name, ProjectID: diffFixedProjectID, EnvironmentID: diffFixedEnvID, OwnerID: diffFixedOwnerID}
				_, se := sls.CreateSecret(ctx, sn)
				_, pe := pls.CreateSecret(ctx, pn)
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateSecret(%q)", name)
				return errClass(se), errClass(pe)
			case 4: // GetSecretByName (same scope)
				ss, se := sls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				ps, pe := pls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("GetSecretByName(%q)", name)
				if errClass(se) != errClass(pe) {
					return errClass(se), errClass(pe)
				}
				if se == nil && pe == nil && ss != nil && ps != nil && ss.Name != ps.Name {
					t.Fatalf("BACKEND DIVERGENCE: GetSecretByName(%q) name mismatch sqlite=%q pg=%q", name, ss.Name, ps.Name)
				}
				return errClass(se), errClass(pe)
			case 5: // AssignRole — composite-PK grant, exercises each engine's upsert path
				su, serr := sls.GetUserByUsername(ctx, name)
				pu, perr := pls.GetUserByUsername(ctx, name)
				if serr != nil || perr != nil {
					lastSQLiteErr, lastPGErr, lastCall = serr, perr, fmt.Sprintf("AssignRole: GetUserByUsername(%q)", name)
					// user absent in one/both → nothing to grant; agree on resolvability.
					return errClass(serr), errClass(perr)
				}
				roleID := diffRoleIDs[int(a)%len(diffRoleIDs)]
				se := sls.AssignRole(ctx, su.ID, roleID, storage.Scope{})
				pe := pls.AssignRole(ctx, pu.ID, roleID, storage.Scope{})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("AssignRole(%q, role=%d)", name, roleID)
				return errClass(se), errClass(pe)
			case 6: // RemoveRole — revoke, exercises the composite-PK delete path
				su, serr := sls.GetUserByUsername(ctx, name)
				pu, perr := pls.GetUserByUsername(ctx, name)
				if serr != nil || perr != nil {
					lastSQLiteErr, lastPGErr, lastCall = serr, perr, fmt.Sprintf("RemoveRole: GetUserByUsername(%q)", name)
					return errClass(serr), errClass(perr)
				}
				roleID := diffRoleIDs[int(a)%len(diffRoleIDs)]
				se := sls.RemoveRole(ctx, su.ID, roleID, storage.Scope{})
				pe := pls.RemoveRole(ctx, pu.ID, roleID, storage.Scope{})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("RemoveRole(%q, role=%d)", name, roleID)
				return errClass(se), errClass(pe)
			case 7: // CreateSession — token is deterministic in name, so a repeat collides
				su, serr := sls.GetUserByUsername(ctx, name)
				pu, perr := pls.GetUserByUsername(ctx, name)
				if serr != nil || perr != nil {
					lastSQLiteErr, lastPGErr, lastCall = serr, perr, fmt.Sprintf("CreateSession: GetUserByUsername(%q)", name)
					return errClass(serr), errClass(perr)
				}
				token := "tok-" + name
				_, se := sls.CreateSession(ctx, &models.Session{UserID: su.ID, SessionToken: token})
				_, pe := pls.CreateSession(ctx, &models.Session{UserID: pu.ID, SessionToken: token})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateSession(%q)", name)
				return errClass(se), errClass(pe)
			case 8: // RevokeUserSessions — deletes every session for the resolved user
				su, serr := sls.GetUserByUsername(ctx, name)
				pu, perr := pls.GetUserByUsername(ctx, name)
				if serr != nil || perr != nil {
					lastSQLiteErr, lastPGErr, lastCall = serr, perr, fmt.Sprintf("RevokeUserSessions: GetUserByUsername(%q)", name)
					return errClass(serr), errClass(perr)
				}
				se := sls.DeleteSessionsForUserExcept(ctx, su.ID, 0)
				pe := pls.DeleteSessionsForUserExcept(ctx, pu.ID, 0)
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("RevokeUserSessions(%q)", name)
				return errClass(se), errClass(pe)
			case 9: // CreateGroup — exercises Group's own partial folded-name unique index
				sg := &models.Group{Name: name, NameFolded: name}
				pg := &models.Group{Name: name, NameFolded: name}
				_, se := sls.CreateGroup(ctx, sg)
				_, pe := pls.CreateGroup(ctx, pg)
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateGroup(%q)", name)
				return errClass(se), errClass(pe)
			case 10: // AddUserToGroup — resolves both by name independently per backend
				su, serr := sls.GetUserByUsername(ctx, name)
				pu, perr := pls.GetUserByUsername(ctx, name)
				if serr != nil || perr != nil {
					lastSQLiteErr, lastPGErr, lastCall = serr, perr, fmt.Sprintf("AddUserToGroup: GetUserByUsername(%q)", name)
					return errClass(serr), errClass(perr)
				}
				sgID, sgErr := diffGroupIDByName(sdb, name)
				pgID, pgErr := diffGroupIDByName(pdb, name)
				if (sgErr == nil) != (pgErr == nil) {
					lastSQLiteErr, lastPGErr, lastCall = sgErr, pgErr, fmt.Sprintf("AddUserToGroup: resolve group(%q)", name)
					return sgErr == nil, pgErr == nil
				}
				if sgErr != nil || pgErr != nil {
					// group absent on both — nothing to join; agree on resolvability.
					return true, true
				}
				se := sls.AddUserToGroup(ctx, su.ID, sgID, diffFixedProjectID)
				pe := pls.AddUserToGroup(ctx, pu.ID, pgID, diffFixedProjectID)
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("AddUserToGroup(%q)", name)
				return errClass(se), errClass(pe)
			case 11: // AssignRoleToGroup
				sgID, sgErr := diffGroupIDByName(sdb, name)
				pgID, pgErr := diffGroupIDByName(pdb, name)
				if (sgErr == nil) != (pgErr == nil) {
					lastSQLiteErr, lastPGErr, lastCall = sgErr, pgErr, fmt.Sprintf("AssignRoleToGroup: resolve group(%q)", name)
					return sgErr == nil, pgErr == nil
				}
				if sgErr != nil || pgErr != nil {
					return true, true
				}
				roleID := diffRoleIDs[int(a)%len(diffRoleIDs)]
				se := sls.AssignRoleToGroup(ctx, sgID, roleID, storage.Scope{})
				pe := pls.AssignRoleToGroup(ctx, pgID, roleID, storage.Scope{})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("AssignRoleToGroup(%q, role=%d)", name, roleID)
				return errClass(se), errClass(pe)
			case 12: // CreateSecretVersion — version number sometimes collides (operand-derived)
				ss, sErr := sls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				ps, pErr := pls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				if (sErr == nil) != (pErr == nil) {
					lastSQLiteErr, lastPGErr, lastCall = sErr, pErr, fmt.Sprintf("CreateSecretVersion: GetSecretByName(%q)", name)
					return sErr == nil, pErr == nil
				}
				if sErr != nil || pErr != nil {
					return true, true
				}
				versionNumber := int(a)%3 + 1
				_, se := sls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: ss.ID, VersionNumber: versionNumber})
				_, pe := pls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: ps.ID, VersionNumber: versionNumber})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateSecretVersion(%q, v=%d)", name, versionNumber)
				return errClass(se), errClass(pe)
			case 13: // toggle DeleteSecret/RestoreSecret depending on each backend's own current state
				sID, sDeleted, sErr := diffSecretIDAndState(sdb, name)
				pID, pDeleted, pErr := diffSecretIDAndState(pdb, name)
				if (sErr == nil) != (pErr == nil) {
					lastSQLiteErr, lastPGErr, lastCall = sErr, pErr, fmt.Sprintf("DeleteOrRestoreSecret: resolve(%q)", name)
					return sErr == nil, pErr == nil
				}
				if sErr != nil || pErr != nil {
					return true, true
				}
				var se, pe error
				if sDeleted {
					se = sls.RestoreSecret(ctx, sID)
				} else {
					se = sls.DeleteSecret(ctx, sID)
				}
				if pDeleted {
					pe = pls.RestoreSecret(ctx, pID)
				} else {
					pe = pls.DeleteSecret(ctx, pID)
				}
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("DeleteOrRestoreSecret(%q, sqliteWasDeleted=%v, pgWasDeleted=%v)", name, sDeleted, pDeleted)
				return errClass(se), errClass(pe)
			case 14: // CreateMachineIdentity + a credential for it (TokenHash deterministic in name)
				smID, smErr := diffMachineIdentityIDByName(ctx, sls, sdb, name)
				pmID, pmErr := diffMachineIdentityIDByName(ctx, pls, pdb, name)
				if (smErr == nil) != (pmErr == nil) {
					lastSQLiteErr, lastPGErr, lastCall = smErr, pmErr, fmt.Sprintf("CreateMachineIdentity(%q)", name)
					return smErr == nil, pmErr == nil
				}
				if smErr != nil || pmErr != nil {
					lastSQLiteErr, lastPGErr, lastCall = smErr, pmErr, fmt.Sprintf("CreateMachineIdentity(%q)", name)
					return errClass(smErr), errClass(pmErr)
				}
				hash := "cred-" + name
				_, se := sls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{MachineIdentityID: smID, TokenHash: hash})
				_, pe := pls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{MachineIdentityID: pmID, TokenHash: hash})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateMachineIdentityCredential(%q)", name)
				return errClass(se), errClass(pe)
			default: // CreateShareRecord — individual share, expiry decided by operand parity
				ss, sErr := sls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				ps, pErr := pls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				if (sErr == nil) != (pErr == nil) {
					lastSQLiteErr, lastPGErr, lastCall = sErr, pErr, fmt.Sprintf("CreateShareRecord: GetSecretByName(%q)", name)
					return sErr == nil, pErr == nil
				}
				if sErr != nil || pErr != nil {
					return true, true
				}
				// share with whichever user "beta" resolves to on each backend (a fixed,
				// separate name from the shared secret's own name, so self-sharing isn't
				// the only path exercised) — absent on one/both is a valid, agreeing outcome.
				su, serr := sls.GetUserByUsername(ctx, "beta")
				pu, perr := pls.GetUserByUsername(ctx, "beta")
				if (serr == nil) != (perr == nil) {
					lastSQLiteErr, lastPGErr, lastCall = serr, perr, "CreateShareRecord: GetUserByUsername(beta)"
					return serr == nil, perr == nil
				}
				if serr != nil || perr != nil {
					return true, true
				}
				var expiresAt *time.Time
				if a%2 == 0 {
					t := diffAuditBaseTime.Add(time.Duration(steps) * time.Hour)
					expiresAt = &t
				}
				_, se := sls.CreateShareRecord(ctx, &models.ShareRecord{SecretID: ss.ID, OwnerID: diffFixedOwnerID, RecipientID: su.ID, ExpiresAt: expiresAt})
				_, pe := pls.CreateShareRecord(ctx, &models.ShareRecord{SecretID: ps.ID, OwnerID: diffFixedOwnerID, RecipientID: pu.ID, ExpiresAt: expiresAt})
				lastSQLiteErr, lastPGErr, lastCall = se, pe, fmt.Sprintf("CreateShareRecord(%q)", name)
				return errClass(se), errClass(pe)
			}
		}

		const maxSteps = 24
		for i := 0; i+1 < len(program) && steps < maxSteps; i += 2 {
			sOK, pOK := apply(program[i], program[i+1])
			if sOK != pOK {
				t.Fatalf("BACKEND DIVERGENCE: op=%d operand=%d error-class disagreement sqliteOK=%v pgOK=%v step=%d call=%s sqliteErr=%v pgErr=%v",
					program[i]%16, program[i+1], sOK, pOK, steps, lastCall, lastSQLiteErr, lastPGErr)
			}

			// Audit append + chain head: runs unconditionally every step (not gated
			// behind its own op slot) so the chain grows in lockstep on both backends by
			// construction, regardless of which op ran — maximizing how many chances the
			// hash-chain-linking mechanism itself gets to diverge, not just how often it's
			// picked by the fuzzer. EventTime is anchored to diffAuditBaseTime + step, not
			// wall-clock (time.Now() here would make the SAME logical event hash
			// differently between the two sequential backend calls, since
			// LogAuditEvent's hash covers EventTime — that would be a test artifact, not
			// a real divergence).
			eventTime := diffAuditBaseTime.Add(time.Duration(steps) * time.Second)
			se := sls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "diff.fuzz.step", EventTime: eventTime, Description: lastCall})
			pe := pls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "diff.fuzz.step", EventTime: eventTime, Description: lastCall})
			if errClass(se) != errClass(pe) {
				t.Fatalf("BACKEND DIVERGENCE: LogAuditEvent step=%d sqliteErr=%v pgErr=%v", steps, se, pe)
			}
			steps++
		}

		// Final state: each table's natural-key SET must be identical across backends.
		assertSetEqual(t, "projects", projectNameSet(mustListProjects(t, sls, ctx)), projectNameSet(mustListProjects(t, pls, ctx)))
		assertSetEqual(t, "secret_nodes", secretNameSet(sdb), secretNameSet(pdb))
		assertSetEqual(t, "user_roles", userRoleKeySet(sdb), userRoleKeySet(pdb))
		assertSetEqual(t, "groups", groupNameSet(sdb), groupNameSet(pdb))
		assertSetEqual(t, "sessions", sessionTokenSet(sdb), sessionTokenSet(pdb))
		assertSetEqual(t, "machine_identity_credentials", machineCredentialHashSet(sdb), machineCredentialHashSet(pdb))
		assertSetEqual(t, "share_records", shareRecordKeySet(sdb), shareRecordKeySet(pdb))

		// The audit chain itself: same event content appended in the same order on
		// both backends (enforced above) must produce the same tamper-evidence chain
		// head — a divergence here means the hash-chain-linking mechanism itself
		// (not just table content) disagrees between engines.
		sHead, sHeadErr := auditChainHead(sdb)
		pHead, pHeadErr := auditChainHead(pdb)
		if errClass(sHeadErr) != errClass(pHeadErr) {
			t.Fatalf("BACKEND DIVERGENCE: audit chain head lookup sqliteErr=%v pgErr=%v", sHeadErr, pHeadErr)
		}
		if sHeadErr == nil && pHeadErr == nil && sHead != pHead {
			t.Fatalf("BACKEND DIVERGENCE: audit chain head sqlite=%q pg=%q", sHead, pHead)
		}
	})
}

var pgSchemaSeq atomic.Int64

func mustListProjects(t *testing.T, ls *store.LocalStorage, ctx context.Context) []*models.Project {
	t.Helper()
	ps, err := ls.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	return ps
}

// assertSetEqual fails with a diff if the two sorted natural-key sets differ.
func assertSetEqual(t *testing.T, table string, s, p []string) {
	t.Helper()
	if len(s) != len(p) {
		t.Fatalf("BACKEND DIVERGENCE: %s set size sqlite=%v pg=%v", table, s, p)
	}
	for i := range s {
		if s[i] != p[i] {
			t.Fatalf("BACKEND DIVERGENCE: %s set sqlite=%v pg=%v", table, s, p)
		}
	}
}

// projectNameSet normalises a project list to a sorted set of names (ids/timestamps
// are engine-assigned and deliberately ignored).
func projectNameSet(ps []*models.Project) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

// secretNameSet is the sorted set of secret-node names in one backend (scope is fixed,
// ids/timestamps ignored).
func secretNameSet(db *gorm.DB) []string {
	var nodes []models.SecretNode
	db.Find(&nodes)
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return out
}

// userRoleKeySet is the sorted set of grants keyed by natural identifiers
// (username|roleID|projectID|environmentID) — user ids are engine-assigned, so a grant
// is compared by the username it points at, resolved via each backend's own id map.
func userRoleKeySet(db *gorm.DB) []string {
	var users []models.User
	db.Find(&users)
	nameByID := make(map[uint]string, len(users))
	for _, u := range users {
		nameByID[u.ID] = u.Username
	}
	var urs []models.UserRole
	db.Find(&urs)
	out := make([]string, 0, len(urs))
	for _, ur := range urs {
		out = append(out, fmt.Sprintf("%s|%d|%d|%d", nameByID[ur.UserID], ur.RoleID, ur.ProjectID, ur.EnvironmentID))
	}
	sort.Strings(out)
	return out
}

// diffGroupIDByName resolves a group's own backend-assigned ID by its Name column
// directly — there is no GetGroupByName on LocalStorage (only GetGroup(ctx, id)), so
// this is test-only resolution, mirroring how the rest of this harness resolves users
// by username before an op that needs their id.
func diffGroupIDByName(db *gorm.DB, name string) (uint, error) {
	var g models.Group
	if err := db.Where("name = ?", name).First(&g).Error; err != nil {
		return 0, err
	}
	return g.ID, nil
}

// diffMachineIdentityIDByName resolves-or-creates a machine identity named name in the
// fixed project scope and returns its id. Like diffGroupIDByName, there is no
// GetMachineIdentityByName — this file's own convention throughout is to resolve
// name-keyed test fixtures via a direct query, then drive the real LocalStorage method
// for the actual write under test.
func diffMachineIdentityIDByName(ctx context.Context, ls *store.LocalStorage, db *gorm.DB, name string) (uint, error) {
	var m models.MachineIdentity
	err := db.Where("project_id = ? AND name = ?", diffFixedProjectID, name).First(&m).Error
	if err == nil {
		return m.ID, nil
	}
	created, cerr := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: diffFixedProjectID, Name: name})
	if cerr != nil {
		return 0, cerr
	}
	return created.ID, nil
}

// diffSecretIDAndState resolves the secret named name in the fixed scope, INCLUDING a
// currently-soft-deleted row (Unscoped — LocalStorage.GetSecretByName excludes deleted
// rows by GORM's default soft-delete scoping, which is exactly what the toggle op needs
// to see through to decide delete vs. restore).
func diffSecretIDAndState(db *gorm.DB, name string) (id uint, deleted bool, err error) {
	var s models.SecretNode
	if err := db.Unscoped().Where("project_id = ? AND environment_id = ? AND name = ?", diffFixedProjectID, diffFixedEnvID, name).First(&s).Error; err != nil {
		return 0, false, err
	}
	return s.ID, s.DeletedAt.Valid, nil
}

// groupNameSet is the sorted set of live (non-soft-deleted) group names.
func groupNameSet(db *gorm.DB) []string {
	var groups []models.Group
	db.Find(&groups)
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.Name)
	}
	sort.Strings(out)
	return out
}

// sessionTokenSet is the sorted set of session tokens — the natural key CreateSession's
// own unique constraint is scoped to, so this is what a genuine collision-handling
// divergence would show up as (one backend keeping a duplicate the other rejected).
func sessionTokenSet(db *gorm.DB) []string {
	var sessions []models.Session
	db.Find(&sessions)
	out := make([]string, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s.SessionToken)
	}
	sort.Strings(out)
	return out
}

// machineCredentialHashSet is the sorted set of credential token hashes — the natural
// key CreateMachineIdentityCredential's own unique constraint is scoped to.
func machineCredentialHashSet(db *gorm.DB) []string {
	var creds []models.MachineIdentityCredential
	db.Find(&creds)
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.TokenHash)
	}
	sort.Strings(out)
	return out
}

// shareRecordKeySet is the sorted set of live shares keyed by natural identifiers
// (secretName|recipientUsername|isGroup|hasExpiry) — ids are engine-assigned, so both
// the secret and the recipient are resolved to their own name/username via each
// backend's own id maps, exactly mirroring userRoleKeySet's approach.
func shareRecordKeySet(db *gorm.DB) []string {
	var secrets []models.SecretNode
	db.Unscoped().Find(&secrets)
	secretNameByID := make(map[uint]string, len(secrets))
	for _, s := range secrets {
		secretNameByID[s.ID] = s.Name
	}
	var users []models.User
	db.Find(&users)
	userNameByID := make(map[uint]string, len(users))
	for _, u := range users {
		userNameByID[u.ID] = u.Username
	}
	var shares []models.ShareRecord
	db.Find(&shares)
	out := make([]string, 0, len(shares))
	for _, sh := range shares {
		out = append(out, fmt.Sprintf("%s|%s|%v|%v", secretNameByID[sh.SecretID], userNameByID[sh.RecipientID], sh.IsGroup, sh.ExpiresAt != nil))
	}
	sort.Strings(out)
	return out
}

// auditChainHead returns the entry_hash of the most recently appended audit event —
// the tamper-evidence chain's current head (ADR-029). Empty string, no error when the
// chain is empty (both backends start empty after wipe(), so this is a valid state to
// compare, not a lookup failure).
func auditChainHead(db *gorm.DB) (string, error) {
	var event models.AuditEvent
	err := db.Order("id DESC").First(&event).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return event.EntryHash, nil
}
