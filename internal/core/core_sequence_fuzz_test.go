package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// coreSeqResetTables is the explicit, hand-named table list fuzzworld.World.Reset
// clears between iterations that reuse the same per-worker world (see
// fuzzworld.World.Reset for why it is hand-named). Dependent-first order.
var coreSeqResetTables = []string{
	"role_permissions", "user_roles", "group_roles", "user_groups",
	"secret_versions", "secret_access_schedules", "share_records", "secret_acls", "secret_nodes",
	"environments", "projects",
	"sod_policies", "audit_events", "sessions",
	"users", "groups", "roles", "permissions",
}

// FuzzCoreOperationSequence is a stateful, model-based fuzzer for KeyorixCore: it
// drives a fuzzer-chosen SEQUENCE of create / grant / revoke / read / rotate
// operations, with the acting principal varied per step, against a real core over
// an in-memory store, and checks each step against a tiny shadow model that IS the
// oracle. This reaches the bug class a single-call harness cannot: an outcome that
// only breaks ACROSS operations — a revoke that doesn't take effect, a grant that
// leaks, a read allowed after the role behind it was removed, or a rotation that
// loses or corrupts the stored value.
//
// Two sound invariant families (each asserted only in the direction a
// trivially-correct model is certain of — never "grant ⇒ must succeed"):
//
//	FAIL-CLOSED (authz): if the model says principal P does NOT currently hold read,
//	GetSecretValueWithPermissionCheck(secret, P) MUST be denied — it must never
//	return plaintext. We assert the DENY direction only; an allow can carry extra
//	legitimate conditions.
//
//	PRESERVE-DATA (integrity): after a create or a rotate, the admin (who bypasses
//	permission checks) MUST read back exactly the value the model last wrote — the
//	plaintext round-trips through the real encrypt→store→decrypt path. And when an
//	authorized principal's read SUCCEEDS, the plaintext it returns must equal the
//	model value too (integrity conditional on success, so it can't false-positive).
//
// The three fuzzable principals are deliberately non-admin and own no secrets (the
// admin fixture creates, owns, and rotates every secret), so the only path to read
// is the reader role we grant/revoke — which makes the model's canRead an exact
// predicate, and makes the admin the trusted oracle for the current value.
//
// NOTE on scope: audit-completeness is deliberately NOT asserted here. In keyorix
// the secret.created / secret.rotated audit events are emitted by the HANDLER layer
// (HTTP/gRPC/CLI), which carries the authenticated actor/IP/UA — core.CreateSecret /
// core.RotateSecret do not self-audit by design. Asserting "each core mutation
// appends an audit event" would therefore FAIL on correct code. Audit-completeness
// belongs to a handler/service-level harness and is tracked separately.
func FuzzCoreOperationSequence(f *testing.F) {
	const (
		adminRoleID  = 900
		readerRoleID = 901
		readPermID   = 900
		adminUserID  = 1
	)
	// principal user IDs the fuzzer drives (none is admin; none owns a secret).
	principals := []uint{2, 3, 4}

	newWorld := func(t *testing.T, w *fuzzworld.World) (*KeyorixCore, *store.LocalStorage, uint, uint) {
		t.Helper()
		if err := w.Reset(coreSeqResetTables); err != nil {
			t.Fatalf("reset: %v", err)
		}
		db := w.DB
		ls := store.NewLocalStorage(db)
		ctx := context.Background()

		// --- fixed world: project + environment (store layer, no authz) ---
		proj, err := ls.CreateProject(ctx, &models.Project{Name: "projA"})
		if err != nil {
			t.Fatalf("create project: %v", err)
		}
		env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
		if err != nil {
			t.Fatalf("create env: %v", err)
		}

		// --- roles/permissions seeded directly (fast, deterministic) ---
		// admin bypasses all checks (ADR-084: the flag, not the name); reader carries
		// secrets.read and is what the fuzzer grants/revokes at project scope.
		mustCreate := func(v any) {
			if err := db.Create(v).Error; err != nil {
				t.Fatalf("seed %T: %v", v, err)
			}
		}
		mustCreate(&models.Role{ID: adminRoleID, Name: "fuzz-admin", NameFolded: "fuzz-admin", BypassesPermissionChecks: true})
		mustCreate(&models.Role{ID: readerRoleID, Name: "fuzz-reader", NameFolded: "fuzz-reader"})
		mustCreate(&models.Permission{ID: readPermID, Name: "secrets.read", Resource: "secrets", Action: "read"})
		mustCreate(&models.RolePermission{RoleID: readerRoleID, PermissionID: readPermID})

		mkUser := func(id uint) {
			mustCreate(&models.User{
				ID: id, Username: fmt.Sprintf("u%d", id), UsernameFolded: fmt.Sprintf("u%d", id),
				Email: fmt.Sprintf("u%d@x.io", id), EmailFolded: fmt.Sprintf("u%d@x.io", id), IsActive: true,
			})
		}
		mkUser(adminUserID)
		mustCreate(&models.UserRole{UserID: adminUserID, RoleID: adminRoleID}) // global admin
		for _, p := range principals {
			mkUser(p)
		}

		c := NewKeyorixCore(ls)
		return c, ls, proj.ID, env.ID
	}

	// admin creates one secret so there is always a target; returns its ID.
	createSecret := func(t *testing.T, c *KeyorixCore, projID, envID uint, name string, val []byte) (uint, bool) {
		t.Helper()
		s, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
			Name: name, Value: val, ProjectID: projID, EnvironmentID: envID,
			Type: "password", CreatedBy: "fuzz-admin", OwnerID: adminUserID,
		})
		if err != nil || s == nil {
			return 0, false
		}
		return s.ID, true
	}

	// Built ONCE per testing.F, before f.Fuzz (internal/testutil/fuzzworld): opening and
	// migrating a fresh DB per iteration was the dominant per-input cost.
	// SetMaxOpenConns(1): a plain ":memory:" DSN gives each pooled connection its own DB.
	// SQLite always; PostgreSQL too when KEYORIX_TEST_PG_DSN is set. Full production schema
	// (fuzzworld.Bootstrap, #1947), not an AutoMigrate-only subset.
	worlds := fuzzworld.Worlds(f, "coreseqfuzz", ":memory:", 1)

	// Every existing seed is prefixed with 0xFF (the full-set sentinel — see
	// decodeOpSubset), so each one still exercises every operation type exactly
	// as it did before swarm mode, byte-for-byte, from the second byte on.
	f.Add([]byte{0xFF, 0, 0, 1, 0, 3, 0, 2, 0, 3, 0})
	f.Add([]byte{0xFF, 0, 1, 3, 1, 1, 1, 3, 4, 2, 1, 3, 4})
	f.Add([]byte{0xFF, 0, 0, 4, 0, 9, 3, 0, 0, 1, 2, 3, 2}) // create, rotate, read
	f.Add([]byte{})
	// Swarm seeds: restrict the active op set to a rare-in-practice pair so
	// coverage-guided mutation starts exploring that pair immediately instead of
	// having to discover a narrow op-subset byte value on its own. Bit i (1<<i)
	// enables op i (0=create,1=grant,2=revoke,3=read,4=rotate).
	f.Add([]byte{0b10010, 1, 0, 0, 4, 1, 2, 1}) // grant(bit1) + rotate(bit4) only
	f.Add([]byte{0b01100, 2, 0, 0, 3, 1, 2, 1}) // revoke(bit2) + read(bit3) only

	f.Fuzz(func(t *testing.T, program []byte) {
		for _, w := range worlds {
			runCoreSeqIteration(t, w, program, newWorld, createSecret, principals, adminRoleID, readerRoleID, adminUserID)
		}
	})
}

// decodeOpSubset (swarm mode) reads the FIRST byte of a raw program as an
// enabled-operation bitmask: bit i (1<<i) enables step operation kind i (0
// create, 1 grant, 2 revoke, 3 read, 4 rotate). Restricting a program to a
// small subset makes coverage-guided mutation converge on a specific,
// possibly rarely-co-occurring PAIR (or singleton) of operation kinds much
// faster than sampling uniformly across all 5 every step — every step in a
// swarm program is guaranteed to be one of the chosen kinds, instead of a
// ~1/25 chance per adjacent pair under uniform selection. The sentinel 0xFF
// and the degenerate all-zero-bits case both mean "every operation enabled",
// so this is a strict superset of the pre-swarm behavior: any existing corpus
// entry whose first byte happens to decode to a non-degenerate subset still
// runs (just a narrower one), and 0xFF exactly reproduces the original
// full-set behavior for the rest of the bytes.
func decodeOpSubset(b byte) []int {
	if b == 0xFF {
		return []int{0, 1, 2, 3, 4}
	}
	var subset []int
	for i := range 5 {
		if b&(1<<uint(i)) != 0 {
			subset = append(subset, i)
		}
	}
	if len(subset) == 0 {
		return []int{0, 1, 2, 3, 4} // degenerate: no bit set -> fall back to full set
	}
	return subset
}

func runCoreSeqIteration(
	t *testing.T, w *fuzzworld.World, program []byte,
	newWorld func(*testing.T, *fuzzworld.World) (*KeyorixCore, *store.LocalStorage, uint, uint),
	createSecret func(*testing.T, *KeyorixCore, uint, uint, string, []byte) (uint, bool),
	principals []uint, adminRoleID, readerRoleID, adminUserID uint,
) {
	t.Helper()
	c, _, projID, envID := newWorld(t, w)
	ctx := context.Background()
	scope := Scope{ProjectID: projID}

	// Swarm mode: the first byte of the raw program picks the enabled-operation
	// subset for the rest of this iteration; everything after it is the
	// original 3-bytes-per-step encoding, now read from body rather than program.
	subsetByte := byte(0xFF)
	body := program
	if len(program) > 0 {
		subsetByte = program[0]
		body = program[1:]
	}
	subset := decodeOpSubset(subsetByte)

	// shadow model:
	//   canRead[userID] mirrors the REAL grant state (updated only on a nil-error
	//   grant/revoke); value[secretID] is the plaintext the model last wrote via a
	//   successful create/rotate (the admin is the trusted oracle for it).
	canRead := map[uint]bool{}
	value := map[uint][]byte{}
	var secretIDs []uint
	secretSeq, rotateSeq := 0, 0

	// assertAdminValue enforces PRESERVE-DATA: the admin bypasses permission checks
	// and our secrets are unclassified with no max-reads, so a successful create or
	// rotate MUST leave the value admin-readable and byte-identical to the model.
	assertAdminValue := func(sid uint, want []byte) {
		var got []byte
		var aerr error
		fuzzutil.Guard(t.Fatalf, "admin GetSecretValueWithPermissionCheck", func() {
			got, aerr = c.GetSecretValueWithPermissionCheck(ctx, sid, adminUserID)
		})
		if aerr != nil {
			t.Fatalf("DATA LOSS/AVAILABILITY: admin cannot read secret %d after a successful mutation: %v", sid, aerr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("DATA CORRUPTION: secret %d admin-read=%q want=%q", sid, got, want)
		}
	}

	// step's op is always a LITERAL kind (0-4), never subject to subset
	// remapping — dispatch (below) is what the fuzzed byte stream goes
	// through; step is also called directly, bypassing the subset entirely,
	// for the two fixed safety-net calls at the end of this function that
	// must always be a real create/read regardless of which subset this
	// iteration's swarm byte selected.
	step := func(op, a, b byte) {
		switch op {
		case 0: // admin creates a secret
			secretSeq++
			val := []byte{a, b}
			if id, ok := createSecret(t, c, projID, envID, fmt.Sprintf("s%d", secretSeq), val); ok {
				secretIDs = append(secretIDs, id)
				value[id] = val
				assertAdminValue(id, val) // round-trip integrity on create
			}
		case 1: // grant reader to a principal (system actor 0 bypasses the grant ceiling)
			u := principals[int(a)%len(principals)]
			if err := c.AssignUserRole(ctx, 0, u, readerRoleID, scope, false); err == nil {
				canRead[u] = true
			}
		case 2: // revoke reader from a principal
			u := principals[int(a)%len(principals)]
			if err := c.RemoveUserRole(ctx, 0, u, readerRoleID, scope); err == nil {
				canRead[u] = false
			}
		case 3: // a principal attempts a permission-checked VALUE read
			if len(secretIDs) == 0 {
				return
			}
			u := principals[int(a)%len(principals)]
			sid := secretIDs[int(b)%len(secretIDs)]
			var got []byte
			var rerr error
			fuzzutil.Guard(t.Fatalf, "GetSecretValueWithPermissionCheck", func() {
				got, rerr = c.GetSecretValueWithPermissionCheck(ctx, sid, u)
			})
			if !canRead[u] {
				// Fail-closed: no read-granting role, owns nothing → must be denied,
				// and must NOT leak plaintext.
				if rerr == nil {
					t.Fatalf("AUTHZ BYPASS: principal %d read secret %d plaintext with no read grant (canRead=false): %q", u, sid, got)
				}
			} else if rerr == nil {
				// Authorized AND succeeded → the plaintext must equal the model value
				// (integrity through the permission path; conditional on success so an
				// extra legitimate deny-condition can't false-positive).
				if !bytes.Equal(got, value[sid]) {
					t.Fatalf("INTEGRITY: principal %d read secret %d got=%q want=%q", u, sid, got, value[sid])
				}
			}
			if rerr != nil && got != nil {
				t.Fatalf("result-shape: denied read returned non-nil plaintext (id=%d principal=%d): %q", sid, u, got)
			}
		case 4: // admin rotates a secret to a fresh, distinct value
			if len(secretIDs) == 0 {
				return
			}
			sid := secretIDs[int(a)%len(secretIDs)]
			rotateSeq++
			// A 5-byte value keyed on rotateSeq is never equal to a 2-byte create
			// value nor to another rotation, so RotateSecret always performs a REAL
			// rotation (never the identical-value no-op path) — the model's value is
			// then the unambiguous post-rotation ground truth.
			newVal := []byte{0xAA, byte(rotateSeq >> 8), byte(rotateSeq), a, b}
			var rerr error
			fuzzutil.Guard(t.Fatalf, "RotateSecret", func() {
				_, rerr = c.RotateSecret(ctx, sid, newVal, adminUserID, "fuzz-admin")
			})
			if rerr == nil {
				value[sid] = newVal
				assertAdminValue(sid, newVal) // rotation preserved data, no loss/corruption
			}
		}
	}

	// dispatch maps a fuzzed op byte through the swarm subset before calling
	// step, so every fuzzed step is one of this iteration's enabled kinds.
	dispatch := func(op, a, b byte) {
		step(byte(subset[int(op)%len(subset)]), a, b)
	}

	// decode body: 3 bytes per step (op, a, b), bounded.
	const maxSteps = 32
	steps := 0
	for i := 0; i+2 < len(body) && steps < maxSteps; i += 3 {
		dispatch(body[i], body[i+1], body[i+2])
		steps++
	}
	// ensure at least one secret + one read exercised on short inputs
	if len(secretIDs) == 0 {
		if id, ok := createSecret(t, c, projID, envID, "s-seed", []byte("v")); ok {
			secretIDs = append(secretIDs, id)
			value[id] = []byte("v")
		}
	}
	if len(secretIDs) > 0 {
		step(3, 0, 0) // outsider read of secret 0 — must be denied (canRead false unless granted)
	}
}
