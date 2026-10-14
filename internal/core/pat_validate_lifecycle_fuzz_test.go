// pat_validate_lifecycle_fuzz_test.go — FuzzPATValidateLifecycle.
//
// The PAT unit tests (pat_test.go) mock storage and exercise ValidatePATToken's
// error branches one at a time. FuzzDecodePATScopes/FuzzDecodePATCIDRs cover the
// pure column decoders, and FuzzPATRestrictionAllows covers the pure authorization
// algebra. None of the four drives the real create -> validate -> restrict ->
// revoke/expire path against a real store: FuzzCoreOperationSequence has the right
// shape (real in-memory SQLite, real KeyorixCore) but never touches
// PersonalAccessToken at all.
//
// This harness builds a fixed fixture of real, issued PATs (via the real
// CreateOwnPAT / RevokeOwnPAT) against a real in-memory SQLite store, then fuzzes
// mutations of one chosen issued token and checks ValidatePATToken's result
// against an independent shadow model built from the fixture's own creation
// parameters — never by re-deriving through the code under test.
//
// Sound invariants (each asserted only in the direction a trivially-correct model
// is certain of):
//
//	(a) FAIL-CLOSED IDENTITY: ValidatePATToken succeeds ONLY for a byte-exact
//	    issued, unexpired, unrevoked token, and then yields exactly that token's
//	    owner and row id. Any other input (no byte-exact match among the issued
//	    tokens) must return an error and a nil user.
//	(b) REVOKED/EXPIRED NEVER AUTHENTICATE: a byte-exact match to a revoked token
//	    must return ErrPATRevoked; a byte-exact match to an expired-but-not-revoked
//	    token must return ErrPATExpired. Neither ever returns a user.
//	(c) RESTRICTION BINDING: on success, the returned restriction equals the one
//	    the fixture itself computed from that token's own creation parameters —
//	    never another token's scopes/CIDRs/project/environment.
//	(d) BOUNDED WORK: fuzzutil.Guard fails the input if ValidatePATToken hangs
//	    beyond the shared guard timeout, for arbitrary-length mutated input.
//
// The token format (patPrefix + 32 random bytes, base64 RawURLEncoding) carries no
// embedded user id — unlike a structured credential, there is no "this user's
// secret with another user's id" to splice at the field level. The harness
// substitutes two equivalent cross-identity probes: splicing raw bytes between two
// different users' real tokens (mutation op 7), and presenting one user's
// byte-exact token while the oracle checks it resolves to exactly that user, never
// the other (folded into oracle (a)/(c), since the fixture always knows the true
// owner of the byte-exact match).
//
// Red-proofed (scratch-edit ValidatePATToken/patRestrictionFrom/CreateOwnPAT to
// plant each defect, confirm the corresponding oracle fires, then revert -- none
// of these edits are present in this file; this is a record of what was checked):
//   - revoked check disabled                                -> (a)/(b) REVOKED TOKEN ACCEPTED
//   - expiry check disabled                                 -> (a)/(b) EXPIRED TOKEN ACCEPTED
//   - patRestrictionFrom drops ProjectID                     -> (c) RESTRICTION BLEED
//   - hash computed over only a 40-char prefix of raw        -> (a) AUTH BYPASS (extended/truncated
//     (both at creation and lookup, so full tokens still       tokens sharing that prefix validate)
//     round-trip)
//   - GetUser looked up by a different stored user's id      -> (a) WRONG IDENTITY
//     than the one the matched row actually carries
//   - hash computed over strings.ToLower(raw)                -> (a) AUTH BYPASS (case-folded
//     (both at creation and lookup)                            variants of a real token validate)
//   - O(n^3) loop over raw inserted before any length check  -> (d) Guard: "exceeded 3s"
package core

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// patLifecycleFixtureEntry is the independent ground truth for one issued PAT,
// built entirely from the parameters the fixture itself passed to CreateOwnPAT /
// RevokeOwnPAT — never by calling patRestrictionFrom or any other code under test.
type patLifecycleFixtureEntry struct {
	plain       string
	ownerID     uint
	patID       uint
	revoked     bool
	expired     bool
	restriction *PATRestriction // nil means "expect ValidatePATToken to return nil"
}

// buildPATLifecycleFixture creates a real KeyorixCore over a fresh in-memory
// SQLite store, with a pinned clock, two active users (one holding a real role
// assignment), and a fixed set of real PATs spanning: unrestricted,
// scope+project restricted, CIDR+environment restricted, a combined-restriction
// token, an expired token, a revoked token, and a token issued from dirty
// (blank/duplicate/bare-IP) scope and CIDR input. Mirrors
// FuzzCoreOperationSequence's real-store fixture pattern
// (core_sequence_fuzz_test.go), scoped down to what ValidatePATToken's path
// touches.
//
// Migrating the roles/user_roles tables so GetUserRoles can succeed (needed to
// reach ValidatePATToken's role-building success path at all) has a real
// trade-off worth stating: GetUserRoles now never errors for an existing user
// (Find on an empty result set is not a GORM error), so ValidatePATToken's
// role-lookup failure branch -- which returns ErrRoleResolutionUnavailable
// (#1944; it formerly soft-failed to an empty role list with a nil error) --
// is not reachable from this fixture. It is covered directly by
// validate_roles_unavailable_test.go with an injected storage fault.
func buildPATLifecycleFixture(t *testing.T) (*KeyorixCore, []patLifecycleFixtureEntry) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1) // :memory: gives each conn its own DB otherwise
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.PersonalAccessToken{}, &models.Notification{},
		&models.Role{}, &models.UserRole{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	mustCreate := func(v any) {
		if err := db.Create(v).Error; err != nil {
			t.Fatalf("seed %T: %v", v, err)
		}
	}
	const userA, userB uint = 101, 102
	mustCreate(&models.User{
		ID: userA, Username: "pat-fuzz-a", UsernameFolded: "pat-fuzz-a",
		Email: "pat-fuzz-a@x.io", EmailFolded: "pat-fuzz-a@x.io",
		IsActive: true, AccountState: AccountActive,
	})
	mustCreate(&models.User{
		ID: userB, Username: "pat-fuzz-b", UsernameFolded: "pat-fuzz-b",
		Email: "pat-fuzz-b@x.io", EmailFolded: "pat-fuzz-b@x.io",
		IsActive: true, AccountState: AccountActive,
	})
	// A real role assignment for userA so ValidatePATToken's GetUserRoles call
	// (pat.go) succeeds and actually builds a non-empty roleNames slice --
	// without this, the roles/user_roles tables wouldn't exist at all and
	// GetUserRoles would always error (ValidatePATToken then returns
	// ErrRoleResolutionUnavailable, #1944), leaving the success path that
	// builds roleNames unexercised.
	// userB is deliberately left with no role assignment: GetUserRoles for an
	// existing user with zero rows still succeeds (empty slice, no error), so
	// this also exercises the "assigned" and "unassigned but table present"
	// cases without needing a second, more invasive test setup.
	const fuzzRoleID uint = 900
	mustCreate(&models.Role{ID: fuzzRoleID, Name: "fuzz-role", NameFolded: "fuzz-role"})
	mustCreate(&models.UserRole{UserID: userA, RoleID: fuzzRoleID})

	c := NewKeyorixCore(ls)
	fixedNow := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixedNow }
	past := fixedNow.Add(-time.Hour)

	var entries []patLifecycleFixtureEntry

	mustIssue := func(owner uint, expiresAt *time.Time, scopes []string, projectScope, envScope uint, cidrs []string) patLifecycleFixtureEntry {
		t.Helper()
		res, err := c.CreateOwnPAT(ctx, owner, "fuzz-token", expiresAt, scopes, projectScope, envScope, cidrs)
		if err != nil {
			t.Fatalf("CreateOwnPAT: %v", err)
		}
		var restriction *PATRestriction
		if len(scopes) > 0 || projectScope != 0 || envScope != 0 || len(cidrs) > 0 {
			restriction = &PATRestriction{
				Permissions: scopes, ProjectID: projectScope, EnvironmentID: envScope, AllowedCIDRs: cidrs,
			}
		}
		return patLifecycleFixtureEntry{
			plain: res.PlainToken, ownerID: owner, patID: res.Token.ID,
			expired: expiresAt != nil && !expiresAt.After(fixedNow), restriction: restriction,
		}
	}

	// 1. Unrestricted (inherits owner's full permission set).
	entries = append(entries, mustIssue(userA, nil, nil, 0, 0, nil))
	// 2. Scope + project restricted.
	entries = append(entries, mustIssue(userA, nil, []string{"secrets.read"}, 5, 0, nil))
	// 3. CIDR + environment restricted.
	entries = append(entries, mustIssue(userB, nil, nil, 0, 7, []string{"10.0.0.0/8"}))
	// 4. Combined restriction (scope + project + environment + CIDR), owner A.
	entries = append(entries, mustIssue(userA, nil,
		[]string{"secrets.read", "secrets.write"}, 3, 9, []string{"192.168.0.0/16"}))
	// 5. Expired (past ExpiresAt, never revoked), owner A.
	entries = append(entries, mustIssue(userA, &past, nil, 0, 0, nil))
	// 6. Revoked (owner B) — issue unrestricted, then revoke via the real path.
	revokedEntry := mustIssue(userB, nil, nil, 0, 0, nil)
	if _, err := c.RevokeOwnPAT(ctx, userB, revokedEntry.patID); err != nil {
		t.Fatalf("RevokeOwnPAT: %v", err)
	}
	revokedEntry.revoked = true
	entries = append(entries, revokedEntry)

	// 7. Dirty scope/CIDR input (blanks, an exact duplicate, a bare IPv4 needing
	// /32 promotion, a bare IPv6 needing /128 promotion) -- exercises
	// encodePATScopes' blank-skip/duplicate-skip branches and encodePATCIDRs'
	// blank-skip/duplicate-skip/bare-IP-promotion branches, none of which the
	// clean entries above ever reach. The expected restriction is hand-computed
	// independently of encodePATScopes/encodePATCIDRs (not derived by calling
	// them), same discipline as mustIssue's restriction-building above.
	dirtyScopes := []string{"secrets.read", "  ", "secrets.read", "secrets.write", ""}
	dirtyCIDRs := []string{"10.0.0.0/8", "  ", "10.0.0.0/8", "192.168.1.5", "::1", ""}
	dirtyRes, err := c.CreateOwnPAT(ctx, userA, "dirty-fuzz-token", nil, dirtyScopes, 11, 0, dirtyCIDRs)
	if err != nil {
		t.Fatalf("CreateOwnPAT (dirty scope/CIDR): %v", err)
	}
	entries = append(entries, patLifecycleFixtureEntry{
		plain: dirtyRes.PlainToken, ownerID: userA, patID: dirtyRes.Token.ID,
		restriction: &PATRestriction{
			Permissions:  []string{"secrets.read", "secrets.write"},
			ProjectID:    11,
			AllowedCIDRs: []string{"10.0.0.0/8", "192.168.1.5/32", "::1/128"},
		},
	})

	// CreateOwnPAT must reject a malformed CIDR outright (encodePATCIDRs's
	// ParseCIDR failure, wrapped by CreateOwnPAT's own error path). Checked by
	// intent here rather than folded into a fixture entry, since a rejected
	// create produces no token to add to the corpus.
	if _, err := c.CreateOwnPAT(ctx, userA, "bad-cidr", nil, nil, 0, 0, []string{"not-a-cidr"}); err == nil {
		t.Fatalf("CreateOwnPAT: expected an error for an unparseable CIDR, got none")
	}

	// RevokeOwnPAT must refuse to revoke a token owned by someone else, and
	// report it as not-found (anti-enumeration) rather than revoking it or
	// leaking that it exists under a different owner. Exercised against entry 0
	// (owned by userA) using userB's caller id; must not actually revoke it.
	if _, err := c.RevokeOwnPAT(ctx, userB, entries[0].patID); err == nil {
		t.Fatalf("RevokeOwnPAT: expected an error revoking another user's token, got none")
	}

	return c, entries
}

// patConfusables are Unicode code points that visually resemble ASCII but are
// distinct bytes once UTF-8 encoded — zero-width/format characters and a
// Cyrillic homoglyph — used by mutation op 6.
var patConfusables = []rune{' ', '\t', '\n', '\u200b', '\ufeff', '\u0430', '\u2000'}

// patPrefixAlts are near-miss variants of patPrefix used by mutation op 5.
var patPrefixAlts = []string{"KX_PAT_", "kx_pat-", "Kx_Pat_", "kx_pat_ ", "xk_pat_", "kx_pat"}

// mutatePATToken applies one of nine deterministic transforms to base, optionally
// pulling bytes from other (another issued token, for the splice op). All
// transforms are pure functions of their byte/int arguments — no randomness beyond
// what the fuzzer already supplies, so a failing case reproduces exactly.
func mutatePATToken(base string, other string, op, p0, p1 byte, extra []byte) string {
	switch op % 9 {
	case 0: // exact copy — the positive control (must validate iff not revoked/expired)
		return base
	case 1: // single-byte flip
		if len(base) == 0 {
			return base
		}
		bs := []byte(base)
		idx := int(p0) % len(bs)
		mask := p1
		if mask == 0 {
			mask = 0xFF
		}
		bs[idx] ^= mask
		return string(bs)
	case 2: // truncation
		if len(base) == 0 {
			return base
		}
		cut := int(p0) % (len(base) + 1)
		return base[:cut]
	case 3: // extension
		return base + string(extra)
	case 4: // case folding
		if p0%2 == 0 {
			return strings.ToUpper(base)
		}
		return strings.ToLower(base)
	case 5: // prefix swap (near-miss patPrefix variants)
		alt := patPrefixAlts[int(p0)%len(patPrefixAlts)]
		if strings.HasPrefix(base, patPrefix) {
			return alt + base[len(patPrefix):]
		}
		return alt + base
	case 6: // whitespace / Unicode confusable insertion
		r := patConfusables[int(p0)%len(patConfusables)]
		idx := 0
		if len(base) > 0 {
			idx = int(p1) % (len(base) + 1)
		}
		return base[:idx] + string(r) + base[idx:]
	case 7: // splice with another user's issued token (the id/secret-mismatch analogue)
		if other == "" {
			return base
		}
		splitA := 0
		if len(base) > 0 {
			splitA = int(p0) % (len(base) + 1)
		}
		splitB := 0
		if len(other) > 0 {
			splitB = int(p1) % (len(other) + 1)
		}
		return base[:splitA] + other[splitB:]
	case 8: // encoding variant — re-encode the random body with standard (padded) base64
		if !strings.HasPrefix(base, patPrefix) {
			return base
		}
		body := base[len(patPrefix):]
		decoded, err := base64.RawURLEncoding.DecodeString(body)
		if err != nil {
			return base
		}
		return patPrefix + base64.StdEncoding.EncodeToString(decoded)
	}
	return base
}

func FuzzPATValidateLifecycle(f *testing.F) {
	seeds := []struct {
		baseSel, op, p0, p1 byte
		extra               []byte
	}{
		{0, 0, 0, 0, nil},                        // exact copy of entry 0 (unrestricted) -> must succeed
		{1, 0, 0, 0, nil},                        // exact copy of entry 1 (scope+project restricted) -> restriction must bind
		{2, 0, 0, 0, nil},                        // exact copy of entry 2 (CIDR+environment restricted) -> restriction must bind
		{3, 0, 0, 0, nil},                        // exact copy of entry 3 (combined restriction) -> restriction must bind
		{4, 0, 0, 0, nil},                        // exact copy of the expired entry -> must fail closed
		{5, 0, 0, 0, nil},                        // exact copy of the revoked entry -> must fail closed
		{6, 0, 0, 0, nil},                        // exact copy of entry 6 (dirty scope/CIDR input) -> normalized restriction must bind
		{1, 1, 10, 0x20, nil},                    // single byte flip on a scoped token
		{2, 2, 5, 0, nil},                        // truncate a CIDR-restricted token
		{3, 3, 0, 0, []byte("XYZ")},              // extend the combined-restriction token
		{0, 4, 1, 0, nil},                        // lowercase the whole token
		{1, 5, 0, 0, nil},                        // prefix swap
		{0, 6, 2, 3, nil},                        // confusable insertion
		{1, 7, 2, 3, nil},                        // splice entry 1's prefix with entry 2's (cross-user) suffix
		{3, 8, 0, 0, nil},                        // re-encode with padded base64
		{0, 0, 0, 0, []byte("not-a-pat-at-all")}, // op 0 ignores extra; exercises the exact-copy path once more
	}
	for _, s := range seeds {
		f.Add(s.baseSel, s.op, s.p0, s.p1, s.extra)
	}

	f.Fuzz(func(t *testing.T, baseSel, op, p0, p1 byte, extra []byte) {
		c, entries := buildPATLifecycleFixture(t)
		ctx := context.Background()

		base := entries[int(baseSel)%len(entries)]
		other := entries[int(p0)%len(entries)] // independent index; op 7 is the only consumer
		mutated := mutatePATToken(base.plain, other.plain, op, p0, p1, extra)

		// Independent ground truth: does `mutated` byte-exactly equal an issued token?
		var match *patLifecycleFixtureEntry
		for i := range entries {
			if entries[i].plain == mutated {
				match = &entries[i]
				break
			}
		}

		var user *models.User
		var roles []string
		var restriction *PATRestriction
		var patID uint
		var verr error
		fuzzutil.Guard(t.Fatalf, "ValidatePATToken", func() {
			user, roles, restriction, patID, verr = c.ValidatePATToken(ctx, mutated)
		})
		_ = roles

		// CurrentPATRestriction (pat.go:268) mirrors ValidatePATToken's revoked/expired
		// gate and restriction lookup for the same raw token, bypassing any auth-cache
		// snapshot (#146/#G18) — the middleware's per-request network-allowlist re-check.
		// Same oracle applies: fail-closed on revoked/expired, exact restriction binding
		// on success, never any identity (it returns no user).
		var curRestriction *PATRestriction
		var cerr error
		fuzzutil.Guard(t.Fatalf, "CurrentPATRestriction", func() {
			curRestriction, cerr = c.CurrentPATRestriction(ctx, mutated)
		})

		if match == nil {
			// (a) FAIL-CLOSED IDENTITY: no byte-exact issued token -> must never succeed,
			// must never return an identity.
			if verr == nil {
				t.Fatalf("AUTH BYPASS: mutated token %q (not byte-exact to any issued token) validated successfully as user %v", mutated, user)
			}
			if user != nil {
				t.Fatalf("IDENTITY LEAK: mutated token %q returned a non-nil user %v despite validation error %v", mutated, user, verr)
			}
			// CurrentPATRestriction must also refuse a non-byte-exact token.
			if cerr == nil {
				t.Fatalf("CurrentPATRestriction AUTH BYPASS: mutated token %q (not byte-exact to any issued token) returned a restriction %+v with no error", mutated, curRestriction)
			}
			return
		}

		switch {
		case match.revoked:
			// (b) revoked never authenticates.
			if verr == nil {
				t.Fatalf("REVOKED TOKEN ACCEPTED: byte-exact match to revoked token (owner=%d) validated successfully", match.ownerID)
			}
			if !errors.Is(verr, ErrPATRevoked) {
				t.Fatalf("byte-exact match to revoked token returned wrong error: %v (want ErrPATRevoked)", verr)
			}
			if user != nil {
				t.Fatalf("IDENTITY LEAK: revoked token resolved to user %v", user)
			}
			if !errors.Is(cerr, ErrPATRevoked) {
				t.Fatalf("CurrentPATRestriction: byte-exact match to revoked token returned wrong error: %v (want ErrPATRevoked)", cerr)
			}
		case match.expired:
			// (b) expired never authenticates.
			if verr == nil {
				t.Fatalf("EXPIRED TOKEN ACCEPTED: byte-exact match to expired token (owner=%d) validated successfully", match.ownerID)
			}
			if !errors.Is(verr, ErrPATExpired) {
				t.Fatalf("byte-exact match to expired token returned wrong error: %v (want ErrPATExpired)", verr)
			}
			if user != nil {
				t.Fatalf("IDENTITY LEAK: expired token resolved to user %v", user)
			}
			if !errors.Is(cerr, ErrPATExpired) {
				t.Fatalf("CurrentPATRestriction: byte-exact match to expired token returned wrong error: %v (want ErrPATExpired)", cerr)
			}
		default:
			// (a) a byte-exact, unexpired, unrevoked issued token MUST validate, and
			// MUST resolve to exactly its own owner.
			if verr != nil {
				t.Fatalf("VALID TOKEN REJECTED: byte-exact match to a live token (owner=%d) failed to validate: %v", match.ownerID, verr)
			}
			if user == nil || user.ID != match.ownerID {
				t.Fatalf("WRONG IDENTITY: byte-exact match to owner=%d resolved to user %v", match.ownerID, user)
			}
			if patID != match.patID {
				t.Fatalf("WRONG PAT ID: byte-exact match to pat=%d resolved to pat id %d", match.patID, patID)
			}
			// (c) RESTRICTION BINDING: exactly this token's own restriction, never another's.
			if !patRestrictionsEqual(restriction, match.restriction) {
				t.Fatalf("RESTRICTION BLEED: token owner=%d pat=%d got restriction %+v, want %+v",
					match.ownerID, match.patID, restriction, match.restriction)
			}
			if cerr != nil {
				t.Fatalf("CurrentPATRestriction: byte-exact match to a live token (owner=%d) failed: %v", match.ownerID, cerr)
			}
			if !patRestrictionsEqual(curRestriction, match.restriction) {
				t.Fatalf("CurrentPATRestriction RESTRICTION BLEED: token owner=%d pat=%d got restriction %+v, want %+v",
					match.ownerID, match.patID, curRestriction, match.restriction)
			}
		}
	})
}

// patRestrictionsEqual compares two *PATRestriction for the fields
// ValidatePATToken can populate, treating nil as "unrestricted" (the only value
// patRestrictionFrom ever returns for a token with no scopes/CIDRs/project/env).
func patRestrictionsEqual(a, b *PATRestriction) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.ProjectID != b.ProjectID || a.EnvironmentID != b.EnvironmentID {
		return false
	}
	if !stringSlicesEqualUnordered(a.Permissions, b.Permissions) {
		return false
	}
	return stringSlicesEqualUnordered(a.AllowedCIDRs, b.AllowedCIDRs)
}

func stringSlicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
