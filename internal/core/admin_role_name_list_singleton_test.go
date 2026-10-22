// admin_role_name_list_singleton_test.go — the guard half of #2496
// (INV-CORE-20).
//
// ADR-084 made `bypasses_permission_checks` the structural marker for
// "this role confers administrative authority" and retired name-based
// resolution. `installAdminRoleIDSet` nevertheless survived as a SECOND,
// separately-maintained name list for two more years of commits, because
// nothing failed when it did. It was found by a documentation audit, not by a
// check — and the recurring lesson in this repo is that a list nothing
// enumerates grows a sibling (see CLAUDE.md, "an enumeration is only as
// complete as the idioms it knows about", five recorded instances).
//
// This is the enumeration. Every occurrence of a canonical admin role NAME as a
// string literal in internal/core's non-test source must have a reviewed row
// below, saying what that occurrence is and why it is not a second
// admin-ness authority. A new occurrence fails this test, which forces the
// same classification at authoring time rather than at the next audit.
//
// Same shape as actor_sentinel_completeness_test.go's allowlist (keyed by
// "<file>:<enclosing top-level declaration>", so it survives line churn),
// including its documented trade-off: a SECOND occurrence added inside an
// ALREADY-listed declaration collapses into the same key and is not separately
// flagged. The dangerous case this guards is a NEW declaration that starts
// deciding admin-ness by name.
//
// What this does NOT do, stated explicitly per CLAUDE.md ("name mechanisms for
// what they verify, and state in the doc comment what they do not"):
//
//   - It does not prove the listed occurrences are correct, only that each was
//     looked at. The `reason` field is prose and decays like any prose.
//   - It is scoped to internal/core. A name-based admin list in server/http,
//     server/grpc or internal/cli is invisible to it. Those layers resolve
//     admin-ness by calling into core (IsGlobalAdmin, targetHasGlobalAdminRole,
//     roleSetContainsAdmin), so core is where a second authority would have to
//     live to matter — but that is an argument about likelihood, not coverage.
//   - It matches string literals, so a name assembled at runtime
//     ("super" + "_admin"), read from config, or held in a non-literal constant
//     elsewhere would slip past. No such construction exists today.
//
// The behavioural half — that the admin-role set the last-admin guards actually
// use is derived from the flag and not from any name — is
// admin_role_structural_source_test.go.
package core

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// adminNameUseKind classifies what an admin-role-name literal is doing.
type adminNameUseKind int

const (
	// kindTheOneNameList: THE single permitted name-based admin list and its
	// accessor. ADR-084 deliberately kept a pure-string admin-name predicate
	// for guards that already hold a role NAME and must not do a storage
	// lookup (role seeding, where the flag is not written yet; IdP auto-grant
	// escalation checks, which belt-and-brace the flag with the name). Exactly
	// one such list may exist.
	kindTheOneNameList adminNameUseKind = iota
	// kindRoleDefinition: the literal names the role being DEFINED or
	// reserved (seed definitions, built-in-name reservation, a seeded role
	// looked up by key during bootstrap). Defining a role named "admin" is not
	// a claim about which roles are administrative — it is where the flag gets
	// written from.
	kindRoleDefinition
	// kindNotAdminness: the literal is an admin role name but the decision it
	// feeds is explicitly not an authorization one — a UI ranking, a
	// notification-recipient list, a permission ACTION that happens to be
	// spelled "admin". Each row says why it cannot be mistaken for a
	// permission decision.
	kindNotAdminness
)

type adminNameUse struct {
	kind   adminNameUseKind
	reason string
}

// adminRoleNameLiteralAllowlist is the reviewed inventory. Key is
// "<file>:<enclosing top-level declaration>".
//
// Adding a row is a claim you are making: that this occurrence does not decide
// which roles confer administrative authority. If it DOES, it belongs in
// adminBypassRoleIDSet (admin_roles.go) instead — the structural flag — and the
// row must not be added.
var adminRoleNameLiteralAllowlist = map[string]adminNameUse{
	"authz.go:adminRoleNames": {
		kindTheOneNameList,
		"THE one permitted name list (ADR-084 kept it for name-holding guards that must not " +
			"do a storage lookup). Read only through isAdminRoleName. Its callers " +
			"(idpAutoGrantOfRoleIsEscalation, sod.go's SoD predicates, " +
			"requireGranterHoldsRolePermissionsNoBaseline's /system-relay refusal, " +
			"auth_bootstrap's seeding) all pair it with, or feed, the structural flag — none " +
			"of them is the sole authority on admin-ness.",
	},
	"auth_bootstrap.go:defaultRoles": {
		kindRoleDefinition,
		"The seed definitions themselves: name, description, permission bundle. This is " +
			"where BypassesPermissionChecks is WRITTEN from (BootstrapSystem calls " +
			"SetRoleBypassesPermissionChecks for every isAdminRoleName(rdef.Name)), so it is " +
			"upstream of the flag, not a second reader of it.",
	},
	"auth_bootstrap.go:builtinRoleNames": {
		kindRoleDefinition,
		"Built-in-name RESERVATION (#294): refuses a caller-created role that squats a " +
			"built-in name. Pins historical aliases too. Says nothing about which roles are " +
			"administrative — a reserved name is not an administrative one (system_viewer, " +
			"auditor are in it).",
	},
	"role_scope_guard.go:projectTierRoleNames": {
		kindRoleDefinition,
		"The ADR-021 project TIER (#3546): which built-in roles may only be granted at a " +
			"project scope. Decides whether a grant's SCOPE is valid, never whether a role " +
			"confers administrative authority; project_admin is in it as a project-tier " +
			"role alongside project_viewer, and admin-ness stays with the structural flag.",
	},
	"auth_bootstrap.go:bootstrapSystemLocked": {
		kindRoleDefinition,
		"roleIDs[\"admin\"] — the bootstrap admin's own grant, looked up by key in the map " +
			"this same function just seeded from defaultRoles. A definition-site lookup, not " +
			"an admin-ness test.",
	},
	"identity.go:rolePrecedence": {
		kindNotAdminness,
		"A display RANKING, picking one \"primary\" role name for single-role UI consumers. " +
			"Its own type doc says the backend still enforces real scope-aware checks via " +
			"Authorize and that this summary is for UI convenience, not a security boundary. " +
			"It ranks every known role, not just admin ones, and no authorization path reads " +
			"it.",
	},
	"notifications.go:approverRoleNames": {
		kindNotAdminness,
		"Selects RECIPIENTS of an \"access request created\" notification. Read only by " +
			"isApproverRole, which gates whether to send a notification — never whether to " +
			"permit an action. Over- or under-including a role here changes who gets an " +
			"email, not who can approve: approval itself goes through the ordinary " +
			"permission check.",
	},
	"access_review.go:secretsActionRank": {
		kindNotAdminness,
		"\"admin\" here is a secrets permission ACTION (read/write/delete/admin), ranked for " +
			"access-review severity. Not a role name at all — the collision is spelling.",
	},
	"access_review.go:roleIsAdminTier": {
		kindNotAdminness,
		"p.Action == \"admin\" on a models.Permission whose Resource is \"secrets\" — a " +
			"permission ACTION, not a role name. roleIsAdminTier classifies a role by the " +
			"permissions it BUNDLES (which is the right question for dormant-grant review), " +
			"never by what the role is called.",
	},
}

// adminRoleNameLiteralRe matches one of the four canonical admin role names as
// a complete quoted string literal. Anchored on the quotes so a permission name
// that merely ENDS in .admin ("secrets.admin", "users.admin") does not match —
// only the role name itself.
var adminRoleNameLiteralRe = regexp.MustCompile(`"(?:super_admin|system_admin|project_admin|admin)"`)

// adminNameDeclRe matches a top-level func or var declaration and captures its
// name, so an occurrence can be attributed to the declaration that contains it.
var adminNameDeclRe = regexp.MustCompile(`^(?:func\s+(?:\([^)]*\)\s*)?|var\s+)([A-Za-z0-9_]+)`)

// actualAdminRoleNameLiteralSites scans every non-test *.go file directly in
// internal/core and returns the set of "file:decl" keys where an admin role
// name appears as a string literal outside a comment.
func actualAdminRoleNameLiteralSites(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading internal/core: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		currentDecl := ""
		for line := range strings.SplitSeq(string(b), "\n") {
			if m := adminNameDeclRe.FindStringSubmatch(line); m != nil {
				currentDecl = m[1]
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // a doc comment naming the pattern is not an occurrence
			}
			// Strip trailing line comments so a literal quoted inside one
			// ("...the fixed `admin` list...") is not counted.
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			if adminRoleNameLiteralRe.MatchString(line) && currentDecl != "" {
				found[name+":"+currentDecl] = true
			}
		}
	}
	return found
}

// TestAdminRoleNameLiteralsAreAllowlisted fails if a canonical admin role name
// appears as a string literal in internal/core's non-test source outside the
// reviewed inventory above — the mechanism that was missing when
// installAdminRoleIDSet survived ADR-084 — and also if a row goes stale.
//
// Calibration, both directions, is TestAdminRoleNameAllowlistSelfCheck below:
// the scanner must actually find the known sites (not pass by finding nothing),
// and a planted second list must be rejected.
func TestAdminRoleNameLiteralsAreAllowlisted(t *testing.T) {
	t.Parallel()
	actual := actualAdminRoleNameLiteralSites(t)

	var unreviewed []string
	for key := range actual {
		if _, ok := adminRoleNameLiteralAllowlist[key]; !ok {
			unreviewed = append(unreviewed, key)
		}
	}
	sort.Strings(unreviewed)

	var stale []string
	for key := range adminRoleNameLiteralAllowlist {
		if !actual[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	if len(unreviewed) > 0 {
		t.Errorf("found %d admin-role-name string literal(s) in internal/core with no reviewed row in "+
			"adminRoleNameLiteralAllowlist (internal/core/admin_role_name_list_singleton_test.go): %v\n\n"+
			"If this occurrence decides WHICH ROLES CONFER ADMINISTRATIVE AUTHORITY, do not add a row: "+
			"that is a second source of truth, and #2496/INV-CORE-20 exists because the last one survived "+
			"ADR-084 undetected. Resolve it from models.Role.BypassesPermissionChecks instead, via "+
			"adminBypassRoleIDSet (admin_roles.go) or storage.RoleSetBypassesPermissionChecks.\n\n"+
			"If it genuinely is a role definition, a UI ranking, a notification-recipient list, a "+
			"permission action, or prose, add a row saying which and why.", len(unreviewed), unreviewed)
	}
	if len(stale) > 0 {
		t.Errorf("found %d adminRoleNameLiteralAllowlist row(s) whose literal no longer exists in source: %v\n"+
			"Remove them — a stale row makes the inventory look larger than the thing it reviews.",
			len(stale), stale)
	}
}

// TestAdminRoleNameAllowlistSelfCheck is the calibration pass: a guard nobody
// has watched fail is not a guard, and a scanner that silently matches nothing
// would pass this file's main test forever.
func TestAdminRoleNameAllowlistSelfCheck(t *testing.T) {
	t.Parallel()

	// Green direction: the scanner must find the sites we know are there. If a
	// future refactor breaks the regex or the file walk, this fires instead of
	// the main test quietly passing on an empty scan.
	actual := actualAdminRoleNameLiteralSites(t)
	for _, must := range []string{
		"authz.go:adminRoleNames",
		"auth_bootstrap.go:defaultRoles",
		"notifications.go:approverRoleNames",
	} {
		if !actual[must] {
			t.Errorf("scanner found no admin-role-name literal at %q, but one is there — "+
				"the scan is broken, and the allowlist test would pass vacuously", must)
		}
	}
	if len(actual) < 5 {
		t.Errorf("scanner found only %d site(s) in internal/core; the reviewed inventory has %d. "+
			"A scan this thin is almost certainly not reading the package.", len(actual), len(adminRoleNameLiteralAllowlist))
	}

	// Red direction: the regex must match a second list of exactly the shape
	// installAdminRoleNames had, and must NOT match a permission name that
	// merely ends in ".admin".
	if !adminRoleNameLiteralRe.MatchString(`var installAdminRoleNames = []string{"super_admin", "admin", "system_admin"}`) {
		t.Error("the retired installAdminRoleNames declaration would NOT be caught by this guard — " +
			"it cannot detect the very regression it exists for")
	}
	for _, notARole := range []string{
		`c.storage.RoleSetHasPermission(ctx, ids, "secrets.admin")`,
		`{"users.admin", "Full administrative access to users"}`,
		`perm := "audit.admin"`,
	} {
		if adminRoleNameLiteralRe.MatchString(notARole) {
			t.Errorf("permission name in %q matched the ROLE-name regex — the guard would demand "+
				"allowlist rows for every .admin permission and get routed around", notARole)
		}
	}
}
