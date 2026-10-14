package accessplan

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
)

// rolePrefix is prepended to every Keyorix role this package proposes, so a migrated role is
// visibly distinguishable from a hand-created one of the same capability set at a glance (and
// never collides with a pre-existing customer role name by accident).
const rolePrefix = "vault-migrated"

// capabilityToPermission maps one Vault ACL capability to its Keyorix permission equivalent
// (ADR-114's permission-mapping table). "" means no Keyorix equivalent exists for that
// capability alone (every such capability either already got its own special handling — sudo,
// deny — before reaching here, or is simply not one of the four this tool recognizes).
func capabilityToPermission(capability string) string {
	switch capability {
	case "read", "list":
		return "secrets.read"
	case "create", "update":
		return "secrets.write"
	case "delete":
		return "secrets.delete"
	default:
		return ""
	}
}

// mappedPermissions converts a stanza's capability list into its deduplicated, sorted Keyorix
// permission set. A capability with no mapping is simply dropped (not every Vault capability —
// e.g. "patch" has no Keyorix write-granularity equivalent beyond secrets.write) — this is a
// narrowing, not a widening: an unmapped capability can never grant something Keyorix couldn't
// otherwise represent.
func mappedPermissions(capabilities []string) []string {
	set := map[string]bool{}
	for _, c := range capabilities {
		if p := capabilityToPermission(c); p != "" {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func containsCapability(capabilities []string, want string) bool {
	return slices.Contains(capabilities, want)
}

// isTemplatedPath reports whether a policy path uses Vault's identity-templating syntax
// ({{identity.entity.id}}, etc.). ADR-114: a templated path's real target depends on who
// authenticates, so no single static Keyorix grant can represent every future holder of it.
func isTemplatedPath(path string) bool {
	return strings.Contains(path, "{{") || strings.Contains(path, "}}")
}

// roleName derives this package's deterministic Keyorix role name for a given permission set —
// the same set always produces the same name, so a repeat run (or a sibling role with the same
// capabilities) resolves to the SAME proposed role rather than a fresh duplicate.
func roleName(permissions []string) string {
	short := make([]string, len(permissions))
	for i, p := range permissions {
		short[i] = strings.TrimPrefix(p, "secrets.")
	}
	sort.Strings(short)
	return rolePrefix + "-" + strings.Join(short, "-")
}

// wildcardSplit splits a Vault ACL path into its literal prefix and whether it ends in Vault's
// one legitimate glob form (a trailing "*"). literal always excludes the "*" itself.
func wildcardSplit(path string) (literal string, wildcard bool) {
	if before, ok := strings.CutSuffix(path, "*"); ok {
		return before, true
	}
	return path, false
}

// pathsOverlap reports whether two Vault ACL paths could ever match the same real secret path —
// the question subtractDeniedPaths' overlap check needs to decide whether a deny stanza bears on
// a given allow stanza at all.
func pathsOverlap(a, b string) bool {
	aLit, aWild := wildcardSplit(a)
	bLit, bWild := wildcardSplit(b)
	switch {
	case aWild && bWild:
		return strings.HasPrefix(aLit, bLit) || strings.HasPrefix(bLit, aLit)
	case aWild:
		return strings.HasPrefix(b, aLit)
	case bWild:
		return strings.HasPrefix(a, bLit)
	default:
		return a == b
	}
}

// namedStanza pairs a policy's name with one of its path blocks, for building a SourceRef a
// human reviewer can trace back to the exact Vault policy.
type namedStanza struct {
	policyName string
	block      healthscan.PolicyPathBlock
	perms      []string
}

func stanzaRef(policyName, path string) string {
	return fmt.Sprintf("policy:%s path:%s", policyName, path)
}

// BuildPolicyItems classifies every path/capability stanza across policies — the complete,
// already-resolved attached-policy set for ONE auth-method role or user — into Role Items.
// Every Item's Outcome is Create (never Skip/Conflict — Reconcile resolves those against live
// Keyorix state) except Unmappable ones, which are final.
//
// Scoping note (load-bearing, not incidental): callers must pass exactly one role/user's own
// attached policies, never the Vault-wide policy list. The deny/allow overlap check below is
// only correct within the scope Vault itself would actually apply a deny — two DIFFERENT roles
// each holding one half of an allow/deny pair never interact in Vault, and must not interact
// here either.
func BuildPolicyItems(policies []healthscan.Policy, mapper *PathMapper) []Item {
	var items []Item
	var allows []namedStanza
	var denyPaths []string

	for _, pol := range policies {
		for _, b := range pol.Blocks {
			ref := stanzaRef(pol.Name, b.Path)
			switch {
			case containsCapability(b.Capabilities, "sudo"):
				items = append(items, Item{Kind: KindRole, Outcome: Unmappable, SourceRef: ref,
					Category: CategorySudo,
					Reason:   `grants "sudo", a full bypass of every other restriction on this path — no Keyorix equivalent is ever granted by migration`,
				})
			case isTemplatedPath(b.Path):
				items = append(items, Item{Kind: KindRole, Outcome: Unmappable, SourceRef: ref,
					Category: CategorySentinelOrTemplated,
					Reason:   "templated path — its real target depends on who authenticates; no static grant can represent it",
				})
			case containsCapability(b.Capabilities, "deny"):
				denyPaths = append(denyPaths, b.Path)
			default:
				perms := mappedPermissions(b.Capabilities)
				if len(perms) == 0 {
					items = append(items, Item{Kind: KindRole, Outcome: Unmappable, SourceRef: ref,
						Category: CategorySentinelOrTemplated,
						Reason:   fmt.Sprintf("capabilities %v have no Keyorix equivalent", b.Capabilities),
					})
					continue
				}
				allows = append(allows, namedStanza{policyName: pol.Name, block: b, perms: perms})
			}
		}
	}

	for _, as := range allows {
		ref := stanzaRef(as.policyName, as.block.Path)
		if overlapsAnyDeny(as.block.Path, denyPaths) {
			items = append(items, Item{Kind: KindRole, Outcome: Unmappable, SourceRef: ref,
				Category: CategoryDenyOverlap,
				Reason:   "a deny stanza on an overlapping path is attached to the same role/user — migrating this allow unmodified could grant MORE than Vault's actual effective access; review and migrate a narrower scope manually",
			})
			continue
		}
		res, category, reason, ok := mapper.Resolve(as.block.Path)
		if !ok {
			items = append(items, Item{Kind: KindRole, Outcome: Unmappable, SourceRef: ref, Category: category, Reason: reason})
			continue
		}
		name := roleName(as.perms)
		items = append(items, Item{
			Kind: KindRole, Outcome: Create, SourceRef: ref,
			ProposedName:          name,
			ProposedProjectID:     res.ProjectID,
			ProposedEnvironmentID: res.EnvironmentID,
			ProposedPermissions:   as.perms,
			ProvenanceKey:         plan.SourceID("role", name, fmt.Sprint(res.ProjectID), fmt.Sprint(res.EnvironmentID)),
		})
	}
	return items
}

func overlapsAnyDeny(allowPath string, denyPaths []string) bool {
	for _, d := range denyPaths {
		if pathsOverlap(allowPath, d) {
			return true
		}
	}
	return false
}
