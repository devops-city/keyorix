package accessplan

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
)

// invalidIdentityChar matches anything outside [a-zA-Z0-9-_] — sanitizeIdentityName's allowlist.
var invalidIdentityChar = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// sanitizeIdentityName builds a deterministic, Keyorix-safe machine identity name from a
// Vault-sourced prefix and name — collapsing anything outside [a-zA-Z0-9-_] to a single "-", the
// same conservative allowlist this module's cmd layer already uses for secret names
// (docs/design-keyorix-migrate.md's sanitizeSecretName precedent).
func sanitizeIdentityName(prefix, raw string) string {
	cleaned := invalidIdentityChar.ReplaceAllString(raw, "-")
	cleaned = strings.Trim(cleaned, "-")
	return prefix + "-" + cleaned
}

// policiesByName indexes a flat policy list for repeated role-by-role lookups.
func policiesByName(policies []healthscan.Policy) map[string]healthscan.Policy {
	out := make(map[string]healthscan.Policy, len(policies))
	for _, p := range policies {
		out[p.Name] = p
	}
	return out
}

// resolveAttachedPolicies returns the subset of allPolicies named in tokenPolicies, in the
// order given. Vault's built-in "default" policy (attached to every token automatically; its
// only grants are token self-management and cubbyhole, never a KV path) is always excluded —
// including it would classify "default" over and over, once per role, as a Mount-Management
// Unmappable item for literally every single role/user this tool ever reads, which is noise,
// not a finding.
func resolveAttachedPolicies(tokenPolicies []string, byName map[string]healthscan.Policy) []healthscan.Policy {
	var out []healthscan.Policy
	for _, name := range tokenPolicies {
		if name == "default" {
			continue
		}
		if p, ok := byName[name]; ok {
			out = append(out, p)
		}
	}
	return out
}

// machineRoleGrantItems turns the Create-outcome Role items BuildPolicyItems produced for one
// role/user into the KindMachineRoleGrant Items linking them to machineName. Unmappable Role
// items are passed through unchanged (still reported) but never get a grant — there is nothing
// to grant.
func machineRoleGrantItems(roleItems []Item, machineName, grantSourceRef string) []Item {
	out := make([]Item, 0, len(roleItems))
	for _, it := range roleItems {
		out = append(out, it)
		if it.Outcome != Create {
			continue
		}
		out = append(out, Item{
			Kind: KindMachineRoleGrant, Outcome: Create, SourceRef: grantSourceRef,
			ProposedRoleRef:       it.ProposedName,
			ProposedMachineRef:    machineName,
			ProposedProjectID:     it.ProposedProjectID,
			ProposedEnvironmentID: it.ProposedEnvironmentID,
			ProvenanceKey:         plan.SourceID("machine-role-grant", machineName, it.ProposedName),
		})
	}
	return out
}

// anyCreate reports whether items contains at least one Create-outcome entry.
func anyCreate(items []Item) bool {
	for _, it := range items {
		if it.Outcome == Create {
			return true
		}
	}
	return false
}

// BuildAppRoleItems maps every AppRole role to a machine identity (ADR-114: AppRole → machine
// identity, exact — the credential itself is never migrated, see apply-access's fresh-token
// issuance) plus role grants derived from its token_policies.
func BuildAppRoleItems(roles []healthscan.AppRoleRoleConfig, allPolicies []healthscan.Policy, mapper *PathMapper) []Item {
	byName := policiesByName(allPolicies)
	var items []Item
	for _, role := range roles {
		ref := fmt.Sprintf("approle:%s", role.Name)
		roleItems := BuildPolicyItems(resolveAttachedPolicies(role.TokenPolicies, byName), mapper)
		if !anyCreate(roleItems) {
			// Nothing this role's policies produced is mappable (or it had no non-default
			// policies at all) — there is no grant for a machine identity to hold, so none is
			// proposed. Every Unmappable row from roleItems still surfaces in the report.
			items = append(items, roleItems...)
			continue
		}
		machineName := sanitizeIdentityName("vault-approle", role.Name)
		items = append(items, Item{
			Kind: KindMachineIdentity, Outcome: Create, SourceRef: ref,
			ProposedName:         machineName,
			ProposedIdentityType: "service",
			ProvenanceKey:        plan.SourceID("approle", role.Mount, role.Name),
		})
		items = append(items, machineRoleGrantItems(roleItems, machineName, ref)...)
	}
	return items
}

// BuildKubernetesItems maps every Kubernetes auth role to one machine identity + OIDC binding
// per CONCRETE (namespace, service-account-name) pair it's bound to (ADR-114: exact for a
// single pair, approximate-round-down — one identity per pair — for a role bound to several).
// issuer is the Vault k8s auth config's issuer URL that this cluster's projected service-account
// tokens actually carry as `iss` — Vault's own kubernetes-auth config does NOT store an
// OIDC-discoverable issuer URL (it stores a CA bundle and review-JWT instead), so this cannot be
// read out of Vault; the operator must supply it (--k8s-issuer). Every role is reported
// Unmappable, category wildcard-identity, when issuer is empty — never guessed at or left blank
// on a created binding.
func BuildKubernetesItems(roles []healthscan.KubernetesAuthRoleConfig, allPolicies []healthscan.Policy, mapper *PathMapper, issuer string) []Item {
	byName := policiesByName(allPolicies)
	var items []Item
	for _, role := range roles {
		roleRef := fmt.Sprintf("k8s-auth:%s", role.Name)

		if issuer == "" {
			items = append(items, Item{Kind: KindOIDCBinding, Outcome: Unmappable, SourceRef: roleRef,
				Category: CategoryWildcardIdentity,
				Reason:   "no --k8s-issuer supplied — Vault's Kubernetes auth config has no OIDC-discoverable issuer URL to read, so this tool cannot build a binding without the operator supplying the cluster's actual token issuer",
			})
			continue
		}

		hasWildcard := containsLiteral(role.BoundServiceAccountNames, "*") || containsLiteral(role.BoundServiceAccountNamespaces, "*")
		if hasWildcard {
			items = append(items, Item{Kind: KindOIDCBinding, Outcome: Unmappable, SourceRef: roleRef,
				Category: CategoryWildcardIdentity,
				Reason:   `bound_service_account_names/namespaces contains "*" — a Keyorix OIDC binding names one exact subject, and this tool has no Kubernetes API access to enumerate which service accounts actually exist in the cluster. Migrate the specific SAs you want individually: create a machine identity + OIDC binding for each, granting it this role's token_policies.`,
			})
			continue
		}

		for _, ns := range role.BoundServiceAccountNamespaces {
			for _, name := range role.BoundServiceAccountNames {
				saRef := fmt.Sprintf("%s sa:%s/%s", roleRef, ns, name)
				roleItems := BuildPolicyItems(resolveAttachedPolicies(role.TokenPolicies, byName), mapper)
				if !anyCreate(roleItems) {
					// Same reasoning as BuildAppRoleItems: nothing to grant means no identity
					// or binding is proposed either. Unmappable rows still surface.
					items = append(items, roleItems...)
					continue
				}
				machineName := sanitizeIdentityName("vault-k8s", role.Name+"-"+ns+"-"+name)
				items = append(items, Item{
					Kind: KindMachineIdentity, Outcome: Create, SourceRef: saRef,
					ProposedName:         machineName,
					ProposedIdentityType: "k8s",
					ProvenanceKey:        plan.SourceID("k8s-auth", role.Mount, role.Name, ns, name),
				})
				items = append(items, Item{
					Kind: KindOIDCBinding, Outcome: Create, SourceRef: saRef,
					ProposedMachineRef:  machineName,
					ProposedOIDCIssuer:  issuer,
					ProposedOIDCSubject: fmt.Sprintf("system:serviceaccount:%s:%s", ns, name),
					ProvenanceKey:       plan.SourceID("k8s-oidc-binding", issuer, ns, name),
				})
				items = append(items, machineRoleGrantItems(roleItems, machineName, saRef)...)
			}
		}
	}
	return items
}

func containsLiteral(values []string, want string) bool {
	return slices.Contains(values, want)
}

// BuildUserpassItems always reports Unmappable (ADR-114: userpass passwords are never
// extractable or portable) with each user's attached policies surfaced as a human-review
// recommendation, never migrated as a credential.
func BuildUserpassItems(users []healthscan.UserpassUserConfig) []Item {
	items := make([]Item, 0, len(users))
	for _, u := range users {
		items = append(items, Item{
			Kind: KindMachineIdentity, Outcome: Unmappable, SourceRef: fmt.Sprintf("userpass:%s/%s", u.Mount, u.Username),
			Category: CategoryUserpass,
			Reason:   fmt.Sprintf("userpass credentials are not extractable or portable and are never migrated; attached policies %v — consider a Keyorix user account (or SSO) with an equivalent role", u.TokenPolicies),
		})
	}
	return items
}
