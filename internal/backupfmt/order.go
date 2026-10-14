// Package backupfmt implements the backend-neutral logical backup/restore
// format (design-b3-backup-v2.md §3): a model-registry-driven table walk,
// NDJSON row encoding, the manifest, and restore ordering.
package backupfmt

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"gorm.io/gorm/schema"

	"github.com/keyorixhq/keyorix/internal/storage"
)

// refOverride names the target model type for one (owning model, field name)
// pair whose field name does not resolve to its referenced model by the
// XxxID naming convention (see resolveReference's doc comment). Kept small
// and explicit deliberately -- design-b3-backup-v2.md §3.4's own decision
// (Andrei, 2026-09-28): a short list of exceptions, not a hand-maintained
// list of every table. TestRestoreOrder_EveryReferenceFieldIsClassified
// fails if any entry here no longer names a real model/field pair (a stale
// override), and separately fails if any ID-shaped field exists that this
// list, notReferences, and the naming convention all fail to classify.
type refOverride struct {
	Model string // owning model's Go type name, e.g. "ShareRecord"
	Field string // field name on that model, e.g. "OwnerID"
	Refs  string // referenced model's Go type name, e.g. "User"
}

var referenceOverrides = []refOverride{
	{"AccessRequest", "SecretID", "SecretNode"}, // nil for a project/role request
	{"AccessRequestApproval", "ApproverID", "User"},
	{"AccessRequestApproval", "RequestID", "AccessRequest"},
	{"AccessReviewItem", "CampaignID", "AccessReviewCampaign"},
	{"AccessReviewItem", "SecretID", "SecretNode"}, // 0 unless the snapshotted grant is secret-scoped
	{"APICallLog", "ClientID", "APIClient"},        // APIClient.ID, not APIClient.ClientID (a string public id)
	{"APIToken", "ClientID", "APIClient"},
	{"AuditCheckpoint", "HeadID", "AuditEvent"}, // the AuditEvent this checkpoint certifies (§3.4: checkpoint after the events it certifies)
	{"DynamicSecretLease", "ConfigID", "DynamicSecretConfig"},
	{"ExternalIdentity", "ProviderID", "IdentityProvider"},
	{"RateLimit", "ClientID", "APIClient"},
	{"SecretACL", "SecretID", "SecretNode"},
	{"SecretDependency", "DependentSecretID", "SecretNode"},
	{"SecretDependency", "DependsOnSecretID", "SecretNode"},
	{"SecretNode", "OwnerID", "User"}, // 0 when the creator was a machine identity (see OwnerMachineIdentityID)
	{"SecretVersionComment", "SecretID", "SecretNode"},
	{"SecretVersionComment", "VersionID", "SecretVersion"},
	{"SetupToken", "InvitationID", "ProjectInvitation"},
	{"ShareRecord", "OwnerID", "User"},
	{"ShareRecord", "SecretID", "SecretNode"},
}

// notReferences lists (model, field) pairs that look ID-shaped (an
// unsigned-integer field whose name ends in "ID") but are NOT a row
// reference to another table -- an external identifier, a provider ID, or
// similar. Restore ordering ignores these; they never become a graph edge.
type notReferenceField struct {
	Model string
	Field string
}

var notReferences = []notReferenceField{
	// PrincipalID is polymorphic: PrincipalType (User/Group/MachineIdentity)
	// discriminates which table it actually references -- no single target
	// to derive an ordering edge from. Not enforced by restore's
	// dangling-reference check either, for the same reason.
	{"AccessReviewItem", "PrincipalID"},
	// RecipientID is polymorphic: IsGroup discriminates User vs Group.
	{"ShareRecord", "RecipientID"},
	// LoginAttemptID is a WEAK pointer to the per-IP login-budget slot (a
	// login_attempts row) the login flow reserved and kept (#2956). That
	// table is a prunable rate-limit ledger, not data: a delivered login
	// releases the slot by deleting its row (LoginCompletion.Succeeded ->
	// ReleaseLoginAttempt), and the age prune and admin clear-login-lockout
	// delete rows too, while the single-use challenge / ceremony row keeps
	// its pointer. Releasing a missing id is already a no-op, so a dangling
	// value is a legal state, not corruption -- enforcing it made restore
	// refuse every backup taken after one delivered MFA or passkey login
	// (DR-FIX-1, TestBackupRestore_AfterDelivered* in server/http/handlers).
	{"MFAChallenge", "LoginAttemptID"},
	{"WebAuthnSession", "LoginAttemptID"},
}

// selfReferenceFields lists (model, field) pairs that reference a row in the
// OWNING model's own table (e.g. SecretNode.ParentID) -- design's decision:
// these are not cycles, they're within-table ordering (insert parents before
// children within the same table's own NDJSON section), so they never
// produce a cross-table graph edge either.
type selfReferenceField struct {
	Model string
	Field string
}

var selfReferences = []selfReferenceField{
	{"SecretNode", "ParentID"},
}

// classifiedField is one ID-shaped field found on a model, together with
// how it was classified.
type classifiedField struct {
	Model string
	Field string
	// Refs is the referenced model's Go type name, "" for a self-reference
	// or a not-a-reference field.
	Refs         string
	SelfRef      bool
	NotReference bool
}

// modelTypeNames returns AllModels()'s Go type names in registry order,
// e.g. "SecretNode" for &models.SecretNode{}.
func modelTypeNames() []string {
	all := storage.AllModels()
	names := make([]string, len(all))
	for i, m := range all {
		names[i] = reflect.TypeOf(m).Elem().Name()
	}
	return names
}

// isUnsignedIntKind reports whether k is uint or any sized unsigned variant
// GORM accepts for a primary/foreign key column.
func isUnsignedIntKind(k reflect.Kind) bool {
	switch k {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

// idShapedFields returns every field on m (by Go struct type name) that
// looks like a row reference: an unsigned integer (or pointer to one) whose
// field name ends in "ID", EXCLUDING the field literally named "ID" itself
// (the primary key, never a reference to another row).
func idShapedFields(m any) []string {
	t := reflect.TypeOf(m).Elem()
	var out []string
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		if f.Name == "ID" {
			continue
		}
		if !strings.HasSuffix(f.Name, "ID") {
			continue
		}
		k := f.Type.Kind()
		if k == reflect.Pointer {
			k = f.Type.Elem().Kind()
		}
		if !isUnsignedIntKind(k) {
			continue
		}
		out = append(out, f.Name)
	}
	return out
}

// resolveByConvention finds the referenced model's Go type name for field:
// strip field's trailing "ID"; if the remainder ENDS WITH a candidate type
// name, that candidate is the reference (handles "OwnerMachineIdentityID" ->
// remainder "OwnerMachineIdentity" ends with "MachineIdentity"). Ties are
// broken by preferring the LONGEST matching candidate name (most specific
// match). Returns "", false if no candidate matches.
//
// The reverse direction (a candidate name that ends with the remainder,
// e.g. "ConfigID" -> "DynamicSecretConfig") is deliberately NOT a
// convention match: it guesses which longer name the field abbreviates, and
// guessed wrong for every "SecretID" field (#3078) -- there is no "Secret"
// model, so it picked "MFASecret" over the real target "SecretNode", and
// restore's dangling-reference check then validated secret references
// against mfa_secrets. A field whose remainder does not name its model in
// full is unresolved here, so TestRestoreOrder_EveryReferenceFieldIsClassified
// fails until it is listed in referenceOverrides by hand.
func resolveByConvention(field string, candidates []string) (string, bool) {
	remainder := strings.TrimSuffix(field, "ID")
	if remainder == "" {
		return "", false
	}

	best := ""
	for _, c := range candidates {
		if strings.HasSuffix(remainder, c) && len(c) > len(best) {
			best = c
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// classifyAll walks every model in registry order and classifies every
// ID-shaped field it finds, via (in priority order) selfReferences,
// notReferences, referenceOverrides, then the naming convention. Returns the
// classifications and a list of fields none of those could classify.
func classifyAll() (classified []classifiedField, unresolved []string) {
	all := storage.AllModels()
	names := modelTypeNames()

	selfSet := make(map[[2]string]bool, len(selfReferences))
	for _, s := range selfReferences {
		selfSet[[2]string{s.Model, s.Field}] = true
	}
	notRefSet := make(map[[2]string]bool, len(notReferences))
	for _, n := range notReferences {
		notRefSet[[2]string{n.Model, n.Field}] = true
	}
	overrideSet := make(map[[2]string]string, len(referenceOverrides))
	for _, o := range referenceOverrides {
		overrideSet[[2]string{o.Model, o.Field}] = o.Refs
	}

	for i, m := range all {
		modelName := names[i]
		for _, field := range idShapedFields(m) {
			key := [2]string{modelName, field}
			switch {
			case selfSet[key]:
				classified = append(classified, classifiedField{Model: modelName, Field: field, SelfRef: true})
			case notRefSet[key]:
				classified = append(classified, classifiedField{Model: modelName, Field: field, NotReference: true})
			case overrideSet[key] != "":
				classified = append(classified, classifiedField{Model: modelName, Field: field, Refs: overrideSet[key]})
			default:
				if refs, ok := resolveByConvention(field, names); ok {
					classified = append(classified, classifiedField{Model: modelName, Field: field, Refs: refs})
				} else {
					unresolved = append(unresolved, fmt.Sprintf("%s.%s", modelName, field))
				}
			}
		}
	}
	sort.Strings(unresolved)
	return classified, unresolved
}

// ClassifiedField is classifyAll's exported counterpart -- what a caller
// outside this package needs to generically populate one row per model (the
// core property test, design §11.1) without duplicating classifyAll's own
// override/convention logic: for every ID-shaped field, whether it's a
// cross-table reference (and to which model), a self-reference, or not a
// reference at all.
type ClassifiedField struct {
	Model        string
	Field        string
	Refs         string // referenced model's Go type name; "" if SelfRef or NotReference
	SelfRef      bool
	NotReference bool
}

// ClassifiedFields exposes classifyAll()'s result: every ID-shaped field on
// every model in storage.AllModels(), classified. unresolved is always empty
// in a passing build -- RestoreOrder() itself refuses to run otherwise -- but
// is still returned so a caller can fail loudly rather than silently ignore
// an unclassified field if this is ever called before that invariant holds.
func ClassifiedFields() (classified []ClassifiedField, unresolved []string) {
	internal, unresolved := classifyAll()
	classified = make([]ClassifiedField, len(internal))
	for i, c := range internal {
		classified[i] = ClassifiedField(c)
	}
	return classified, unresolved
}

// RestoreOrder returns AllModels()'s Go type names ordered so that every
// model referenced by another model's field (per classifyAll) is inserted
// before the model that references it -- a topological sort of the
// dependency graph derived above (design-b3-backup-v2.md §3.4). Returns an
// error naming the cycle if the derived graph is not a DAG (should not
// happen for real schema references; a cycle here means an override or the
// naming convention misclassified something).
func RestoreOrder() ([]string, error) {
	classified, unresolved := classifyAll()
	if len(unresolved) > 0 {
		return nil, fmt.Errorf("restore ordering: %d ID-shaped field(s) not classified as a reference, override, "+
			"self-reference, or not-a-reference: %s", len(unresolved), strings.Join(unresolved, ", "))
	}

	names := modelTypeNames()
	inDegree := make(map[string]int, len(names))
	edges := make(map[string][]string, len(names)) // referenced -> [dependents]
	for _, n := range names {
		inDegree[n] = 0
	}
	seenEdge := make(map[[2]string]bool)
	for _, c := range classified {
		if c.Refs == "" {
			continue
		}
		if c.Refs == c.Model {
			continue // self-reference by convention match, not flagged via selfReferences
		}
		key := [2]string{c.Refs, c.Model}
		if seenEdge[key] {
			continue
		}
		seenEdge[key] = true
		edges[c.Refs] = append(edges[c.Refs], c.Model)
		inDegree[c.Model]++
	}

	// Kahn's algorithm, deterministic: process the ready set in registry
	// order every round, not map iteration order, so RestoreOrder's result
	// (and therefore the archive's physical table layout) is stable across
	// runs/builds -- required since restore replays this exact order and the
	// manifest's per-table hash covers exactly this sequence (§3.3).
	ready := make([]string, 0, len(names))
	for _, n := range names {
		if inDegree[n] == 0 {
			ready = append(ready, n)
		}
	}
	var order []string
	for len(ready) > 0 {
		next := ready[0]
		ready = ready[1:]
		order = append(order, next)
		var newlyReady []string
		for _, dep := range edges[next] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				newlyReady = append(newlyReady, dep)
			}
		}
		// Preserve registry order among newly-ready nodes.
		if len(newlyReady) > 0 {
			nrSet := make(map[string]bool, len(newlyReady))
			for _, n := range newlyReady {
				nrSet[n] = true
			}
			for _, n := range names {
				if nrSet[n] {
					ready = append(ready, n)
				}
			}
		}
	}

	if len(order) != len(names) {
		var stuck []string
		for _, n := range names {
			if inDegree[n] > 0 {
				stuck = append(stuck, n)
			}
		}
		sort.Strings(stuck)
		return nil, fmt.Errorf("restore ordering: dependency graph has a cycle involving: %s", strings.Join(stuck, ", "))
	}
	return order, nil
}

// modelsByTypeName returns storage.AllModels()'s entries keyed by their Go
// type name, e.g. "SecretNode" -> &models.SecretNode{} -- the same
// registry, just index-able by the names RestoreOrder() returns.
func modelsByTypeName() map[string]any {
	all := storage.AllModels()
	names := modelTypeNames()
	out := make(map[string]any, len(all))
	for i, m := range all {
		out[names[i]] = m
	}
	return out
}

// modelsInOrder maps RestoreOrder()'s Go-type-name sequence back to the
// actual model instances, in that same sequence -- what the table-walk
// writer (writer.go) actually needs to drive.
func modelsInOrder(order []string) []any {
	byName := modelsByTypeName()
	out := make([]any, len(order))
	for i, name := range order {
		out[i] = byName[name]
	}
	return out
}

// schemaCache is shared across every schema.Parse call in this package --
// gorm's own recommended usage (avoids re-parsing the same struct tags on
// every call) and required for schema.Parse's signature regardless.
var schemaCache sync.Map

// parseSchema parses m's GORM schema using the default (unconfigured)
// naming strategy -- the same one every gorm.Open call in internal/storage
// uses (factory.go's gormConfig sets no custom NamingStrategy), so table
// and column names resolved here are byte-identical to what migrateDatabase
// actually created, including any model's own custom TableName() override
// (e.g. SoDPolicy, MachineIdentityOIDCBinding).
func parseSchema(m any) (*schema.Schema, error) {
	return schema.Parse(m, &schemaCache, schema.NamingStrategy{})
}

// referenceEdge is one classified cross-table reference, resolved from Go
// type/field names (classifiedField) down to actual table/column names --
// what CheckDanglingReferences (checks.go) needs to build real SQL, and
// what a caller wanting the archive's physical table order can get from
// RestoreOrder() directly without needing this resolution at all.
type referenceEdge struct {
	ChildTable  string
	ChildColumn string
	ParentTable string
	// ChildHasIDColumn is false for the small set of composite-primary-key
	// join tables (RolePermission, UserRole, GroupRole, UserGroup) that have
	// no single "id" column at all -- CheckDanglingReferences (checks.go)
	// needs a backend-specific fallback for identifying a row in those,
	// since "id" doesn't exist to select there on either backend.
	ChildHasIDColumn bool
}

// referenceEdges resolves classifyAll()'s classified cross-table references
// (skipping self-references and not-a-reference fields) to real table and
// column names via parseSchema.
func referenceEdges() ([]referenceEdge, error) {
	classified, unresolved := classifyAll()
	if len(unresolved) > 0 {
		return nil, fmt.Errorf("cannot resolve reference edges: %d ID-shaped field(s) unclassified: %s",
			len(unresolved), strings.Join(unresolved, ", "))
	}

	byName := modelsByTypeName()
	schemas := make(map[string]*schema.Schema, len(byName))
	for name, m := range byName {
		s, err := parseSchema(m)
		if err != nil {
			return nil, fmt.Errorf("parse schema for %s: %w", name, err)
		}
		schemas[name] = s
	}

	var edges []referenceEdge
	for _, c := range classified {
		if c.Refs == "" || c.Refs == c.Model {
			continue
		}
		childSchema := schemas[c.Model]
		field := childSchema.LookUpField(c.Field)
		if field == nil {
			return nil, fmt.Errorf("field %s.%s not found in parsed schema", c.Model, c.Field)
		}
		parentSchema, ok := schemas[c.Refs]
		if !ok {
			return nil, fmt.Errorf("referenced model %q (from %s.%s) not found in registry", c.Refs, c.Model, c.Field)
		}
		edges = append(edges, referenceEdge{
			ChildTable:       childSchema.Table,
			ChildColumn:      field.DBName,
			ParentTable:      parentSchema.Table,
			ChildHasIDColumn: childSchema.LookUpField("ID") != nil,
		})
	}
	return edges, nil
}
