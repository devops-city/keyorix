package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// isNotFoundStorageErr reports whether err is a "not found"-substring error, the
// convention every LocalStorage Get* method in this codebase uses (see
// local_secrets.go's GetProject).
func isNotFoundStorageErr(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// resolveConnectorOwnership resolves each connector's tenant-scoping data
// (ADR-082 §A/§E) from its config entry. A "platform"-scoped connector needs no
// resolution. A "project"-scoped connector's project: name is pinned to a real
// Keyorix project ID via ConnectorProjectBinding, never re-resolved by name on a
// later boot — see that model's own doc comment for why (project names are
// mutable and a soft-deleted project's name is freed for reuse, so re-resolving
// by name every boot would let an ordinary rename silently reassign ownership):
//
//   - First boot for a connector (no binding row yet): resolve config's project:
//     name to a project via storage.GetProjectByName, persist the binding.
//   - A later boot (binding row exists): resolve the project by the STORED ID
//     (storage.GetProject), never by name. If that project no longer exists
//     (deleted), or its CURRENT name no longer matches the name recorded in the
//     binding at first-boot time, this fails boot — a rename or delete is
//     something server/main.go treats as requiring deliberate operator action,
//     not something to silently follow or silently ignore.
//
// Every problem across every connector is collected into ONE aggregated error
// (branch 1's validateConnectScopes style), naming each offending connector and
// its specific reason, rather than failing on the first one found.
func resolveConnectorOwnership(ctx context.Context, st corestorage.Storage, connectors []config.ConnectorConfig) (map[string]core.ConnectOwnership, error) {
	ownership := make(map[string]core.ConnectOwnership, len(connectors))
	var problems []string
	for _, cn := range connectors {
		if cn.Scope == "platform" {
			ownership[cn.Name] = core.ConnectOwnership{Scope: "platform"}
			continue
		}
		// cn.Scope == "project" here: internal/config.validateConnectScopes already
		// guaranteed no other value reached boot (amended — there is no longer an
		// allow_unscoped bypass; a missing or unrecognized scope always fails boot
		// before this function is ever reached).
		binding, err := st.GetConnectorProjectBinding(ctx, cn.Name)
		switch {
		case err != nil && isNotFoundStorageErr(err):
			// First boot for this connector: resolve name -> ID, persist.
			project, perr := st.GetProjectByName(ctx, cn.Project)
			if perr != nil {
				problems = append(problems, fmt.Sprintf("%s: project %q not found: %v", cn.Name, cn.Project, perr))
				continue
			}
			created, cerr := st.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
				Connector:   cn.Name,
				ProjectID:   project.ID,
				ProjectName: project.Name,
			})
			if cerr != nil {
				problems = append(problems, fmt.Sprintf("%s: failed to persist project binding: %v", cn.Name, cerr))
				continue
			}
			auditConnectorProjectBindingCreate(ctx, st, created, "boot-time first resolution")
			ownership[cn.Name] = core.ConnectOwnership{Scope: "project", ProjectID: created.ProjectID}
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", cn.Name, err))
		default:
			// Binding exists: resolve by the stored ID, never by name.
			project, perr := st.GetProject(ctx, binding.ProjectID)
			if perr != nil {
				problems = append(problems, fmt.Sprintf("%s: bound to project id %d, which no longer exists (deleted?): %v", cn.Name, binding.ProjectID, perr))
				continue
			}
			if project.Name != binding.ProjectName {
				problems = append(problems, fmt.Sprintf(
					"%s: bound project (id %d) was renamed from %q to %q since this connector was first configured — this is a deliberate boot failure (ADR-082), not a silent reassignment; if the rename was intentional, update connect.connectors[].project to %q and clear the stale connector_project_bindings row for %q before restarting",
					cn.Name, binding.ProjectID, binding.ProjectName, project.Name, project.Name, cn.Name))
				continue
			}
			ownership[cn.Name] = core.ConnectOwnership{Scope: "project", ProjectID: binding.ProjectID}
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("connector(s) with unresolvable project binding: %s", strings.Join(problems, "; "))
	}
	return ownership, nil
}

// auditConnectorProjectBindingCreate records a ConnectorProjectBinding write
// (ADR-082 branch 3, issue #1477's audit half): the binding is an
// authorization input (it feeds core.ConnectOwnership, and from there
// connectOwnershipSatisfied) regardless of which door the write comes through.
// This unattended boot-time path was originally paired with a second call site,
// the now-deleted RemoteStorage proxy's write; source distinguishes call sites
// in the Description in case a second one is reintroduced. A logging
// failure here does not fail boot — the binding itself already persisted
// successfully — but is surfaced loudly (SECURITY-prefixed, matching
// internal/core's own emitAudit convention) since a silently-dropped audit
// write for an authorization-input change is exactly the kind of gap this
// branch exists to close.
func auditConnectorProjectBindingCreate(ctx context.Context, st corestorage.Storage, b *models.ConnectorProjectBinding, source string) {
	t := true
	event := &models.AuditEvent{
		EventType:   core.EventConnectorProjectBindingCreate,
		ProjectID:   &b.ProjectID,
		Description: fmt.Sprintf("connector project binding created (%s): connector %q bound to project %q (id %d)", source, b.Connector, b.ProjectName, b.ProjectID),
		Success:     &t,
		EventTime:   time.Now(),
		ActorType:   core.ActorTypeSystem,
	}
	if err := st.LogAuditEvent(ctx, event); err != nil {
		log.Printf("SECURITY: failed to persist audit event %q for connector %q: %v", core.EventConnectorProjectBindingCreate, b.Connector, err)
	}
}

// connectOwnershipKeySetMismatch returns every connector name whose presence in
// connect.Manager (builtNames) and in the resolved ownership map disagree — no
// exemption of any kind (amended: the prior connect.allow_unscoped-linked
// exemption is removed along with the flag, since resolveConnectorOwnership no
// longer skips any connector). A connector present in one set but not the other
// must never happen in a correctly-booted server (e.g. an unrecognized connector
// Type, which resolves ownership successfully but never makes it into the
// manager) — every divergence is reported.
func connectOwnershipKeySetMismatch(builtNames []string, ownership map[string]core.ConnectOwnership) []string {
	built := make(map[string]bool, len(builtNames))
	for _, name := range builtNames {
		built[name] = true
	}
	var mismatch []string
	for name := range built {
		if _, ok := ownership[name]; !ok {
			mismatch = append(mismatch, name)
		}
	}
	for name := range ownership {
		if !built[name] {
			mismatch = append(mismatch, name)
		}
	}
	return mismatch
}

// warnConnectConfigDrift performs two READ-ONLY, warn-only consistency checks
// after Connect's boot-time wiring (ownership) is resolved — #1477/#1479's
// boot-time drift detection. This is the only place in the system that sees
// both config (ownership, resolved from cfg.Connect.Connectors just before
// this is called) and DB rows (ConnectRefGrant, ConnectorProjectBinding)
// together, which is why it closes what the create-time checks
// (CreateConnectRefGrant, resolveConnectorOwnership's own
// CreateConnectorProjectBinding call) structurally cannot: a config edit
// AFTER a grant/binding already exists. Neither
// condition here is a security risk — a dead ref-grant already denies
// nothing extra (ReadFederatedSecret's platform branch is a terminal deny
// regardless of any grant), and an orphaned binding is simply unused, not
// over-permissive — so this warns, aggregated in ADR-082's own established
// style (one summary line naming every offender), and never fails boot.
// Scoped to when Connect's boot-wiring actually runs (cc.Enabled with at
// least one recognized connector) — a fully-disabled Connect config with
// leftover rows from a PRIOR enabled state is not covered; that is a
// narrower, separate case than the config-edit drift this targets.
func warnConnectConfigDrift(ctx context.Context, st corestorage.Storage, ownership map[string]core.ConnectOwnership) {
	if grants, err := st.ListConnectRefGrants(ctx); err != nil {
		log.Printf("Keyorix Connect: boot-time drift check: failed to list ref-grants: %v", err)
	} else {
		var dead []string
		for _, g := range grants {
			if ownership[g.Connector].Scope == "platform" {
				dead = append(dead, fmt.Sprintf("grant %d (connector %q)", g.ID, g.Connector))
			}
		}
		if len(dead) > 0 {
			log.Printf("Keyorix Connect: WARNING: %d ConnectRefGrant(s) are dead configuration — bound to a connector that now resolves to scope: platform, a terminal deny that never consults ref-grant delegation (ADR-082): %s",
				len(dead), strings.Join(dead, ", "))
		}
	}

	if bindings, err := st.ListConnectorProjectBindings(ctx); err != nil {
		log.Printf("Keyorix Connect: boot-time drift check: failed to list connector project bindings: %v", err)
	} else {
		var orphaned []string
		for _, b := range bindings {
			if _, ok := ownership[b.Connector]; !ok {
				orphaned = append(orphaned, fmt.Sprintf("%s (bound to project %q)", b.Connector, b.ProjectName))
			}
		}
		if len(orphaned) > 0 {
			log.Printf("Keyorix Connect: WARNING: %d connector project binding(s) reference a connector no longer in cfg.Connect.Connectors — orphaned by a removed or renamed connector: %s",
				len(orphaned), strings.Join(orphaned, ", "))
		}
	}
}

// wireConnect wires Keyorix Connect (ADR-043) read-through federation to
// external secret stores, when enabled — the fifth DefaultIntegrations
// component as of ADR-109 step 4 (connect behind ports). Uses
// coreService.Storage() for the boot-time ownership resolution and drift
// check below; core.NewKeyorixCore(store) always sets storage before
// DefaultIntegrations is ever called, so it is available here unconditionally.
func wireConnect(cfg *config.Config, coreService *core.KeyorixCore) error {
	cc := cfg.Connect
	if !cc.Enabled || len(cc.Connectors) == 0 {
		return nil
	}
	// ADR-082 §C: cfg.Validate() already refused to boot with a missing/invalid
	// connector scope — unconditionally, no deployment-wide escape hatch (amended:
	// the original connect.allow_unscoped flag let the server boot, but an unscoped
	// connector still denied on every read via connectOwnershipSatisfied's
	// missing-entry-denies rule, so it never restored actual usability — only
	// deferred the failure from "boot" to "every subsequent read," with a WARN an
	// operator could easily miss. Adding scope: to a connector takes minutes; there
	// is nothing for this migration path to bypass.
	var connectors []connect.Connector
	for _, cn := range cc.Connectors {
		switch cn.Type {
		case "aws-secrets-manager":
			// account_id is optional (unlike gcp-secret-manager's mandatory
			// project_id — see internal/connect/awssm.go's doc comment for why the
			// risk shape differs: a bare secret name never crosses AWS accounts, so
			// the confused-deputy gap only exists for ARN-shaped refs, and even then
			// requires the target account's own resource policy to separately grant
			// access). cfg.Validate()'s validateConnectAWSAccountID already rejected a
			// malformed (non-12-digit) account_id before this function is ever
			// reached; an empty account_id is a legal, if less-hardened,
			// configuration and boots fine, with a warning recommending it be set.
			if cn.AccountID == "" {
				log.Printf("Keyorix Connect: aws-secrets-manager connector %q has no account_id configured — a ref supplied as a full ARN naming a DIFFERENT AWS account will still succeed if that account's own resource policy grants cross-account access; set account_id to pin the connector to one account (a bare secret-name ref is unaffected either way -- Secrets Manager always resolves those within the caller's own account)", cn.Name)
			}
			conn, ok := connect.NewCloudConnector(cn.Type, connect.ConnectorParams{Name: cn.Name, Region: cn.Region, AccountID: cn.AccountID, AllowedRefs: cn.AllowedRefs})
			if !ok {
				return fmt.Errorf("connect: connector %q has type %q, which this server binary was not built with (excluded by the no%s build tag) — rebuild without -tags no%s, or remove this connector", cn.Name, cn.Type, cloudProviderTag(cn.Type), cloudProviderTag(cn.Type))
			}
			connectors = append(connectors, conn)
		case "gcp-secret-manager":
			// project_id is now a required field: unreachable via a config that
			// passed cfg.Validate() — validateConnectGCPProjectID
			// (internal/config/config.go) already refused to boot a
			// gcp-secret-manager connector with an unset project_id, before this
			// function is ever reached (see the cfg.Validate() call at the top of
			// initializeCoreService). Fail loud rather than silently construct an
			// unpinned connector if this is somehow reached anyway (e.g. a future
			// caller of this loop that bypasses Validate()) — the old behavior let an
			// unpinned connector boot with only a log warning, which is exactly the
			// confused-deputy gap this field now closes.
			if cn.ProjectID == "" {
				log.Fatalf("Keyorix Connect: gcp-secret-manager connector %q has no project_id — this should have been caught by cfg.Validate()", cn.Name)
			}
			conn, ok := connect.NewCloudConnector(cn.Type, connect.ConnectorParams{Name: cn.Name, ProjectID: cn.ProjectID, AllowedRefs: cn.AllowedRefs})
			if !ok {
				return fmt.Errorf("connect: connector %q has type %q, which this server binary was not built with (excluded by the no%s build tag) — rebuild without -tags no%s, or remove this connector", cn.Name, cn.Type, cloudProviderTag(cn.Type), cloudProviderTag(cn.Type))
			}
			connectors = append(connectors, conn)
		case "azure-key-vault":
			conn, ok := connect.NewCloudConnector(cn.Type, connect.ConnectorParams{Name: cn.Name, Address: cn.Address, AllowedRefs: cn.AllowedRefs})
			if !ok {
				return fmt.Errorf("connect: connector %q has type %q, which this server binary was not built with (excluded by the no%s build tag) — rebuild without -tags no%s, or remove this connector", cn.Name, cn.Type, cloudProviderTag(cn.Type), cloudProviderTag(cn.Type))
			}
			connectors = append(connectors, conn)
		case "vault":
			tokenEnv := cn.TokenEnv
			if tokenEnv == "" {
				tokenEnv = "VAULT_TOKEN"
			}
			token, terr0 := resolveVaultToken(tokenEnv)
			if terr0 != nil {
				return fmt.Errorf("connect: vault connector %q token: %w", cn.Name, terr0)
			}
			if token == "" {
				log.Printf("Keyorix Connect: vault connector %q has no token (%s unset) — reads will fail", cn.Name, tokenEnv)
			}
			vc := connect.NewVaultConnector(cn.Name, cn.Address, token, cn.AllowedRefs)
			if ttl, renewable, terr := vc.CheckTokenTTL(context.Background()); terr != nil {
				log.Printf("Keyorix Connect: vault connector %q: token TTL check failed: %v", cn.Name, terr)
			} else if ttl > 0 && ttl < 86400 && !renewable {
				log.Printf("Keyorix Connect: vault connector %q: token has %d seconds remaining and is NOT renewable — replace before expiry", cn.Name, ttl)
			} else if ttl > 0 && ttl < 86400 {
				log.Printf("Keyorix Connect: vault connector %q: token expires in %d seconds; ensure renewal is configured", cn.Name, ttl)
			}
			connectors = append(connectors, vc)
		default:
			// #1476: unreachable via a config that passed cfg.Validate() —
			// validateConnectTypes (internal/config/config.go) already refused
			// to boot with a connector Type outside connect.KnownTypes, before
			// this function is ever reached (see the cfg.Validate() call at the
			// top of initializeCoreService). Fail loud rather than silently
			// skip if this is somehow reached anyway (e.g. a future caller of
			// this loop that bypasses Validate()) — the old behavior let a
			// misconfigured connector boot invisibly, the same fail-open shape
			// ADR-082 closed for scope. See
			// server/connector_type_registry_test.go for the test keeping this
			// switch's case set and connect.KnownTypes from drifting apart.
			log.Fatalf("Keyorix Connect: connector %q has unrecognized type %q (must be one of %s) — this should have been caught by cfg.Validate()", cn.Name, cn.Type, strings.Join(connect.KnownTypes, ", "))
		}
	}
	if len(connectors) == 0 {
		return nil
	}
	mgr := connect.NewManager(connectors)

	// ADR-082 branch 2: resolve each connector's tenant-scoping data (project
	// binding for scope: project; nothing to resolve for scope: platform)
	// BEFORE wiring the manager in, so a resolution failure blocks boot
	// entirely rather than leaving Connect half-wired.
	ownership, err := resolveConnectorOwnership(context.Background(), coreService.Storage(), cc.Connectors)
	if err != nil {
		log.Fatalf("Keyorix Connect: %v", err)
	}

	// Defense-in-depth: ownership was resolved from the FULL cc.Connectors
	// config, but mgr was built only from connectors the type-switch above
	// actually recognized (an unrecognized type is skipped with a WARN, not a
	// hard failure — the `default` case above). If a connector's ownership
	// resolved successfully but it never made it into mgr (e.g. an
	// unrecognized type), or vice versa, that is a key-set mismatch this ADR
	// requires to fail boot loudly rather than silently deny (a missing
	// ownership entry, connectOwnershipSatisfied's own fallback) or silently
	// skip ownership entirely (a connector with no check at all). No exemption
	// of any kind (amended — the prior allow_unscoped-linked exemption is
	// removed along with the flag): every divergence between the two sets is
	// reported.
	if mismatch := connectOwnershipKeySetMismatch(mgr.Names(), ownership); len(mismatch) > 0 {
		log.Fatalf("Keyorix Connect: connector(s) present in config but whose manager/ownership resolution disagree on which connectors exist — this must never happen in a correctly-booted server; investigate before proceeding (ADR-082): %s", strings.Join(mismatch, ", "))
	}

	coreService.SetConnectManager(mgr)
	coreService.SetConnectOwnership(ownership)
	log.Printf("Keyorix Connect enabled (%d connector(s))", len(connectors))

	// #1477/#1479: warn-only consistency check, run here because this is the
	// only place in the system that sees both config (ownership, resolved
	// just above) and DB rows (ConnectRefGrant, ConnectorProjectBinding)
	// together — the create-time checks (CreateConnectRefGrant,
	// resolveConnectorOwnership's own CreateConnectorProjectBinding call
	// above) each structurally cannot see this:
	// a grant/binding valid when created can still drift out of sync with a
	// LATER config edit. Neither condition this checks is a security risk —
	// a dead ref-grant or an orphaned binding both already fail closed/are
	// simply unused, no over-permission — so this warns, never fails boot.
	warnConnectConfigDrift(context.Background(), coreService.Storage(), ownership)
	return nil
}
