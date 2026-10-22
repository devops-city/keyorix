package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/keyorixhq/keyorix/internal/connect/connecttypes"
)

// ConnectConfig configures read-through federation to external secret stores
// (ADR-043). Opt-in: with no connectors (or Enabled false) the /connect API is off.
type ConnectConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Connectors []ConnectorConfig `yaml:"connectors"`
}

// ConnectorConfig describes one external-store connector. Name is the API path key
// (unique); Type selects the backend ("aws-secrets-manager"); Region is the backend
// region where applicable. Credentials come from the backend's ambient identity
// chain, never from here.
type ConnectorConfig struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Region string `yaml:"region"`
	// Address is the backend base URL: the Vault server for type "vault"
	// (e.g. https://vault:8200), or the Key Vault URL for type "azure-key-vault"
	// (e.g. https://myvault.vault.azure.net/).
	Address string `yaml:"address"`
	// ProjectID pins a "gcp-secret-manager" connector to a single GCP project (#431):
	// every ref must embed this exact project ID
	// (projects/PROJECT/secrets/NAME/versions/VERSION), or the read is rejected before
	// reaching the backend. Unlike Address for "vault"/"azure-key-vault", a GCP ref
	// carries its own project ID, so leaving this unset would let a single connector
	// (and the ambient ADC identity it runs under) address secrets in ANY project
	// that identity can reach, regardless of this connector's Keyorix-side tenant
	// scope (a confused-deputy gap). Required, unconditionally, for every
	// "gcp-secret-manager" connector — validateConnectGCPProjectID (below) fails
	// boot on an unset value, with no deployment-wide escape hatch, mirroring how
	// Scope has none. An existing deployment upgrading past this change must add
	// project_id to every gcp-secret-manager connector first (see CHANGELOG.md).
	// Unrelated to Project below — this is a GCP-side identifier, Project is Keyorix's.
	ProjectID string `yaml:"project_id"`
	// AccountID optionally pins an "aws-secrets-manager" connector to a single AWS
	// account: an ARN-shaped ref naming a DIFFERENT account is rejected before the
	// backend call. Unlike ProjectID above, this is NOT required: a bare secret-name
	// ref (the common shape) is always resolved within the ambient credential's own
	// AWS account by the Secrets Manager API itself, so it never carries a competing
	// account to check, and a full-ARN ref naming another account additionally
	// requires that target account's own resource policy to have separately granted
	// cross-account access (a double opt-in, unlike GCP's single-opt-in
	// ambient-reach gap — see internal/connect/awssm.go's doc comment). When set,
	// validateConnectAWSAccountID (below) fails boot if it is not exactly 12 digits
	// (the AWS account ID format); when unset, server/main.go logs a startup
	// recommendation but boots — a deliberate phase-in, not a bug: making this
	// mandatory would force every connector that only ever reads bare-name refs
	// (which cannot cross accounts regardless) to configure a field with zero
	// enforcement value for them.
	AccountID string `yaml:"account_id"`
	// TokenEnv names the environment variable holding the backend token for type
	// "vault" (default "VAULT_TOKEN"). The token is read from the environment, never
	// from this file.
	TokenEnv string `yaml:"token_env"`
	// AllowedRefs, when non-empty, restricts which secret references this connector
	// may read: a requested ref must have one of these prefixes (a defense-in-depth
	// guardrail in Keyorix's layer, on top of the backend identity's IAM policy). An
	// empty list places no restriction here — the backend IAM scope is then the only
	// bound, so prefer setting both.
	AllowedRefs []string `yaml:"allowed_refs"`
	// Scope declares this connector's tenant boundary (ADR-082): "project" (owned by
	// exactly one Keyorix project — requires Project) or "platform" (org-wide; requires
	// the connect.platform.use permission at authorization time, must NOT set Project).
	// Required, unconditionally: a missing or unrecognized value (anything other than
	// "project"/"platform") always fails boot. There is no escape hatch — an operator
	// migrating an existing config adds scope: to every connector before upgrading; see
	// ADR-082 §C for why that boot-fail-loud requirement has no deployment-wide bypass.
	Scope string `yaml:"scope"`
	// Project names the Keyorix project that owns this connector, by NAME — not a
	// numeric ID. A numeric project ID differs per deployment (the same logical project
	// has a different row ID in every install's database), which would break config
	// portability across environments and air-gap bundles; a name travels with the
	// config unchanged. Required when Scope is "project"; must be empty when Scope is
	// "platform" (a platform connector is not owned by any single project — setting
	// both is a contradiction, and fails boot). This branch only checks presence — the
	// name is resolved to a real project ID at boot in a later branch (ADR-082 §A/§D);
	// an unresolvable name fails boot at that point, not here.
	Project string `yaml:"project"`
	// Environment optionally further scopes a "project"-scoped connector to one
	// environment within Project, by name. Reserved (ADR-082 §G): accepted and stored,
	// but NOT enforced — every environment within Project is currently treated
	// identically for authorization purposes regardless of this field. Enforcement
	// semantics are a real design question deferred to a follow-up ADR, not decided
	// here.
	Environment string `yaml:"environment"`
}

// validateConnectTypes enforces #1476: every cfg.Connect.Connectors entry's Type
// must be one of connecttypes.KnownTypes, the single source of truth for recognized
// connector types (see that var's own doc comment for why server/main.go's
// dispatch switch stays a literal switch rather than deriving from this list, and
// how the two are kept from drifting apart). Runs BEFORE validateConnectScopes:
// an unrecognized type is a more fundamental problem than a scope-shape issue on
// a connector Keyorix would never actually construct. Aggregates every offending
// connector into one error, mirroring validateConnectScopes's own aggregation —
// an operator fixing config should not have to restart-and-discover connectors
// one at a time.
//
// This closes the same fail-open shape ADR-082 closed for scope: server/main.go's
// Connect-wiring switch used to silently skip (log.Printf, keep booting) a
// connector whose Type matched no case label — see the v0.92.0 CHANGELOG entry.
func validateConnectTypes(cc ConnectConfig) error {
	known := make(map[string]bool, len(connecttypes.KnownTypes))
	for _, t := range connecttypes.KnownTypes {
		known[t] = true
	}
	var invalid []string
	for _, connector := range cc.Connectors {
		if !known[connector.Type] {
			invalid = append(invalid, fmt.Sprintf("%s (type: %q)", connector.Name, connector.Type))
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("connect: connector(s) with unrecognized type (must be one of %s): %s",
			strings.Join(connecttypes.KnownTypes, ", "), strings.Join(invalid, ", "))
	}
	return nil
}

// validateConnectScopes enforces ADR-082 §B/§C on cfg.Connect.Connectors — pure
// config-shape validation, no DB/network access, no logging. Every check aggregates
// across ALL offending connectors into one error naming each by config name, rather
// than failing on (and hiding) the first one found — an operator fixing config
// should not have to restart-and-discover connectors one at a time. There is no
// deployment-wide escape hatch (ADR-082 §C, amended): a missing scope fails boot
// unconditionally, the same as an unrecognized value — the migration path for an
// existing deployment is to add scope: to every connector, not to opt out of the
// check. Checks run in this order, each independent of the others by construction
// (a connector can only land in one bucket): unrecognized scope, missing scope,
// scope "project" without a Project name, scope "platform" with a Project name set
// (a platform connector is not owned by any single project).
func validateConnectScopes(cc ConnectConfig) error {
	var missing, invalid, projectNeedsProject, platformRejectsProject []string
	for _, connector := range cc.Connectors {
		switch connector.Scope {
		case "":
			missing = append(missing, connector.Name)
		case "project":
			if connector.Project == "" {
				projectNeedsProject = append(projectNeedsProject, connector.Name)
			}
		case "platform":
			if connector.Project != "" {
				platformRejectsProject = append(platformRejectsProject, connector.Name)
			}
		default:
			invalid = append(invalid, connector.Name)
		}
	}

	if len(invalid) > 0 {
		return fmt.Errorf("connect: connector(s) with unrecognized scope (must be \"project\" or \"platform\"): %s", strings.Join(invalid, ", "))
	}
	if len(missing) > 0 {
		return fmt.Errorf("connect: connector(s) missing required \"scope\" (must be \"project\" or \"platform\" — ADR-082, no exceptions): %s", strings.Join(missing, ", "))
	}
	if len(projectNeedsProject) > 0 {
		return fmt.Errorf("connect: connector(s) with scope \"project\" missing required \"project\": %s", strings.Join(projectNeedsProject, ", "))
	}
	if len(platformRejectsProject) > 0 {
		return fmt.Errorf("connect: connector(s) with scope \"platform\" must not set \"project\" (a platform connector is not owned by any single project): %s", strings.Join(platformRejectsProject, ", "))
	}
	return nil
}

// validateConnectGCPProjectID closes a confused-deputy gap in the
// "gcp-secret-manager" connector: unlike the Vault/Azure Address (the backend's own
// base URL — the connector IS the tenant boundary), a GCP Secret Manager ref carries
// its own project ID embedded in the resource name
// (projects/PROJECT/secrets/NAME/versions/VERSION). validateConnectScopes above
// already binds a connector to a Keyorix-side tenant (project/platform scope), but
// that says nothing about which GCP project the ambient ADC identity actually
// reaches — a connector scoped to Keyorix project X with no project_id set would
// let any connect.read-holding caller in project X's scope read a secret from GCP
// project Y (or any other project the ADC identity can reach), as long as the
// backend IAM happens to allow it. project_id (#431) is the only thing that pins
// the GCP-side project to match the Keyorix-side scope, so — like Scope above — it
// is required unconditionally, with no deployment-wide escape hatch: a missing
// project_id fails boot for every "gcp-secret-manager" connector, aggregated into
// one error naming every offending connector by name (mirrors validateConnectScopes's
// own aggregation style). Only connectors of type "gcp-secret-manager" are checked;
// other types have their own binding field (Address) which is enforced separately.
func validateConnectGCPProjectID(cc ConnectConfig) error {
	var missing []string
	for _, connector := range cc.Connectors {
		if connector.Type == "gcp-secret-manager" && connector.ProjectID == "" {
			missing = append(missing, connector.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("connect: gcp-secret-manager connector(s) missing required \"project_id\" — an unset project_id lets a caller read secrets from ANY GCP project the ambient ADC identity can reach, regardless of this connector's Keyorix tenant scope (a confused-deputy gap; #431/ADR-082): %s", strings.Join(missing, ", "))
	}
	return nil
}

// awsAccountIDPattern is the AWS account ID format: exactly 12 digits.
var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// validateConnectAWSAccountID checks the OPTIONAL account_id pin on
// "aws-secrets-manager" connectors — the AWS sibling of
// validateConnectGCPProjectID above, but deliberately NOT a mandatory-field check:
// see ConnectorConfig.AccountID's own doc comment and internal/connect/awssm.go for
// why AWS's confused-deputy risk shape is narrower than GCP's (a bare secret-name
// ref, the common case, can never cross AWS accounts at all; a full-ARN ref naming
// another account additionally requires that account's own resource policy to have
// separately granted access — a double opt-in). Because the field is optional, this
// only ever rejects a connector that DID set account_id but set it to something that
// is not a well-formed AWS account ID (exactly 12 digits) — catching a typo at boot
// rather than at first read. A missing account_id is not an error here; server/main.go
// logs a startup recommendation for that case instead (mirroring the phase-in
// idiom GCP's project_id itself used before it became mandatory). Aggregates every
// offending connector into one error, mirroring validateConnectGCPProjectID's own
// aggregation style.
func validateConnectAWSAccountID(cc ConnectConfig) error {
	var malformed []string
	for _, connector := range cc.Connectors {
		if connector.Type != "aws-secrets-manager" || connector.AccountID == "" {
			continue
		}
		if !awsAccountIDPattern.MatchString(connector.AccountID) {
			malformed = append(malformed, fmt.Sprintf("%s (account_id: %q)", connector.Name, connector.AccountID))
		}
	}
	if len(malformed) > 0 {
		return fmt.Errorf("connect: aws-secrets-manager connector(s) with malformed \"account_id\" (must be exactly 12 digits, the AWS account ID format): %s", strings.Join(malformed, ", "))
	}
	return nil
}

// validateConnectSection checks connect.connectors: types, scopes, GCP project IDs and AWS account IDs
// (Validate step).
func validateConnectSection(c *Config) error {
	if err := validateConnectTypes(c.Connect); err != nil {
		return err
	}

	if err := validateConnectScopes(c.Connect); err != nil {
		return err
	}

	if err := validateConnectGCPProjectID(c.Connect); err != nil {
		return err
	}

	if err := validateConnectAWSAccountID(c.Connect); err != nil {
		return err
	}
	return nil
}
