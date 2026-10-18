// dynamicsecret.go ports `keyorix dynamic-secret` (docs/cli-split-inventory.md §2.4, PR 1):
// on-demand database/cloud credentials (ADR-035). Same flags, output, and exit codes as
// the old CLI's internal/cli/dynamic package -- this is a pure transport port (REST only,
// Zero GAPs), not a behavior change.
package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var dynamicSecretCmd = &cobra.Command{
	Use:     "dynamic-secret",
	Aliases: []string{"dynamic-secrets", "dyn"},
	Short:   "Issue and manage on-demand database credentials (dynamic secrets)",
}

// dynAdminDSNEnv lets operators supply the privileged admin connection string out of
// band (CI, scripts) instead of the interactive hidden prompt -- never as a flag, so it
// cannot land in shell history or process listings.
const dynAdminDSNEnv = "KEYORIX_DYNAMIC_ADMIN_DSN"

var (
	dynListProjectID int
	dynListEnvID     int
	dynTTL           int
	dynRenewTTL      int
	dynYes           bool
	dynLevel         string

	dynCfgName           string
	dynCfgProjectID      int
	dynCfgEnvID          int
	dynCfgBackend        string
	dynCfgTemplate       string
	dynCfgDefaultTTL     int
	dynCfgMaxTTL         int
	dynCfgMaxActiveLease int
)

var dynCreateConfigCmd = &cobra.Command{
	Use:   "create",
	Short: "Register a new dynamic-secret target config",
	Long: `Register a target database/store Keyorix can mint on-demand credentials for.

The admin DSN -- a privileged connection string used only to create and drop the
short-lived users -- is read from the ` + dynAdminDSNEnv + ` environment variable, or
prompted for with hidden input. It is never accepted as a flag (so it cannot land
in shell history); the server encrypts it at rest and never returns it.

For the cloud-IAM backends (aws-sts, gcp, azure, kubernetes) the "admin DSN" is
instead a small JSON config and the issued credential is a short-lived cloud token,
not a username/password:
  aws-sts:    {"role_arn":"...","region":"...","duration_seconds":3600} (optional
              creation template = an inline STS session policy)
  gcp:        {"service_account":"sa@project.iam.gserviceaccount.com","scopes":[...]}
  azure:      {"scopes":["https://management.azure.com/.default"]}
  kubernetes: {"namespace":"app","service_account":"my-app","audiences":["https://svc"]}
              (mints a ServiceAccount token via TokenRequest; add
              "api_server"/"ca_cert"/"token" to target an out-of-cluster API server;
              add "revocable":true to let Revoke genuinely invalidate the token
              early instead of waiting for its natural expiry -- this binds each
              token to a dedicated per-lease Secret and requires the calling
              identity to also hold create+delete on secrets in the namespace,
              on top of create on serviceaccounts/token)
Cloud credentials for the mint call come from the ambient identity (AWS chain /
GCP ADC / Azure DefaultAzureCredential / in-cluster ServiceAccount), never from
Keyorix config. AWS STS, Azure, and GCP tokens have no safe early-revoke
mechanism and always self-expire -- see internal/dynamic's per-backend file
header comments for why.

Examples:
  keyorix dynamic-secret create --name app-db --project-id 1 --backend postgres \
    --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};'
  keyorix dynamic-secret create --name cache --project-id 1 --backend redis \
    --creation-template '~app:* +@read'
  # cloud: paste the JSON config at the hidden prompt
  keyorix dynamic-secret create --name aws-readonly --project-id 1 --backend aws-sts
  keyorix dynamic-secret create --name gcp-token   --project-id 1 --backend gcp
  keyorix dynamic-secret create --name k8s-token   --project-id 1 --backend kubernetes`,
	RunE: runDynCreateConfig,
}

var dynListCmd = &cobra.Command{
	Use:   "list",
	Short: "List dynamic-secret target configs",
	RunE:  runDynList,
}

var dynGetConfigCmd = &cobra.Command{
	Use:   "get-config <config-id>",
	Short: "Show a dynamic-secret config's details",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynGetConfig,
}

var dynIssueCmd = &cobra.Command{
	Use:   "issue <config-id>",
	Short: "Issue a short-lived credential from a config (shown once)",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynIssue,
}

var dynLeasesCmd = &cobra.Command{
	Use:   "leases <config-id>",
	Short: "List leases issued from a config",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynLeases,
}

var dynRenewCmd = &cobra.Command{
	Use:   "renew <lease-id>",
	Short: "Extend an active lease (up to the config's max TTL)",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynRenew,
}

var dynRevokeCmd = &cobra.Command{
	Use:   "revoke <lease-id>",
	Short: "Revoke an active lease now",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynRevoke,
}

var dynRevokeAllCmd = &cobra.Command{
	Use:   "revoke-all <config-id>",
	Short: "Revoke ALL active leases from a config (incident kill switch)",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynRevokeAll,
}

var dynClassifyCmd = &cobra.Command{
	Use:   "classify <config-id>",
	Short: "Set a dynamic-secret config's classification level",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynClassify,
}

func init() {
	dynCreateConfigCmd.Flags().StringVar(&dynCfgName, "name", "", "Config name (required)")
	dynCreateConfigCmd.Flags().IntVar(&dynCfgProjectID, "project-id", 0, "Project ID (required)")
	dynCreateConfigCmd.Flags().IntVar(&dynCfgEnvID, "environment-id", 0, "Environment ID (0 = project-wide)")
	dynCreateConfigCmd.Flags().StringVar(&dynCfgBackend, "backend", "", "Backend: postgres | mysql | mongodb | redis | aws-sts | gcp | azure | kubernetes (required)")
	dynCreateConfigCmd.Flags().StringVar(&dynCfgTemplate, "creation-template", "", "Backend-specific grant/role/ACL template ({{name}} for SQL)")
	dynCreateConfigCmd.Flags().IntVar(&dynCfgDefaultTTL, "default-ttl", 0, "Default lease TTL in seconds (0 = server default)")
	dynCreateConfigCmd.Flags().IntVar(&dynCfgMaxTTL, "max-ttl", 0, "Max lease TTL ceiling in seconds (0 = no ceiling)")
	dynCreateConfigCmd.Flags().IntVar(&dynCfgMaxActiveLease, "max-active-leases", 0, "Max concurrent active leases from this config (0 = no ceiling)")

	dynListCmd.Flags().IntVar(&dynListProjectID, "project-id", 0, "Filter by project ID")
	dynListCmd.Flags().IntVar(&dynListEnvID, "environment-id", 0, "Filter by environment ID")
	dynIssueCmd.Flags().IntVar(&dynTTL, "ttl", 0, "Lease TTL in seconds (0 = the config default)")
	dynRenewCmd.Flags().IntVar(&dynRenewTTL, "ttl", 0, "Renewal TTL in seconds (0 = the config default)")
	dynRevokeAllCmd.Flags().BoolVar(&dynYes, "yes", false, "Skip the confirmation prompt")
	dynClassifyCmd.Flags().StringVar(&dynLevel, "level", "", "Classification level (required)")
	_ = dynClassifyCmd.MarkFlagRequired("level")

	dynamicSecretCmd.AddCommand(dynCreateConfigCmd, dynListCmd, dynGetConfigCmd, dynIssueCmd,
		dynLeasesCmd, dynRenewCmd, dynRevokeCmd, dynRevokeAllCmd, dynClassifyCmd)
	rootCmd.AddCommand(dynamicSecretCmd)
}

// dynamicSecretAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every dynamic-secret subcommand needs.
func dynamicSecretAPIClient() (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	return newAPIClient(serverURL, token)
}

// readDynamicAdminDSN resolves the admin DSN from the environment, falling back to a
// hidden interactive prompt. It is never read from a flag.
func readDynamicAdminDSN(backend string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(dynAdminDSNEnv)); v != "" {
		return v, nil
	}
	fmt.Printf("Admin DSN for the %s target (input hidden): ", backend)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read admin DSN (set %s for non-interactive use): %w", dynAdminDSNEnv, err)
	}
	dsn := strings.TrimSpace(string(b))
	if dsn == "" {
		return "", usageErrorf("admin DSN is required")
	}
	return dsn, nil
}

func runDynCreateConfig(_ *cobra.Command, _ []string) error {
	if dynCfgName == "" || dynCfgProjectID == 0 || dynCfgBackend == "" {
		return usageErrorf("--name, --project-id and --backend are required")
	}
	adminDSN, err := readDynamicAdminDSN(dynCfgBackend)
	if err != nil {
		return err
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	body := apiclient.CreateDynamicSecretConfigJSONRequestBody{
		Name:              dynCfgName,
		ProjectId:         dynCfgProjectID,
		EnvironmentId:     dynCfgEnvID,
		BackendType:       dynCfgBackend,
		AdminDsn:          adminDSN,
		CreationTemplate:  dynCfgTemplate,
		DefaultTtlSeconds: &dynCfgDefaultTTL,
		MaxTtlSeconds:     &dynCfgMaxTTL,
		MaxActiveLeases:   &dynCfgMaxActiveLease,
	}
	resp, err := client.CreateDynamicSecretConfigWithResponse(context.Background(), body)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("create dynamic-secret config failed", resp.StatusCode(), resp.Body)
	}
	cfg := resp.JSON200.Data
	fmt.Printf("Created dynamic-secret config #%d (%s, %s).\n", derefUint32(cfg.Id), derefStr(cfg.Name), derefStr((*string)(cfg.BackendType)))
	fmt.Printf("Issue a credential with: keyorix dynamic-secret issue %d\n", derefUint32(cfg.Id))
	return nil
}

func runDynList(_ *cobra.Command, _ []string) error {
	if err := checkOutputFormat(dynListFormat); err != nil {
		return err
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	var params apiclient.ListDynamicSecretConfigsParams
	if dynListProjectID > 0 {
		params.ProjectId = &dynListProjectID
	}
	if dynListEnvID > 0 {
		params.EnvironmentId = &dynListEnvID
	}
	resp, err := client.ListDynamicSecretConfigsWithResponse(context.Background(), &params)
	if err != nil {
		return err
	}
	var configs []apiclient.DynamicSecretConfig
	if resp.JSON200 != nil && resp.JSON200.Data != nil {
		configs = *resp.JSON200.Data
	}
	return emitList(dynListFormat, configs, func() error {
		if resp.JSON200 == nil || resp.JSON200.Data == nil || len(*resp.JSON200.Data) == 0 {
			fmt.Println("No dynamic-secret configs found.")
			return nil
		}
		fmt.Printf("%-5s %-24s %-10s %-8s %-8s\n", "ID", "NAME", "BACKEND", "TTL", "MAXTTL")
		for _, cfg := range *resp.JSON200.Data {
			fmt.Printf("%-5d %-24s %-10s %-8d %-8d\n", derefUint32(cfg.Id), derefStr(cfg.Name),
				derefStr((*string)(cfg.BackendType)), derefInt(cfg.DefaultTtlSeconds), derefInt(cfg.MaxTtlSeconds))
		}
		return nil
	})
}

func runDynGetConfig(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid config id: %s", args[0])
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetDynamicSecretConfigWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get dynamic-secret config failed", resp.StatusCode(), resp.Body)
	}
	printDynConfig(resp.JSON200.Data)
	return nil
}

func printDynConfig(cfg *apiclient.DynamicSecretConfig) {
	fmt.Printf("ID:             %d\n", derefUint32(cfg.Id))
	fmt.Printf("Name:           %s\n", derefStr(cfg.Name))
	fmt.Printf("Project ID:     %d\n", derefUint32(cfg.ProjectId))
	fmt.Printf("Environment ID: %d\n", derefUint32(cfg.EnvironmentId))
	fmt.Printf("Backend:        %s\n", derefStr((*string)(cfg.BackendType)))
	fmt.Printf("Default TTL:    %ds\n", derefInt(cfg.DefaultTtlSeconds))
	fmt.Printf("Max TTL:        %ds\n", derefInt(cfg.MaxTtlSeconds))
	if c := derefStr(cfg.Classification); c != "" {
		fmt.Printf("Classification: %s\n", c)
	}
}

func runDynIssue(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid config id: %s", args[0])
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	body := apiclient.IssueDynamicSecretLeaseJSONRequestBody{TtlSeconds: &dynTTL}
	resp, err := client.IssueDynamicSecretLeaseWithResponse(context.Background(), id, body)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("issue dynamic-secret lease failed", resp.StatusCode(), resp.Body)
	}
	lease := resp.JSON200.Data
	fmt.Println("Credential issued — shown once, auto-revokes at expiry.")
	fmt.Printf("  lease:    %s\n", derefStr(lease.LeaseId))
	if u := derefStr(lease.Username); u != "" {
		fmt.Printf("  username: %s\n", u)
	}
	if p := derefStr(lease.Password); p != "" {
		fmt.Printf("  password: %s\n", p)
	}
	// Cloud-IAM backends (AWS STS) return their credential as fields.
	if lease.Fields != nil {
		for _, k := range sortedKeys(*lease.Fields) {
			fmt.Printf("  %-9s %s\n", k+":", (*lease.Fields)[k])
		}
	}
	fmt.Printf("  expires:  %s\n", derefStr(lease.ExpiresAt))
	return nil
}

// sortedKeys returns a map's keys in deterministic order, for stable CLI output.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func runDynLeases(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid config id: %s", args[0])
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListDynamicSecretLeasesWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || len(*resp.JSON200.Data) == 0 {
		fmt.Println("No leases for this config.")
		return nil
	}
	fmt.Printf("%-34s %-16s %-14s %s\n", "LEASE", "ROLE", "STATUS", "EXPIRES")
	for _, l := range *resp.JSON200.Data {
		fmt.Printf("%-34s %-16s %-14s %s\n", derefStr(l.LeaseId), derefStr(l.RoleName),
			derefStr((*string)(l.Status)), derefStr(l.ExpiresAt))
	}
	return nil
}

func runDynRenew(_ *cobra.Command, args []string) error {
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	body := apiclient.RenewDynamicSecretLeaseJSONRequestBody{TtlSeconds: &dynRenewTTL}
	resp, err := client.RenewDynamicSecretLeaseWithResponse(context.Background(), args[0], body)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("renew lease failed", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Lease %s renewed — new expiry %s\n", derefStr(resp.JSON200.Data.LeaseId), derefStr(resp.JSON200.Data.ExpiresAt))
	return nil
}

func runDynRevoke(_ *cobra.Command, args []string) error {
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RevokeDynamicSecretLeaseWithResponse(context.Background(), args[0])
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("revoke lease failed", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Lease %s %s.\n", derefStr(resp.JSON200.Data.LeaseId), derefStr(resp.JSON200.Data.Status))
	return nil
}

func runDynRevokeAll(cmd *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid config id: %s", args[0])
	}
	if !dynYes {
		fmt.Printf("Revoke ALL active leases from config %d? This invalidates every outstanding\ncredential it issued. Type 'yes' to confirm: ", id)
		var answer string
		_, _ = fmt.Fscanln(cmd.InOrStdin(), &answer)
		if answer != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.RevokeAllDynamicSecretLeasesWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("revoke-all failed", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Config %d: revoked %d lease(s), %d failed.\n", derefUint32(resp.JSON200.Data.ConfigId),
		derefInt(resp.JSON200.Data.Revoked), derefInt(resp.JSON200.Data.Failed))
	return nil
}

func runDynClassify(_ *cobra.Command, args []string) error {
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid config id: %s", args[0])
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	level := apiclient.ClassifyDynamicSecretConfigJSONBodyClassification(dynLevel)
	body := apiclient.ClassifyDynamicSecretConfigJSONRequestBody{Classification: &level}
	resp, err := client.ClassifyDynamicSecretConfigWithResponse(context.Background(), id, body)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("classify config failed", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("✅ Classification set to %q for config %d.\n", dynLevel, id)
	return nil
}

func derefUint32(u *uint32) uint32 {
	if u == nil {
		return 0
	}
	return *u
}
