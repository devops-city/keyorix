package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
)

// ── create ──────────────────────────────────────────────────────────────────────

var (
	secretCreateName          string
	secretCreateType          string
	secretCreateProjectID     int
	secretCreateEnvironmentID int
	secretCreateMaxReads      int
	secretCreateExpiration    string
	secretCreateValue         string
	secretCreateFromFile      string
	secretCreateInteractive   bool
	secretCreateDescription   string
)

var secretCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new secret",
	RunE:  runSecretCreate,
}

func init() {
	secretCreateCmd.Flags().StringVar(&secretCreateName, "name", "", "Secret name (required)")
	secretCreateCmd.Flags().StringVar(&secretCreateType, "type", "generic", "Secret type")
	secretCreateCmd.Flags().IntVar(&secretCreateProjectID, "project", 1, "Project ID")
	secretCreateCmd.Flags().IntVar(&secretCreateEnvironmentID, "environment", 1, "Environment ID. With --project and no --environment the project's \"development\" environment is used; if it has none, --environment is required (see `keyorix project environments <project-id>`). Without --project: 1")
	secretCreateCmd.Flags().IntVar(&secretCreateMaxReads, "max-reads", 0, "Maximum number of reads (0 = unlimited)")
	secretCreateCmd.Flags().StringVar(&secretCreateExpiration, "expires", "", "Expiration time (RFC3339 format)")
	secretCreateCmd.Flags().StringVar(&secretCreateValue, "value", "", "Secret value")
	secretCreateCmd.Flags().StringVar(&secretCreateFromFile, "from-file", "", "Read secret value from file")
	secretCreateCmd.Flags().BoolVar(&secretCreateInteractive, "interactive", false, "Interactive mode (value read from a hidden prompt)")
	secretCreateCmd.Flags().StringVar(&secretCreateDescription, "description", "", "Optional free-text note about the secret")
	SecretCmd.AddCommand(secretCreateCmd)
}

// readSecretValueFromFile reads a secret value from a caller-supplied path.
// Mirrors the old CLI's buildCreateRequest/buildUpdateRequest guard exactly:
// only a relative path is accepted, and the path must not be a symlink --
// both refusals exist so a secret value can't be read from an arbitrary
// absolute location or through a planted symlink.
func readSecretValueFromFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("absolute paths are not allowed: %s (use a path relative to the current directory, e.g. --from-file ./%s)", cleanPath, filepath.Base(cleanPath))
	}
	fileInfo, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat file: %w", err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlinks are not allowed: %s", cleanPath)
	}
	return regularfile.ReadFile("secret value file", cleanPath)
}

// readHiddenValue prompts on stderr and reads a value from stdin with echo
// disabled (golang.org/x/term), so the value never appears in the terminal
// scrollback or a screen-recording. Matches the old CLI's --interactive mode.
func readHiddenValue(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	valueBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read value: %w", err)
	}
	return valueBytes, nil
}

func resolveSecretCreateValue() ([]byte, error) {
	switch {
	case secretCreateInteractive:
		v, err := readHiddenValue("Secret value (hidden): ")
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, fmt.Errorf("secret value is required")
		}
		return v, nil
	case secretCreateFromFile != "":
		return readSecretValueFromFile(secretCreateFromFile)
	case secretCreateValue != "":
		return []byte(secretCreateValue), nil
	default:
		return nil, fmt.Errorf("secret value is required (use --value, --from-file, or --interactive)")
	}
}

func runSecretCreate(cmd *cobra.Command, args []string) error {
	warnInsecureFlag(cmd, "value", "use --interactive or --from-file instead.")
	if secretCreateName == "" {
		return fmt.Errorf("secret name is required (use --name)")
	}
	value, err := resolveSecretCreateValue()
	if err != nil {
		return err
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	// --environment defaults to 1, which is only right for project 1: when the flag was
	// not given, use the chosen project's own development environment (#3155).
	if !cmd.Flags().Changed("environment") && secretCreateProjectID > 0 {
		envID, ok, derr := defaultEnvironmentForProject(context.Background(), client, secretCreateProjectID)
		if derr != nil {
			return derr
		}
		if ok {
			secretCreateEnvironmentID = envID
		}
	}
	body := apiclient.CreateSecretJSONRequestBody{
		Name:          secretCreateName,
		Value:         string(value),
		Type:          secretCreateType,
		EnvironmentId: secretCreateEnvironmentID,
	}
	if secretCreateProjectID != 0 {
		body.ProjectId = &secretCreateProjectID
	}
	if secretCreateMaxReads > 0 {
		body.MaxReads = &secretCreateMaxReads
	}
	if secretCreateDescription != "" {
		body.Description = &secretCreateDescription
	}
	if secretCreateExpiration != "" {
		exp, perr := time.Parse(time.RFC3339, secretCreateExpiration)
		if perr != nil {
			return fmt.Errorf("invalid expiration format: %w", perr)
		}
		body.Expiration = &exp
	}

	resp, err := client.CreateSecretWithResponse(context.Background(), body)
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		err := httpStatusError("failed to create secret", resp.StatusCode(), resp.Body)
		if secretCreateProjectID > 0 && strings.Contains(string(resp.Body), "does not belong to project") {
			if hint := validEnvironmentsHint(context.Background(), client, secretCreateProjectID); hint != "" {
				return fmt.Errorf("%w\n%s", err, hint)
			}
		}
		return err
	}
	printCreatedSecret(resp.JSON201.Data)
	return nil
}

// defaultEnvironmentForProject returns the ID of the project's "development" environment. It
// never guesses another one: a project without a "development" environment (the first listed
// could be production) is an error that names the environments and asks for --environment.
// ok is false, with a nil error, when the list cannot be read or is empty (a caller without
// access to it keeps the flag's literal default and the server's verdict).
func defaultEnvironmentForProject(ctx context.Context, client *apiclient.ClientWithResponses, projectID int) (id int, ok bool, err error) {
	envs, lerr := listEnvironments(ctx, client, uint(projectID)) // #nosec G115 -- guarded > 0 by the caller
	if lerr != nil || len(envs) == 0 {
		return 0, false, nil
	}
	for _, e := range envs {
		if strings.EqualFold(e.Name, "development") {
			return int(e.ID), true, nil // #nosec G115 -- DB auto-increment ID
		}
	}
	return 0, false, fmt.Errorf("project %d has no \"development\" environment, so --environment is required\n%s", projectID, validEnvironmentsHint(ctx, client, projectID))
}

// validEnvironmentsHint names the environments a project does have, for the "environment N
// does not belong to project M" refusal; "" when they cannot be listed.
func validEnvironmentsHint(ctx context.Context, client *apiclient.ClientWithResponses, projectID int) string {
	envs, err := listEnvironments(ctx, client, uint(projectID)) // #nosec G115 -- guarded > 0 by the caller
	if err != nil || len(envs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(envs))
	for _, e := range envs {
		parts = append(parts, fmt.Sprintf("%d (%s)", e.ID, e.Name))
	}
	return fmt.Sprintf("project %d has environments: %s -- pass one with --environment", projectID, strings.Join(parts, ", "))
}

func printCreatedSecret(s *apiclient.Secret) {
	fmt.Println("Secret created successfully!")
	fmt.Printf("ID:          %d\n", derefSecretInt(s.Id))
	fmt.Printf("Name:        %s\n", derefStr(s.Name))
	fmt.Printf("Type:        %s\n", derefStr(s.Type))
	fmt.Printf("Project:     %d\n", derefSecretInt(s.ProjectId))
	fmt.Printf("Environment: %d\n", derefSecretInt(s.EnvironmentId))
	if s.CreatedAt != nil {
		fmt.Printf("Created:     %s\n", s.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if s.Expiration != nil {
		fmt.Printf("Expires:     %s\n", s.Expiration.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
}

// ── get ─────────────────────────────────────────────────────────────────────────

var (
	secretGetID        int
	secretGetName      string
	secretGetRef       string
	secretGetShowValue bool
	secretGetProject   int
	secretGetEnv       int
)

var secretGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a secret",
	Long: `Retrieve a secret by ID, by name, or by a project/environment/name reference.

--ref reads the secret's value by a human-readable "project/environment/name"
reference (ADR-059) -- handy for scripts and automation. It always reads the
value (so it counts toward max_reads and is audited like any value read).`,
	RunE: runSecretGet,
}

func init() {
	secretGetCmd.Flags().IntVar(&secretGetID, "id", 0, "Secret ID")
	secretGetCmd.Flags().StringVar(&secretGetName, "name", "", "Secret name")
	secretGetCmd.Flags().StringVar(&secretGetRef, "ref", "", "Reference: project/environment/name (reads the value)")
	secretGetCmd.Flags().IntVar(&secretGetProject, "project", 1, "Project ID (required with --name)")
	secretGetCmd.Flags().IntVar(&secretGetEnv, "environment", 1, "Environment ID (required with --name)")
	secretGetCmd.Flags().BoolVar(&secretGetShowValue, "show-value", false, "Show the decrypted secret value")
	SecretCmd.AddCommand(secretGetCmd)
}

func runSecretGet(cmd *cobra.Command, args []string) error {
	selectors := 0
	for _, set := range []bool{secretGetID != 0, secretGetName != "", secretGetRef != ""} {
		if set {
			selectors++
		}
	}
	if selectors == 0 {
		return fmt.Errorf("one of --id, --name, or --ref is required")
	}
	if selectors > 1 {
		return fmt.Errorf("--id, --name, and --ref are mutually exclusive")
	}
	// A reference read is value-oriented (it resolves to one secret and returns its value).
	showValue := secretGetShowValue || secretGetRef != ""

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	if secretGetRef != "" {
		resp, err := client.GetSecretValueByRefWithResponse(ctx, &apiclient.GetSecretValueByRefParams{Ref: secretGetRef})
		if err != nil {
			return fmt.Errorf("get secret by ref: %w", err)
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get secret by ref", resp.StatusCode(), resp.Body)
		}
		displaySecret(resp.JSON200.Data.Secret, derefStr(resp.JSON200.Data.Value), showValue)
		return nil
	}

	if secretGetID != 0 {
		return runSecretGetByID(ctx, client, secretGetID, showValue)
	}
	return runSecretGetByName(ctx, client, showValue)
}

func runSecretGetByID(ctx context.Context, client *apiclient.ClientWithResponses, id int, showValue bool) error {
	// `secret get` prints "Total Reads", so it asks for the opt-in count.
	params := &apiclient.GetSecretParams{Include: &includeTotalReads}
	if showValue {
		t := true
		params.IncludeValue = &t
	}
	resp, err := client.GetSecretWithResponse(ctx, id, params)
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get secret", resp.StatusCode(), resp.Body)
	}
	d := resp.JSON200.Data
	if showValue && d.Secret != nil {
		displaySecret(d.Secret, derefStr(d.Value), true)
		return nil
	}
	displaySecret(secretGetResultToSecret(d), "", false)
	return nil
}

func runSecretGetByName(ctx context.Context, client *apiclient.ClientWithResponses, showValue bool) error {
	// Resolve name -> secret via the filtered list, then optionally fetch the value.
	params := &apiclient.ListSecretsParams{ProjectId: &secretGetProject, EnvironmentId: &secretGetEnv, PageSize: intPtr(1000)}
	resp, err := client.ListSecretsWithResponse(ctx, params)
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("list secrets", resp.StatusCode(), resp.Body)
	}
	var found *apiclient.SecretListEntry
	for _, s := range derefSecretListEntrySlice(resp.JSON200.Data.Secrets) {
		if derefStr(s.Name) == secretGetName {
			entry := s
			found = &entry
			break
		}
	}
	if found == nil {
		return fmt.Errorf("secret %q not found", secretGetName)
	}
	id := derefSecretInt(found.Id)
	if !showValue {
		// The list omits total_reads; a metadata read by id (no value, so no read is
		// recorded) carries it. Fall back to the list entry if that fetch fails.
		f := false
		if mresp, merr := client.GetSecretWithResponse(ctx, id, &apiclient.GetSecretParams{IncludeValue: &f, Include: &includeTotalReads}); merr == nil && mresp.JSON200 != nil && mresp.JSON200.Data != nil {
			displaySecret(secretGetResultToSecret(mresp.JSON200.Data), "", false)
			return nil
		}
		displaySecret(secretListEntryToSecret(found), "", false)
		return nil
	}
	t := true
	vresp, err := client.GetSecretWithResponse(ctx, id, &apiclient.GetSecretParams{IncludeValue: &t, Include: &includeTotalReads})
	if err != nil {
		return fmt.Errorf("get secret value: %w", err)
	}
	if vresp.JSON200 == nil || vresp.JSON200.Data == nil {
		return httpStatusError("get secret value", vresp.StatusCode(), vresp.Body)
	}
	d := vresp.JSON200.Data
	if d.Secret != nil {
		displaySecret(d.Secret, derefStr(d.Value), true)
	} else {
		displaySecret(secretGetResultToSecret(d), derefStr(d.Value), true)
	}
	return nil
}

func intPtr(n int) *int { return &n }

// includeTotalReads is the opt-in `include` token for GET /secrets/{id}: the server
// computes total_reads (an O(reads) count) only when asked.
var includeTotalReads = "total_reads"

// ── Display ───────────────────────────────────────────────────────────────────

func displaySecret(s *apiclient.Secret, value string, showValue bool) {
	if s == nil {
		fmt.Println("(secret not found)")
		return
	}
	fmt.Println("Secret Information")
	fmt.Println("==================")
	fmt.Printf("ID:          %d\n", derefSecretInt(s.Id))
	fmt.Printf("Name:        %s\n", derefStr(s.Name))
	fmt.Printf("Type:        %s\n", derefStr(s.Type))
	fmt.Printf("Status:      %s\n", derefStr(s.Status))
	fmt.Printf("Project:     %d\n", derefSecretInt(s.ProjectId))
	fmt.Printf("Environment: %d\n", derefSecretInt(s.EnvironmentId))
	fmt.Printf("Created By:  %s\n", derefStr(s.CreatedBy))
	if s.CreatedAt != nil {
		fmt.Printf("Created:     %s\n", s.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if s.UpdatedAt != nil {
		fmt.Printf("Updated:     %s\n", s.UpdatedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if s.MaxReads != nil {
		fmt.Printf("Max Reads:   %d\n", *s.MaxReads)
	}
	if s.TotalReads != nil {
		// Lifetime value reads (the server's access-log count), not the max_reads counter.
		fmt.Printf("Total Reads: %d\n", *s.TotalReads)
	}
	if s.Expiration != nil {
		fmt.Printf("Expires:     %s\n", s.Expiration.UTC().Format("2006-01-02 15:04:05 UTC"))
		if time.Now().After(*s.Expiration) {
			fmt.Println("WARNING: secret is EXPIRED")
		}
	}

	switch {
	case value != "":
		fmt.Println()
		fmt.Println("Decrypted Value")
		fmt.Println("---------------")
		fmt.Println(value)
	case showValue:
		fmt.Println()
		fmt.Println("(value unavailable)")
	default:
		fmt.Println()
		fmt.Println("Use --show-value to display the decrypted value.")
	}
}

// secretGetResultToSecret projects the metadata-only fields of a
// SecretGetResult onto a Secret for display, used when include_value was not
// requested (the server sends the secret's fields directly at the top level).
func secretGetResultToSecret(d *apiclient.SecretGetResult) *apiclient.Secret {
	return &apiclient.Secret{
		Id: d.Id, ParentId: d.ParentId, ProjectId: d.ProjectId, EnvironmentId: d.EnvironmentId,
		Name: d.Name, IsSecret: d.IsSecret, Type: d.Type, Description: d.Description,
		MaxReads: d.MaxReads, ReadCount: d.ReadCount, Expiration: d.Expiration,
		Classification: d.Classification, Status: d.Status, CreatedBy: d.CreatedBy,
		OwnerId: d.OwnerId, IsShared: d.IsShared, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
		LastRotatedAt: d.LastRotatedAt, TotalReads: d.TotalReads,
	}
}

func secretListEntryToSecret(e *apiclient.SecretListEntry) *apiclient.Secret {
	return &apiclient.Secret{
		Id: e.Id, ParentId: e.ParentId, ProjectId: e.ProjectId, EnvironmentId: e.EnvironmentId,
		Name: e.Name, IsSecret: e.IsSecret, Type: e.Type, Description: e.Description,
		MaxReads: e.MaxReads, ReadCount: e.ReadCount, Expiration: e.Expiration,
		Classification: e.Classification, Status: e.Status, CreatedBy: e.CreatedBy,
		OwnerId: e.OwnerId, IsShared: e.IsShared, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
	}
}

func derefSecretListEntrySlice(s *[]apiclient.SecretListEntry) []apiclient.SecretListEntry {
	if s == nil {
		return nil
	}
	return *s
}

// ── update ──────────────────────────────────────────────────────────────────────

var (
	secretUpdateID          int
	secretUpdateMaxReads    int
	secretUpdateExpiration  string
	secretUpdateValue       string
	secretUpdateFromFile    string
	secretUpdateInteractive bool
	secretUpdateClearExp    bool
	secretUpdateClearReads  bool
)

var secretUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an existing secret",
	RunE:  runSecretUpdate,
}

func init() {
	secretUpdateCmd.Flags().IntVar(&secretUpdateID, "id", 0, "Secret ID (required)")
	secretUpdateCmd.Flags().IntVar(&secretUpdateMaxReads, "max-reads", -1, "Update max reads (-1 = no change, minimum 1; use --clear-max-reads to remove the limit)")
	secretUpdateCmd.Flags().BoolVar(&secretUpdateClearReads, "clear-max-reads", false, "Remove the read limit (unlimited)")
	secretUpdateCmd.Flags().StringVar(&secretUpdateExpiration, "expires", "", "Update expiration (RFC3339 format)")
	secretUpdateCmd.Flags().StringVar(&secretUpdateValue, "value", "", "New secret value")
	secretUpdateCmd.Flags().StringVar(&secretUpdateFromFile, "from-file", "", "Read new value from file")
	secretUpdateCmd.Flags().BoolVar(&secretUpdateInteractive, "interactive", false, "Interactive mode (value read from a hidden prompt)")
	secretUpdateCmd.Flags().BoolVar(&secretUpdateClearExp, "clear-expiration", false, "Remove expiration")
	SecretCmd.AddCommand(secretUpdateCmd)
}

func runSecretUpdate(cmd *cobra.Command, args []string) error {
	if secretUpdateID == 0 {
		return fmt.Errorf("secret ID is required (use --id)")
	}
	warnInsecureFlag(cmd, "value", "use --interactive or --from-file instead.")

	var value []byte
	var err error
	switch {
	case secretUpdateInteractive:
		value, err = readHiddenValue("New secret value (hidden): ")
	case secretUpdateFromFile != "":
		value, err = readSecretValueFromFile(secretUpdateFromFile)
	case secretUpdateValue != "":
		value = []byte(secretUpdateValue)
	}
	if err != nil {
		return err
	}

	body := apiclient.UpdateSecretJSONRequestBody{}
	if len(value) > 0 {
		v := string(value)
		body.Value = &v
	}
	switch {
	case secretUpdateClearReads && secretUpdateMaxReads >= 0:
		return fmt.Errorf("--max-reads and --clear-max-reads are mutually exclusive")
	case secretUpdateClearReads:
		t := true
		body.ClearMaxReads = &t
	case secretUpdateMaxReads == 0:
		return fmt.Errorf("--max-reads must be at least 1; to remove the read limit use --clear-max-reads")
	case secretUpdateMaxReads > 0:
		body.MaxReads = &secretUpdateMaxReads
	}
	if secretUpdateClearExp {
		t := true
		body.ClearExpiration = &t
	} else if secretUpdateExpiration != "" {
		exp, perr := time.Parse(time.RFC3339, secretUpdateExpiration)
		if perr != nil {
			return fmt.Errorf("invalid expiration format (use RFC3339): %w", perr)
		}
		body.Expiration = &exp
	}

	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.UpdateSecretWithResponse(context.Background(), secretUpdateID, body)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to update secret", resp.StatusCode(), resp.Body)
	}
	s := resp.JSON200.Data
	fmt.Println("Secret updated successfully!")
	fmt.Printf("ID: %d\n", derefSecretInt(s.Id))
	fmt.Printf("Name: %s\n", derefStr(s.Name))
	fmt.Printf("Type: %s\n", derefStr(s.Type))
	if len(value) > 0 {
		fmt.Println("New encrypted version created")
	}
	return nil
}

// ── delete ──────────────────────────────────────────────────────────────────────

var (
	secretDeleteID      int
	secretDeleteName    string
	secretDeleteProject int
	secretDeleteEnv     int
	secretDeleteForce   bool
	secretDeleteFormat  string
)

var secretDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a secret (soft-delete; restorable with 'secret restore')",
	RunE:  runSecretDelete,
}

func init() {
	secretDeleteCmd.Flags().IntVar(&secretDeleteID, "id", 0, "Secret ID")
	secretDeleteCmd.Flags().StringVar(&secretDeleteName, "name", "", "Secret name")
	secretDeleteCmd.Flags().IntVar(&secretDeleteProject, "project", 1, "Project ID (required with --name)")
	secretDeleteCmd.Flags().IntVar(&secretDeleteEnv, "environment", 1, "Environment ID (required with --name)")
	secretDeleteCmd.Flags().BoolVar(&secretDeleteForce, "force", false, "Skip confirmation prompt, and delete even if other secrets depend on this one")
	secretDeleteCmd.Flags().StringVar(&secretDeleteFormat, "format", "text", "Output format: text or json (json is non-interactive and requires --force)")
	SecretCmd.AddCommand(secretDeleteCmd)
}

func runSecretDelete(cmd *cobra.Command, args []string) error {
	if secretDeleteID == 0 && secretDeleteName == "" {
		return fmt.Errorf("either --id or --name is required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	var secretID int
	var secretName string
	if secretDeleteID != 0 {
		t := false
		resp, gerr := client.GetSecretWithResponse(ctx, secretDeleteID, &apiclient.GetSecretParams{IncludeValue: &t})
		if gerr != nil || resp.JSON200 == nil || resp.JSON200.Data == nil {
			return fmt.Errorf("secret not found: %w", gerr)
		}
		secretID = secretDeleteID
		secretName = derefStr(resp.JSON200.Data.Name)
	} else {
		id, name, ferr := findRemoteSecretByName(ctx, client, secretDeleteName, secretDeleteProject, secretDeleteEnv)
		if ferr != nil {
			return ferr
		}
		secretID, secretName = id, name
	}

	jsonOut := secretDeleteFormat == "json"
	if secretDeleteFormat != "json" && secretDeleteFormat != "text" {
		return fmt.Errorf("unsupported format: %s (use 'text' or 'json')", secretDeleteFormat)
	}
	if jsonOut && !secretDeleteForce {
		return fmt.Errorf("--format json is non-interactive: pass --force to confirm the deletion")
	}

	vresp, err := client.GetSecretVersionsWithResponse(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}
	var versionCount int
	if vresp.JSON200 != nil && vresp.JSON200.Data != nil {
		versionCount = len(derefSecretVersionSlice(vresp.JSON200.Data.Versions))
	}

	// Dependents (ADR-052): other secrets that declared a dependency on this
	// one. Fail closed -- if the check itself fails, --force is required.
	var dependents []apiclient.SecretDependencyEdge
	depResp, derr := client.ListSecretDependenciesWithResponse(ctx, secretID)
	switch {
	case derr == nil && depResp.JSON200 != nil && depResp.JSON200.Data != nil:
		dependents = derefSecretDependencyEdgeSlice(depResp.JSON200.Data.Dependents)
	case secretDeleteForce:
		fmt.Fprintf(os.Stderr, "warning: could not check dependents of secret %d; continuing because --force was given\n", secretID)
	case derr != nil:
		return fmt.Errorf("could not check what depends on secret %d (use --force to delete anyway): %w", secretID, derr)
	default:
		return httpStatusError(fmt.Sprintf("could not check what depends on secret %d (use --force to delete anyway)", secretID), depResp.StatusCode(), depResp.Body)
	}

	if len(dependents) > 0 && !secretDeleteForce {
		// Unreachable in json mode (json requires --force), so text only.
		fmt.Printf("Secret '%s' (ID: %d) has %d dependent secret(s):\n", secretName, secretID, len(dependents))
		printDeleteDependents(dependents)
		return fmt.Errorf("refusing to delete secret %d: %d secret(s) depend on it -- re-run with --force to delete anyway", secretID, len(dependents))
	}

	if !jsonOut {
		fmt.Println("About to delete secret:")
		fmt.Printf("ID: %d\n", secretID)
		fmt.Printf("Name: %s\n", secretName)
		fmt.Printf("Versions: %d\n", versionCount)
		if len(dependents) > 0 {
			fmt.Printf("WARNING: %d secret(s) depend on this one (--force given):\n", len(dependents))
			printDeleteDependents(dependents)
		}
	}

	if !secretDeleteForce {
		fmt.Println()
		fmt.Println("This soft-deletes the secret and all its versions -- it stops appearing in")
		fmt.Println("normal listings immediately, and can be restored with")
		fmt.Printf("'keyorix secret restore --id %d' until the purge date, which is printed once\n", secretID)
		fmt.Println("the deletion is done (it depends on the server's soft-delete retention window).")
		fmt.Println()
		if !confirmSecretDeletion(secretName) {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	dresp, err := client.DeleteSecretWithResponse(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	if dresp.StatusCode() != 204 {
		return httpStatusError("failed to delete secret", dresp.StatusCode(), dresp.Body)
	}
	rawPurgeAt := ""
	if dresp.HTTPResponse != nil {
		rawPurgeAt = dresp.HTTPResponse.Header.Get("Keyorix-Purge-At")
	}
	purgeAt := normalizePurgeAt(rawPurgeAt)
	if jsonOut {
		return writeSecretDeleteJSON(secretDeleteResult{
			ID: secretID, Name: secretName, Deleted: true, SoftDeleted: true, Versions: versionCount,
			RestoreCommand: fmt.Sprintf("keyorix secret restore --id %d", secretID),
			PurgeAt:        purgeAt,
			Dependents:     toDeleteDependents(dependents),
		})
	}
	fmt.Printf("Secret '%s' (ID: %d) deleted (soft-delete)\n", secretName, secretID)
	fmt.Printf("Its %d version(s) are kept, not destroyed; restore with: keyorix secret restore --id %d\n", versionCount, secretID)
	if purgeAt != "" {
		fmt.Printf("Restorable until %s (UTC); it will not be purged earlier.\n", purgeAt)
	} else {
		// An older server does not send the date; say so rather than guess one.
		fmt.Println("Restorable until the server's soft-delete retention window expires (this server did not report the date).")
	}
	return nil
}

// normalizePurgeAt validates the Keyorix-Purge-At header of DELETE /secrets/{id} (the
// instant before which the secret will not be purged) and renders it as UTC RFC 3339.
// Empty when the server is older than the header or could not read the date back; a
// value that is not a valid RFC 3339 time is treated as absent rather than echoed to the
// terminal.
func normalizePurgeAt(v string) string {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// secretDeleteResult is the --format json shape of 'secret delete'.
type secretDeleteResult struct {
	ID             int                     `json:"id"`
	Name           string                  `json:"name"`
	Deleted        bool                    `json:"deleted"`
	SoftDeleted    bool                    `json:"soft_deleted"`
	Versions       int                     `json:"versions"`
	RestoreCommand string                  `json:"restore_command,omitempty"`
	PurgeAt        string                  `json:"purge_at,omitempty"`
	Dependents     []secretDeleteDependent `json:"dependents"`
}

type secretDeleteDependent struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func toDeleteDependents(edges []apiclient.SecretDependencyEdge) []secretDeleteDependent {
	out := make([]secretDeleteDependent, 0, len(edges))
	for _, e := range edges {
		out = append(out, secretDeleteDependent{ID: derefSecretInt(e.SecretId), Name: derefStr(e.SecretName)})
	}
	return out
}

func printDeleteDependents(edges []apiclient.SecretDependencyEdge) {
	for _, e := range edges {
		fmt.Printf("  - %s (ID: %d)\n", derefStr(e.SecretName), derefSecretInt(e.SecretId))
	}
}

func writeSecretDeleteJSON(r secretDeleteResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// findRemoteSecretByName resolves a secret name to its (ID, name) via the
// list endpoint's fuzzy "search" filter, then requires an EXACT name match
// among the results -- the list endpoint has no exact-name filter, and
// treating a fuzzy substring hit as a confirmed match could delete the wrong
// secret.
func findRemoteSecretByName(ctx context.Context, client *apiclient.ClientWithResponses, name string, projectID, environmentID int) (int, string, error) {
	search := name
	resp, err := client.ListSecretsWithResponse(ctx, &apiclient.ListSecretsParams{
		ProjectId: &projectID, EnvironmentId: &environmentID, Search: &search, PageSize: intPtr(100),
	})
	if err != nil {
		return 0, "", fmt.Errorf("secret not found: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return 0, "", httpStatusError("secret not found", resp.StatusCode(), resp.Body)
	}
	var matches []apiclient.SecretListEntry
	for _, s := range derefSecretListEntrySlice(resp.JSON200.Data.Secrets) {
		if derefStr(s.Name) == name {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return 0, "", fmt.Errorf("secret not found: no secret named %q in project %d, environment %d", name, projectID, environmentID)
	case 1:
		return derefSecretInt(matches[0].Id), derefStr(matches[0].Name), nil
	default:
		return 0, "", fmt.Errorf("ambiguous: %d secrets named %q in project %d, environment %d -- use --id instead", len(matches), name, projectID, environmentID)
	}
}

func confirmSecretDeletion(secretName string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Type the secret name '%s' to confirm deletion: ", secretName)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != secretName {
		fmt.Printf("Name mismatch. Expected '%s', got '%s'\n", secretName, input)
		return false
	}
	fmt.Print("Are you absolutely sure? (yes/no): ")
	confirmation, _ := reader.ReadString('\n')
	confirmation = strings.TrimSpace(strings.ToLower(confirmation))
	return confirmation == "yes"
}

func derefSecretVersionSlice(s *[]apiclient.SecretVersion) []apiclient.SecretVersion {
	if s == nil {
		return nil
	}
	return *s
}

// ── list ────────────────────────────────────────────────────────────────────────

var (
	secretListProject string
	secretListEnv     int
	secretListLimit   int
	secretListOffset  int
	secretListSearch  string
	secretListFormat  string
)

var secretListCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets",
	Long: `List secrets with filtering and pagination.

The server applies authentication-based filtering automatically: you see
only what you're authorized to read.`,
	RunE: runSecretList,
}

func init() {
	secretListCmd.Flags().StringVar(&secretListProject, "project", "", "Project name or numeric ID")
	secretListCmd.Flags().IntVar(&secretListEnv, "environment", 0, "Filter by environment ID (0 = all)")
	secretListCmd.Flags().IntVar(&secretListLimit, "limit", 50, "Maximum number of results")
	secretListCmd.Flags().IntVar(&secretListOffset, "offset", 0, "Number of results to skip")
	secretListCmd.Flags().StringVar(&secretListSearch, "search", "", "Search query")
	addOutputFlag(secretListCmd, &secretListFormat)
	SecretCmd.AddCommand(secretListCmd)
}

func runSecretList(cmd *cobra.Command, args []string) error {
	if err := checkOutputFormat(secretListFormat); err != nil {
		return err
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	page := (secretListOffset / secretListLimit) + 1
	params := &apiclient.ListSecretsParams{Page: &page, PageSize: &secretListLimit}
	if secretListProject != "" {
		_, id, rerr := resolveMachineProjectID(client, secretListProject)
		if rerr != nil {
			return rerr
		}
		params.ProjectId = &id
	}
	if secretListEnv != 0 {
		params.EnvironmentId = &secretListEnv
	}
	if secretListSearch != "" {
		params.Search = &secretListSearch
	}

	resp, err := client.ListSecretsWithResponse(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to list secrets", resp.StatusCode(), resp.Body)
	}
	secrets := derefSecretListEntrySlice(resp.JSON200.Data.Secrets)
	total := int64(derefSecretInt(resp.JSON200.Data.Total))

	// `truncated` means the server hit a bound while assembling this caller's
	// multi-scope view, so `total` is a FLOOR. Say so rather than print it as a
	// count — a quietly short number is the defect this flag was added to stop
	// (#2780 follow-up). Only reachable without --project: every other list call in
	// this CLI passes an explicit project and so takes the server's scoped branch,
	// which is never truncated.
	if resp.JSON200.Data.Truncated != nil && *resp.JSON200.Data.Truncated {
		reason := derefStr(resp.JSON200.Data.TruncatedReason)
		fmt.Fprintf(os.Stderr,
			"warning: the server could not list every secret you can read, so the total below (%d) is a "+
				"lower bound, not a count. Narrow the query with --project to get an exact listing.\n", total)
		if reason != "" {
			fmt.Fprintf(os.Stderr, "warning: %s\n", reason)
		}
	}

	if secretListFormat == outputTable {
		displaySecretsTable(secrets, total, page, secretListLimit)
		return nil
	}
	return displaySecretsStructured(secretListFormat, secrets, total, page, secretListLimit)
}

func displaySecretsTable(secrets []apiclient.SecretListEntry, total int64, page, pageSize int) {
	fmt.Println("Secrets List")
	fmt.Println("============")
	if secretListSearch != "" {
		fmt.Printf("Search: %s\n", secretListSearch)
	}
	nsLabel := "all"
	if secretListProject != "" {
		nsLabel = secretListProject
	}
	envLabel := "all"
	if secretListEnv != 0 {
		envLabel = fmt.Sprintf("%d", secretListEnv)
	}
	fmt.Printf("Project: %s, Environment: %s\n", nsLabel, envLabel)

	offset := (page - 1) * pageSize
	fmt.Printf("Total: %d, Showing: %d (offset: %d, limit: %d)\n\n", total, len(secrets), offset, pageSize)

	if len(secrets) == 0 {
		fmt.Println("No secrets found.")
		return
	}

	fmt.Printf("%-5s %-20s %-12s %-8s %-20s %-20s\n", "ID", "NAME", "TYPE", "STATUS", "CREATED (UTC)", "EXPIRES (UTC)")
	fmt.Printf("%-5s %-20s %-12s %-8s %-20s %-20s\n",
		"-----", "--------------------", "------------", "--------", "--------------------", "--------------------")
	for _, s := range secrets {
		expires := "Never"
		if s.Expiration != nil {
			expires = s.Expiration.UTC().Format("2006-01-02 15:04")
			if time.Now().After(*s.Expiration) {
				expires += " (EXPIRED)"
			}
		}
		created := ""
		if s.CreatedAt != nil {
			created = s.CreatedAt.UTC().Format("2006-01-02 15:04")
		}
		fmt.Printf("%-5d %-20s %-12s %-8s %-20s %-20s\n",
			derefSecretInt(s.Id), truncateSecretString(derefStr(s.Name), 20), truncateSecretString(derefStr(s.Type), 12),
			derefStr(s.Status), created, truncateSecretString(expires, 20))
	}
	if total > int64(pageSize) {
		fmt.Printf("\nPagination: Showing %d-%d of %d total\n", offset+1, minInt(offset+len(secrets), int(total)), total)
		if offset+pageSize < int(total) {
			fmt.Printf("Use --offset %d to see more results\n", offset+pageSize)
		}
	}
}

type jsonSecretEntry struct {
	ID            int     `json:"id"`
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Status        string  `json:"status"`
	ProjectID     int     `json:"project_id"`
	EnvironmentID int     `json:"environment_id"`
	CreatedBy     string  `json:"created_by"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	MaxReads      *int    `json:"max_reads,omitempty"`
	Expiration    *string `json:"expiration,omitempty"`
}

type jsonSecretsOutput struct {
	Total   int64             `json:"total"`
	Offset  int               `json:"offset"`
	Limit   int               `json:"limit"`
	Count   int               `json:"count"`
	Secrets []jsonSecretEntry `json:"secrets"`
}

func displaySecretsStructured(format string, secrets []apiclient.SecretListEntry, total int64, page, pageSize int) error {
	offset := (page - 1) * pageSize
	out := jsonSecretsOutput{Total: total, Offset: offset, Limit: pageSize, Count: len(secrets), Secrets: make([]jsonSecretEntry, 0, len(secrets))}
	for _, s := range secrets {
		entry := jsonSecretEntry{
			ID: derefSecretInt(s.Id), Name: derefStr(s.Name), Type: derefStr(s.Type), Status: derefStr(s.Status),
			ProjectID: derefSecretInt(s.ProjectId), EnvironmentID: derefSecretInt(s.EnvironmentId), CreatedBy: derefStr(s.CreatedBy),
			MaxReads: s.MaxReads,
		}
		if s.CreatedAt != nil {
			entry.CreatedAt = s.CreatedAt.Format(time.RFC3339)
		}
		if s.UpdatedAt != nil {
			entry.UpdatedAt = s.UpdatedAt.Format(time.RFC3339)
		}
		if s.Expiration != nil {
			exp := s.Expiration.Format(time.RFC3339)
			entry.Expiration = &exp
		}
		out.Secrets = append(out.Secrets, entry)
	}
	return printStructured(format, out)
}

func truncateSecretString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
