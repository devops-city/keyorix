// machine.go ports `keyorix machine` (docs/cli-split-inventory.md §2.3, PR 2):
// project-scoped machine identity management (ADR-023/030/031), REST only. Same
// flags, output, and exit codes as the old CLI's internal/cli/machine package minus
// its local/embedded-mode branch (ADR-108 Decision A removes local mode entirely --
// every command here is the "remote" branch of its old-CLI counterpart).
//
// The project comes from --project, KEYORIX_PROJECT, or the active project set by
// `keyorix project use` (#2981).
package cmd

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Manage machine identities",
	Long:  "Commands for listing, creating, and managing the lifecycle of project machine identities (CI, k8s, services, automation).",
}

func init() {
	rootCmd.AddCommand(machineCmd)
}

// machineAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every machine subcommand needs.
func machineAPIClient() (*apiclient.ClientWithResponses, error) {
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

// resolveMachineProjectID resolves a project name or numeric ID (flag or
// KEYORIX_PROJECT) to its numeric ID via resolveProjectRef (#2562: a
// project-scoped caller can pass the numeric ID).
func resolveMachineProjectID(client *apiclient.ClientWithResponses, flagValue string) (string, int, error) {
	// flag > KEYORIX_PROJECT > the project set with `keyorix project use` (#2981: the
	// other project-scoped command groups already honour the active project; machine
	// alone demanded --project on every call).
	name, err := resolveActiveProjectName(flagValue)
	if err != nil {
		return "", 0, fmt.Errorf("no project given: pass --project, set KEYORIX_PROJECT, or run 'keyorix project use <name>'")
	}
	_, id, err := resolveProjectRef(context.Background(), client, name, false)
	if err != nil {
		return "", 0, err
	}
	return name, id, nil
}

// fetchMachineIdentities lists a project's machine identities.
func fetchMachineIdentities(client *apiclient.ClientWithResponses, projectID int) ([]apiclient.MachineIdentity, error) {
	resp, err := client.ListMachineIdentitiesWithResponse(context.Background(), projectID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.MachineIdentities == nil {
		if resp.StatusCode() != 200 {
			return nil, httpStatusError("failed to list machine identities", resp.StatusCode(), resp.Body)
		}
		return nil, nil
	}
	return *resp.JSON200.Data.MachineIdentities, nil
}

// findMachineByRef finds a machine identity in a project by numeric ID or name.
//
// A ref that parses as a valid numeric ID is ALWAYS resolved as an ID lookup -- it
// never falls through to a Name match, even if no identity has that ID (G78, ported
// unchanged from the old CLI: a purely numeric Name could otherwise shadow the
// intended machine and get resolved instead).
func findMachineByRef(client *apiclient.ClientWithResponses, projectID int, ref string) (apiclient.MachineIdentity, error) {
	identities, err := fetchMachineIdentities(client, projectID)
	if err != nil {
		return apiclient.MachineIdentity{}, fmt.Errorf("failed to list machine identities: %w", err)
	}
	if id, err := strconv.Atoi(ref); err == nil {
		for _, m := range identities {
			if derefInt(m.Id) == id {
				return m, nil
			}
		}
		return apiclient.MachineIdentity{}, fmt.Errorf("machine identity %q not found in project", ref)
	}
	for _, m := range identities {
		if derefStr(m.Name) == ref {
			return m, nil
		}
	}
	return apiclient.MachineIdentity{}, fmt.Errorf("machine identity %q not found in project", ref)
}

// ── create ──────────────────────────────────────────────────────────────────────

var (
	machineCreateProjectName    string
	machineCreateName           string
	machineCreateType           string
	machineCreateDescription    string
	machineCreateClassification string
)

var machineCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a machine identity in a project",
	RunE:  runMachineCreate,
}

func init() {
	machineCreateCmd.Flags().StringVar(&machineCreateProjectName, "project", "", "Project name or numeric ID")
	machineCreateCmd.Flags().StringVar(&machineCreateName, "name", "", "Machine identity name (required)")
	machineCreateCmd.Flags().StringVar(&machineCreateType, "type", "other", "Identity type: ci | k8s | service | automation | other | node")
	machineCreateCmd.Flags().StringVar(&machineCreateDescription, "description", "", "Description")
	machineCreateCmd.Flags().StringVar(&machineCreateClassification, "classification", "", "Data classification: public | internal | confidential | restricted")
	machineCmd.AddCommand(machineCreateCmd)
}

func runMachineCreate(cmd *cobra.Command, args []string) error {
	if machineCreateName == "" {
		return usageErrorf("--name is required")
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineCreateProjectName)
	if err != nil {
		return err
	}

	body := apiclient.CreateMachineIdentityJSONRequestBody{
		Name:         machineCreateName,
		IdentityType: &machineCreateType,
	}
	if machineCreateDescription != "" {
		body.Description = &machineCreateDescription
	}
	if machineCreateClassification != "" {
		body.Classification = &machineCreateClassification
	}
	resp, err := client.CreateMachineIdentityWithResponse(context.Background(), projectID, body)
	if err != nil {
		return fmt.Errorf("failed to create machine identity: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.MachineIdentity == nil {
		return httpStatusError("failed to create machine identity", resp.StatusCode(), resp.Body)
	}
	m := *resp.JSON201.Data.MachineIdentity
	fmt.Printf("Machine identity created: id=%d name=%q type=%s state=%s\n",
		derefInt(m.Id), derefStr(m.Name), derefStr(m.IdentityType), string(derefState(m.State)))
	return nil
}

// ── list ────────────────────────────────────────────────────────────────────────

var machineListProjectName string

var machineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List machine identities in a project",
	RunE:  runMachineList,
}

func init() {
	machineListCmd.Flags().StringVar(&machineListProjectName, "project", "", "Project name or numeric ID")
	machineCmd.AddCommand(machineListCmd)
}

func runMachineList(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	projectName, projectID, err := resolveMachineProjectID(client, machineListProjectName)
	if err != nil {
		return err
	}
	identities, err := fetchMachineIdentities(client, projectID)
	if err != nil {
		return fmt.Errorf("failed to list machine identities: %w", err)
	}
	if len(identities) == 0 {
		fmt.Printf("No machine identities found for project %q.\n", projectName)
		return nil
	}
	fmt.Printf("%-5s %-24s %-12s %-10s %s\n", "ID", "NAME", "TYPE", "STATE", "DESCRIPTION")
	fmt.Printf("%-5s %-24s %-12s %-10s %s\n", "-----", "------------------------", "------------", "----------", "-----------")
	for _, m := range identities {
		desc := derefStr(m.Description)
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-5d %-24s %-12s %-10s %s\n", derefInt(m.Id), cliout.SanitizeForTerminal(derefStr(m.Name)), derefStr(m.IdentityType), string(derefState(m.State)), cliout.SanitizeForTerminal(desc))
	}
	return nil
}

// ── describe ────────────────────────────────────────────────────────────────────

var machineDescribeProjectName string

var machineDescribeCmd = &cobra.Command{
	Use:   "describe <name|id>",
	Short: "Show details of a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineDescribe,
}

func init() {
	machineDescribeCmd.Flags().StringVar(&machineDescribeProjectName, "project", "", "Project name or numeric ID")
	machineCmd.AddCommand(machineDescribeCmd)
}

func runMachineDescribe(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineDescribeProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}
	fmt.Printf("ID:          %d\n", derefInt(m.Id))
	fmt.Printf("Name:        %s\n", cliout.SanitizeForTerminal(derefStr(m.Name)))
	fmt.Printf("Type:        %s\n", derefStr(m.IdentityType))
	fmt.Printf("State:       %s\n", string(derefState(m.State)))
	fmt.Printf("Project ID:  %d\n", derefInt(m.ProjectId))
	if desc := derefStr(m.Description); desc != "" {
		fmt.Printf("Description: %s\n", cliout.SanitizeForTerminal(desc))
	}
	if m.LastSeenAt != nil {
		fmt.Printf("Last seen:   %s\n", m.LastSeenAt.Format("2006-01-02 15:04:05 MST"))
	}
	if m.RevokedAt != nil {
		fmt.Printf("Revoked at:  %s\n", m.RevokedAt.Format("2006-01-02 15:04:05 MST"))
	}
	return nil
}

func derefState(s *apiclient.MachineIdentityState) apiclient.MachineIdentityState {
	if s == nil {
		return ""
	}
	return *s
}

// ── migrate-from-user ──────────────────────────────────────────────────────────────
//
// Ports `keyorix migrate user-to-machine` (docs/cli-split-inventory-census.md,
// FINISH-SPLIT census-gaps batch): the REST-backed thin-CLI replacement for
// internal/cli/migrate/user_to_machine.go's LOCAL-MODE-ONLY command. The old command's
// --by flag and requireMigrationAuthority check existed only because local mode has no
// session to attribute the action to or enforce authority through -- POST
// /machine-identities/migrate-from-user does both itself (the bearer token IS the acting
// identity; the route already requires roles.assign (project) AND users.write (global) via
// router middleware, server/http/router.go). So --by is dropped, not carried forward.
// Named "migrate-from-user", not "migrate ... user-to-machine": a top-level "migrate" verb
// in this CLI would be confusable with the separate keyorix-migrate binary (Vault/cloud
// import tool) -- unrelated despite the name collision, per the census entry's own note.

var (
	machineMigrateProjectName string
	machineMigrateType        string
	machineMigrateName        string
	machineMigrateKeepUser    bool
)

var machineMigrateFromUserCmd = &cobra.Command{
	Use:   "migrate-from-user <username>",
	Short: "Convert a service-account-shaped user into a machine identity",
	Long: "Materialise a project machine identity (ADR-023) for an existing user and,\n" +
		"unless --keep-user is set, suspend the source user so it can no longer log in.\n" +
		"The user is never deleted; suspension is reversible via `keyorix user reactivate`.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runMachineMigrateFromUser,
}

func init() {
	machineMigrateFromUserCmd.Flags().StringVar(&machineMigrateProjectName, "project", "", "Project for the new machine identity")
	machineMigrateFromUserCmd.Flags().StringVar(&machineMigrateType, "type", "service", "Identity type: ci | k8s | service | automation | other")
	machineMigrateFromUserCmd.Flags().StringVar(&machineMigrateName, "name", "", "Machine identity name (defaults to the username)")
	machineMigrateFromUserCmd.Flags().BoolVar(&machineMigrateKeepUser, "keep-user", false, "Leave the source user active (default: suspend it)")
	machineCmd.AddCommand(machineMigrateFromUserCmd)
}

func runMachineMigrateFromUser(cmd *cobra.Command, args []string) error {
	username := args[0]
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineMigrateProjectName)
	if err != nil {
		return err
	}

	body := apiclient.MigrateUserToMachineJSONRequestBody{Username: username, KeepUser: &machineMigrateKeepUser}
	if machineMigrateType != "" {
		body.IdentityType = &machineMigrateType
	}
	if machineMigrateName != "" {
		body.Name = &machineMigrateName
	}
	resp, err := client.MigrateUserToMachineWithResponse(context.Background(), projectID, body)
	if err != nil {
		return fmt.Errorf("failed to migrate user to machine identity: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.MachineIdentity == nil {
		return apiError("migrate user to machine identity", resp.StatusCode(), resp.Body)
	}
	m := *resp.JSON201.Data.MachineIdentity
	fmt.Printf("Migrated user %q to machine identity: id=%d name=%q type=%s state=%s\n",
		username, derefInt(m.Id), derefStr(m.Name), derefStr(m.IdentityType), string(derefState(m.State)))
	if !machineMigrateKeepUser {
		fmt.Println("Source user suspended (login blocked). Use `keyorix user reactivate` to restore.")
	}
	return nil
}

// ── grant-role / revoke-role / roles ─────────────────────────────────────────
//
// A machine identity is otherwise permanently unable to read/write anything in
// its project: the REST endpoints (grantMachineRole/removeMachineRole/
// listMachineRoles, ADR-030) existed already, but no CLI command wrapped them --
// the only way to grant one a role was a hand-crafted authenticated HTTP POST.
// Reuses resolveRoleIDByName (rbac.go) so a role is named the same way
// `keyorix rbac assign-role --role <name>` already accepts it.

var (
	machineGrantRoleProjectName  string
	machineGrantRoleName         string
	machineRevokeRoleProjectName string
	machineRevokeRoleName        string
	machineRolesProjectName      string
)

var machineGrantRoleCmd = &cobra.Command{
	Use:   "grant-role <name|id>",
	Short: "Grant a machine identity a project-scoped role",
	Long:  "Grant a machine identity a role at its project's scope, so tokens it issues can act with that role's permissions.",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineGrantRole,
}

func init() {
	machineGrantRoleCmd.Flags().StringVar(&machineGrantRoleProjectName, "project", "", "Project name or numeric ID")
	machineGrantRoleCmd.Flags().StringVar(&machineGrantRoleName, "role", "", "Role name to grant (required)")
	machineCmd.AddCommand(machineGrantRoleCmd)
}

func runMachineGrantRole(cmd *cobra.Command, args []string) error {
	if machineGrantRoleName == "" {
		return usageErrorf("--role is required")
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	_, projectID, err := resolveMachineProjectID(client, machineGrantRoleProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, client, machineGrantRoleName)
	if err != nil {
		return err
	}
	resp, err := client.GrantMachineRoleWithResponse(ctx, projectID, derefInt(m.Id), apiclient.GrantMachineRoleJSONRequestBody{RoleId: roleID})
	if err != nil {
		return fmt.Errorf("failed to grant role: %w", err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return apiError("grant machine role", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Granted role '%s' to machine identity '%s'\n", machineGrantRoleName, derefStr(m.Name))
	return nil
}

var machineRevokeRoleCmd = &cobra.Command{
	Use:   "revoke-role <name|id>",
	Short: "Remove a project-scoped role grant from a machine identity",
	Long:  "Revoke a previously granted project-scoped role (distinct from `machine revoke`, which revokes the whole machine identity).",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineRevokeRole,
}

func init() {
	machineRevokeRoleCmd.Flags().StringVar(&machineRevokeRoleProjectName, "project", "", "Project name or numeric ID")
	machineRevokeRoleCmd.Flags().StringVar(&machineRevokeRoleName, "role", "", "Role name to revoke (required)")
	machineCmd.AddCommand(machineRevokeRoleCmd)
}

func runMachineRevokeRole(cmd *cobra.Command, args []string) error {
	if machineRevokeRoleName == "" {
		return usageErrorf("--role is required")
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	_, projectID, err := resolveMachineProjectID(client, machineRevokeRoleProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}
	roleID, err := resolveRoleIDByName(ctx, client, machineRevokeRoleName)
	if err != nil {
		return err
	}
	resp, err := client.RemoveMachineRoleWithResponse(ctx, projectID, derefInt(m.Id), roleID, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return apiError("revoke machine role", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Revoked role '%s' from machine identity '%s'\n", machineRevokeRoleName, derefStr(m.Name))
	return nil
}

var machineRolesCmd = &cobra.Command{
	Use:   "roles <name|id>",
	Short: "List a machine identity's project-scoped roles",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineRoles,
}

func init() {
	machineRolesCmd.Flags().StringVar(&machineRolesProjectName, "project", "", "Project name or numeric ID")
	machineCmd.AddCommand(machineRolesCmd)
}

func runMachineRoles(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	_, projectID, err := resolveMachineProjectID(client, machineRolesProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}
	resp, err := client.ListMachineRolesWithResponse(ctx, projectID, derefInt(m.Id))
	if err != nil {
		return fmt.Errorf("failed to list machine roles: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return apiError("list machine roles", resp.StatusCode(), resp.Body)
	}
	roles := derefRoleRefSlice(resp.JSON200.Data.Roles)
	if len(roles) == 0 {
		fmt.Printf("No roles granted to machine identity %q.\n", derefStr(m.Name))
		return nil
	}
	fmt.Printf("%-5s %s\n", "ID", "NAME")
	fmt.Printf("%-5s %s\n", "-----", "----------------")
	for _, r := range roles {
		fmt.Printf("%-5d %s\n", derefInt(r.Id), cliout.SanitizeForTerminal(derefStr(r.Name)))
	}
	return nil
}
