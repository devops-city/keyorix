// group.go ports `keyorix group` (docs/cli-split-inventory.md §2.2, PR 3): group
// CRUD and membership management, REST only. Same flags, output, and exit codes as
// the old CLI's internal/cli/group package's remote-mode branch (ADR-108 Decision A
// removes local mode entirely -- every command here is the "remote" branch of its
// old-CLI counterpart; the confirmation prompt on `group delete` is ported unchanged).
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage groups",
	Long:  "Create, read, update, delete, list groups and manage membership.",
}

func init() {
	rootCmd.AddCommand(groupCmd)
}

// groupAPIClient resolves the stored credentials and builds a client plus the
// resolved server URL, the shared pre-flight every group subcommand needs (the
// server URL is echoed in several of this package's status messages, matching
// the old CLI's remote-mode output).
func groupAPIClient() (*apiclient.ClientWithResponses, string, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, "", fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, "", err
	}
	client, err := newAPIClient(serverURL, token)
	return client, serverURL, err
}

// ── create ──────────────────────────────────────────────────────────────────────

var (
	groupCreateName        string
	groupCreateDescription string
)

var groupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a group",
	RunE:  runGroupCreate,
}

func init() {
	groupCreateCmd.Flags().StringVar(&groupCreateName, "name", "", "Group name (required)")
	groupCreateCmd.Flags().StringVar(&groupCreateDescription, "description", "", "Description")
	groupCmd.AddCommand(groupCreateCmd)
}

func runGroupCreate(cmd *cobra.Command, args []string) error {
	if groupCreateName == "" {
		return fmt.Errorf("name is required (use --name)")
	}
	client, serverURL, err := groupAPIClient()
	if err != nil {
		return err
	}
	fmt.Printf("Creating group %q on %s...\n", groupCreateName, serverURL)

	body := apiclient.CreateGroupJSONRequestBody{Name: groupCreateName}
	if groupCreateDescription != "" {
		body.Description = &groupCreateDescription
	}
	resp, err := client.CreateGroupWithResponse(context.Background(), body)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return httpStatusError("failed to create group", resp.StatusCode(), resp.Body)
	}
	g := *resp.JSON201.Data
	fmt.Printf("Group created: id=%d name=%s\n", derefInt(g.Id), derefStr(g.Name))
	return nil
}

// ── get ─────────────────────────────────────────────────────────────────────────

var groupGetID int

var groupGetCmd = &cobra.Command{
	Use:   "get [group]",
	Short: "Get a group by name or id",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGroupGet,
}

func init() {
	groupGetCmd.Flags().IntVar(&groupGetID, "id", 0, groupIDFlagUsage)
	groupCmd.AddCommand(groupGetCmd)
}

func runGroupGet(cmd *cobra.Command, args []string) error {
	ref, err := groupRef(args, groupGetID, "")
	if err != nil {
		return err
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	gid, err := resolveRBACGroupIDOnly(context.Background(), client, ref)
	if err != nil {
		return err
	}
	resp, err := client.GetGroupWithResponse(context.Background(), gid)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to get group", resp.StatusCode(), resp.Body)
	}
	g := *resp.JSON200.Data
	fmt.Printf("ID: %d\nName: %s\nDescription: %s\n", derefInt(g.Id), derefStr(g.Name), derefStr(g.Description))
	return nil
}

// ── update ──────────────────────────────────────────────────────────────────────

var (
	groupUpdateID          int
	groupUpdateName        string
	groupUpdateDescription string
)

var groupUpdateCmd = &cobra.Command{
	Use:   "update [group]",
	Short: "Update a group",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGroupUpdate,
}

func init() {
	groupUpdateCmd.Flags().IntVar(&groupUpdateID, "id", 0, groupIDFlagUsage)
	groupUpdateCmd.Flags().StringVar(&groupUpdateName, "name", "", "New name")
	groupUpdateCmd.Flags().StringVar(&groupUpdateDescription, "description", "", "New description")
	groupCmd.AddCommand(groupUpdateCmd)
}

func runGroupUpdate(cmd *cobra.Command, args []string) error {
	ref, err := groupRef(args, groupUpdateID, "")
	if err != nil {
		return err
	}
	if groupUpdateName == "" && groupUpdateDescription == "" {
		return fmt.Errorf("provide at least one of --name or --description")
	}
	client, serverURL, err := groupAPIClient()
	if err != nil {
		return err
	}
	gid, err := resolveRBACGroupIDOnly(context.Background(), client, ref)
	if err != nil {
		return err
	}
	fmt.Printf("Updating group %d on %s...\n", gid, serverURL)

	body := apiclient.UpdateGroupJSONRequestBody{}
	if groupUpdateName != "" {
		body.Name = &groupUpdateName
	}
	if groupUpdateDescription != "" {
		body.Description = &groupUpdateDescription
	}
	resp, err := client.UpdateGroupWithResponse(context.Background(), gid, body)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to update group", resp.StatusCode(), resp.Body)
	}
	g := *resp.JSON200.Data
	fmt.Printf("Group updated: id=%d name=%s\n", derefInt(g.Id), derefStr(g.Name))
	return nil
}

// ── delete ──────────────────────────────────────────────────────────────────────

var (
	groupDeleteID    int
	groupDeleteForce bool
)

var groupDeleteCmd = &cobra.Command{
	Use:   "delete [group]",
	Short: "Delete a group",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGroupDelete,
}

func init() {
	groupDeleteCmd.Flags().IntVar(&groupDeleteID, "id", 0, groupIDFlagUsage)
	groupDeleteCmd.Flags().BoolVar(&groupDeleteForce, "force", false, "Skip the confirmation prompt")
	groupCmd.AddCommand(groupDeleteCmd)
}

// runGroupDelete mirrors the old CLI's confirm-then-delete flow: the group's
// name is fetched first (best-effort -- an unreachable/erroring GET just falls
// back to an id-only label) so the confirmation prompt and the final result
// both name the actual target.
func runGroupDelete(cmd *cobra.Command, args []string) error {
	ref, err := groupRef(args, groupDeleteID, "")
	if err != nil {
		return err
	}
	client, serverURL, err := groupAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	gid, err := resolveRBACGroupIDOnly(ctx, client, ref)
	if err != nil {
		return err
	}

	label := fmt.Sprintf("group %d", gid)
	if resp, gerr := client.GetGroupWithResponse(ctx, gid); gerr == nil && resp.JSON200 != nil && resp.JSON200.Data != nil {
		g := *resp.JSON200.Data
		label = fmt.Sprintf("group %d (%s)", derefInt(g.Id), derefStr(g.Name))
	}

	if !groupDeleteForce {
		if !confirmYesNo(fmt.Sprintf("Delete %s on %s? This cannot be undone.", label, serverURL)) {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	fmt.Printf("Deleting %s on %s...\n", label, serverURL)
	resp, err := client.DeleteGroupWithResponse(ctx, gid)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("failed to delete group", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Deleted %s.\n", label)
	return nil
}

// confirmYesNo prompts on stdin and reports whether the operator typed "y"/"yes"
// (case-insensitive). Anything else -- including a blank line -- is treated as
// "no", so an accidental Enter never confirms a destructive action.
func confirmYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (yes/no): ", prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}

// ── list ────────────────────────────────────────────────────────────────────────

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups",
	RunE:  runGroupList,
}

func init() {
	groupCmd.AddCommand(groupListCmd)
}

func runGroupList(cmd *cobra.Command, args []string) error {
	if err := checkOutputFormat(groupListFormat); err != nil {
		return err
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListGroupsWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to list groups", resp.StatusCode(), resp.Body)
	}
	groups := derefGroupSlice(resp.JSON200.Data.Groups)
	return emitList(groupListFormat, groups, func() error {
		fmt.Printf("%-6s %-25s %s\n", "ID", "NAME", "DESCRIPTION")
		for _, g := range groups {
			fmt.Printf("%-6d %-25s %s\n", derefInt(g.Id), cliout.SanitizeForTerminal(derefStr(g.Name)), cliout.SanitizeForTerminal(derefStr(g.Description)))
		}
		return nil
	})
}

// ── members ─────────────────────────────────────────────────────────────────────

var groupMembersID int

var groupMembersCmd = &cobra.Command{
	Use:   "members [group]",
	Short: "List members of a group",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGroupMembers,
}

func init() {
	groupMembersCmd.Flags().IntVar(&groupMembersID, "id", 0, groupIDFlagUsage)
	groupCmd.AddCommand(groupMembersCmd)
}

func runGroupMembers(cmd *cobra.Command, args []string) error {
	ref, err := groupRef(args, groupMembersID, "")
	if err != nil {
		return err
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	gid, err := resolveRBACGroupIDOnly(context.Background(), client, ref)
	if err != nil {
		return err
	}
	resp, err := client.GetGroupMembersWithResponse(context.Background(), gid)
	if err != nil {
		return fmt.Errorf("failed to list members: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to list members", resp.StatusCode(), resp.Body)
	}
	members := derefUserSummarySlice(resp.JSON200.Data.Members)
	fmt.Printf("Group %d — %d member(s)\n", gid, len(members))
	fmt.Printf("%-6s %-20s %-30s\n", "ID", "USERNAME", "EMAIL")
	for _, u := range members {
		fmt.Printf("%-6d %-20s %-30s\n", derefInt(u.Id), cliout.SanitizeForTerminal(derefStr(u.Username)), cliout.SanitizeForTerminal(derefStr(u.Email)))
	}
	return nil
}

// ── add-member / remove-member ─────────────────────────────────────────────────
//
// Both take the group as a positional <group> (name or id) or --group / --group-id,
// and the user as --user (username, email or id) or --user-id, so they read like
// `rbac assign-role-to-group --group` and `rbac assign-role --user` (#2981).

var (
	groupAddMemberGroupID   int
	groupAddMemberGroup     string
	groupAddMemberUserID    int
	groupAddMemberUser      string
	groupAddMemberProjectID int
)

var groupAddMemberCmd = &cobra.Command{
	Use:   "add-member [group]",
	Short: "Add a user to a group",
	Example: `  keyorix group add-member platform-team --user alice
  keyorix group add-member --group-id 1 --user-id 2`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGroupAddMember,
}

func init() {
	groupAddMemberCmd.Flags().IntVar(&groupAddMemberGroupID, "group-id", 0, groupIDFlagUsage)
	groupAddMemberCmd.Flags().StringVar(&groupAddMemberGroup, "group", "", rbacGroupFlagUsage)
	groupAddMemberCmd.Flags().IntVar(&groupAddMemberUserID, "user-id", 0, "User ID (or use --user)")
	groupAddMemberCmd.Flags().StringVar(&groupAddMemberUser, "user", "", groupUserFlagUsage)
	groupAddMemberCmd.Flags().IntVar(&groupAddMemberProjectID, "project", 0, "Scope membership to a project (0 = global)")
	groupCmd.AddCommand(groupAddMemberCmd)
}

func runGroupAddMember(cmd *cobra.Command, args []string) error {
	gref, uref, err := groupMemberRefs(args, groupAddMemberGroupID, groupAddMemberGroup, groupAddMemberUserID, groupAddMemberUser)
	if err != nil {
		return err
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	gid, uid, err := resolveGroupMemberIDs(ctx, client, gref, uref)
	if err != nil {
		return err
	}
	body := apiclient.AddGroupMemberJSONRequestBody{UserId: uid}
	if groupAddMemberProjectID != 0 {
		body.ProjectId = &groupAddMemberProjectID
	}
	resp, err := client.AddGroupMemberWithResponse(ctx, gid, body)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}
	if resp.StatusCode() != 200 {
		return httpStatusError("failed to add member", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("User %d added to group %d (project %d).\n", uid, gid, groupAddMemberProjectID)
	return nil
}

var (
	groupRemoveMemberGroupID   int
	groupRemoveMemberGroup     string
	groupRemoveMemberUserID    int
	groupRemoveMemberUser      string
	groupRemoveMemberProjectID int
)

var groupRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member [group]",
	Short: "Remove a user from a group",
	Example: `  keyorix group remove-member platform-team --user alice
  keyorix group remove-member --group-id 1 --user-id 2`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGroupRemoveMember,
}

func init() {
	groupRemoveMemberCmd.Flags().IntVar(&groupRemoveMemberGroupID, "group-id", 0, groupIDFlagUsage)
	groupRemoveMemberCmd.Flags().StringVar(&groupRemoveMemberGroup, "group", "", rbacGroupFlagUsage)
	groupRemoveMemberCmd.Flags().IntVar(&groupRemoveMemberUserID, "user-id", 0, "User ID (or use --user)")
	groupRemoveMemberCmd.Flags().StringVar(&groupRemoveMemberUser, "user", "", groupUserFlagUsage)
	groupRemoveMemberCmd.Flags().IntVar(&groupRemoveMemberProjectID, "project", 0, "Scope membership to a project (0 = global)")
	groupCmd.AddCommand(groupRemoveMemberCmd)
}

func runGroupRemoveMember(cmd *cobra.Command, args []string) error {
	gref, uref, err := groupMemberRefs(args, groupRemoveMemberGroupID, groupRemoveMemberGroup, groupRemoveMemberUserID, groupRemoveMemberUser)
	if err != nil {
		return err
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	gid, uid, err := resolveGroupMemberIDs(ctx, client, gref, uref)
	if err != nil {
		return err
	}
	var params *apiclient.RemoveGroupMemberParams
	if groupRemoveMemberProjectID != 0 {
		params = &apiclient.RemoveGroupMemberParams{ProjectId: &groupRemoveMemberProjectID}
	}
	resp, err := client.RemoveGroupMemberWithResponse(ctx, gid, uid, params)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("failed to remove member", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("User %d removed from group %d (project %d).\n", uid, gid, groupRemoveMemberProjectID)
	return nil
}

// ── shared helpers ──────────────────────────────────────────────────────────────

func derefGroupSlice(s *[]apiclient.Group) []apiclient.Group {
	if s == nil {
		return nil
	}
	return *s
}

func derefUserSummarySlice(s *[]apiclient.UserSummary) []apiclient.UserSummary {
	if s == nil {
		return nil
	}
	return *s
}

const (
	groupIDFlagUsage   = "Group ID (alternative to the positional <group>, which also takes a name)"
	groupUserFlagUsage = "User username, email or numeric ID (alternative to --user-id)"
)

// groupRef picks the group a command acts on: the positional <group> (name or id)
// wins, then --group (name or id), then the numeric id flag. It only decides WHAT
// was asked for; resolveRBACGroupIDOnly turns it into an id. Existing --id /
// --group-id invocations keep working unchanged (#2981).
func groupRef(args []string, idFlag int, nameFlag string) (string, error) {
	switch {
	case len(args) > 0 && args[0] != "":
		if idFlag != 0 && strconv.Itoa(idFlag) != args[0] {
			return "", fmt.Errorf("group given twice and differently: %q and --id/--group-id %d", args[0], idFlag)
		}
		return args[0], nil
	case nameFlag != "":
		return nameFlag, nil
	case idFlag != 0:
		return strconv.Itoa(idFlag), nil
	}
	return "", fmt.Errorf("group is required: pass the group name or id (e.g. `keyorix group get platform-team`) or use --id")
}

// resolveRBACGroupIDOnly is resolveRBACGroupID without the display name. A numeric
// ref is used as-is (no lookup), so id-based invocations make the same requests as before.
func resolveRBACGroupIDOnly(ctx context.Context, client *apiclient.ClientWithResponses, ref string) (int, error) {
	id, _, err := resolveRBACGroupID(ctx, client, ref)
	return id, err
}

// groupMemberRefs gathers the group and user references for add-member/remove-member.
func groupMemberRefs(args []string, groupID int, groupName string, userID int, userRef string) (gref, uref string, err error) {
	gref, err = groupRef(args, groupID, groupName)
	if err != nil {
		return "", "", err
	}
	switch {
	case userRef != "":
		if userID != 0 && strconv.Itoa(userID) != userRef {
			return "", "", fmt.Errorf("user given twice and differently: --user %q and --user-id %d", userRef, userID)
		}
		uref = userRef
	case userID != 0:
		uref = strconv.Itoa(userID)
	default:
		return "", "", fmt.Errorf("user is required: pass --user <username|email|id> (or --user-id)")
	}
	return gref, uref, nil
}

func resolveGroupMemberIDs(ctx context.Context, client *apiclient.ClientWithResponses, gref, uref string) (gid, uid int, err error) {
	if gid, err = resolveRBACGroupIDOnly(ctx, client, gref); err != nil {
		return 0, 0, err
	}
	if uid, err = resolveUserRef(ctx, client, uref); err != nil {
		return 0, 0, err
	}
	return gid, uid, nil
}

// resolveUserRef resolves a numeric id, an email or a username to a user id. A
// numeric ref is used as-is; otherwise it is matched case-insensitively against
// the user list (email when the ref contains "@", else username).
func resolveUserRef(ctx context.Context, client *apiclient.ClientWithResponses, ref string) (int, error) {
	if id, err := strconv.Atoi(ref); err == nil {
		return id, nil
	}
	pageSize := 1000
	resp, err := client.ListUsersWithResponse(ctx, &apiclient.ListUsersParams{PageSize: &pageSize})
	if err != nil {
		return 0, fmt.Errorf("failed to list users: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Users == nil {
		return 0, httpStatusError("failed to list users", resp.StatusCode(), resp.Body)
	}
	byEmail := strings.Contains(ref, "@")
	for _, u := range *resp.JSON200.Data.Users {
		cand := derefStr(u.Username)
		if byEmail {
			cand = derefStr(u.Email)
		}
		if strings.EqualFold(cand, ref) {
			return derefInt(u.Id), nil
		}
	}
	return 0, fmt.Errorf("user %q not found", ref)
}
