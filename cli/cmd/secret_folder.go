// secret_folder.go — keyorix secret folder create/list/delete.
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var secretFolderCmd = &cobra.Command{
	Use:   "folder",
	Short: "Manage secret folders",
	Long:  "Commands for creating, listing, and deleting secret folder nodes.",
}

func init() {
	SecretCmd.AddCommand(secretFolderCmd)
}

// ── create ──────────────────────────────────────────────────────────────────────

var (
	secretFolderCreateName    string
	secretFolderCreateProject int
	secretFolderCreateEnvID   int
	secretFolderCreateParent  int
)

var secretFolderCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a folder",
	RunE:  runSecretFolderCreate,
}

func init() {
	secretFolderCreateCmd.Flags().StringVar(&secretFolderCreateName, "name", "", "Folder name (required)")
	secretFolderCreateCmd.Flags().IntVar(&secretFolderCreateProject, "project", 1, "Project ID")
	secretFolderCreateCmd.Flags().IntVar(&secretFolderCreateEnvID, "environment", 1, "Environment ID")
	secretFolderCreateCmd.Flags().IntVar(&secretFolderCreateParent, "parent", 0, "Parent folder ID (0 = root)")
	secretFolderCmd.AddCommand(secretFolderCreateCmd)
}

func runSecretFolderCreate(cmd *cobra.Command, args []string) error {
	if secretFolderCreateName == "" {
		return usageErrorf("folder name is required (use --name)")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	body := apiclient.CreateFolderJSONRequestBody{
		Name:          secretFolderCreateName,
		EnvironmentId: secretFolderCreateEnvID,
	}
	if secretFolderCreateProject != 0 {
		body.ProjectId = &secretFolderCreateProject
	}
	if secretFolderCreateParent != 0 {
		body.ParentId = &secretFolderCreateParent
	}
	resp, err := client.CreateFolderWithResponse(context.Background(), body)
	if err != nil {
		return fmt.Errorf("failed to create folder: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("failed to create folder", resp.StatusCode(), resp.Body)
	}
	printFolder(resp.JSON200.Data)
	return nil
}

func printFolder(f *apiclient.Secret) {
	fmt.Println("Folder created successfully!")
	fmt.Printf("ID:          %d\n", derefSecretInt(f.Id))
	fmt.Printf("Name:        %s\n", derefStr(f.Name))
	fmt.Printf("Project:     %d\n", derefSecretInt(f.ProjectId))
	fmt.Printf("Environment: %d\n", derefSecretInt(f.EnvironmentId))
	if f.ParentId != nil {
		fmt.Printf("Parent ID:   %d\n", *f.ParentId)
	}
	if f.CreatedAt != nil {
		fmt.Printf("Created:     %s\n", f.CreatedAt.Format(time.RFC3339))
	}
}

// ── list ────────────────────────────────────────────────────────────────────────

var (
	secretFolderListProject int
	secretFolderListParent  int
)

var secretFolderListCmd = &cobra.Command{
	Use:   "list",
	Short: "List folders",
	RunE:  runSecretFolderList,
}

func init() {
	secretFolderListCmd.Flags().IntVar(&secretFolderListProject, "project", 0, "Filter by project ID")
	secretFolderListCmd.Flags().IntVar(&secretFolderListParent, "parent", 0, "Filter by parent folder ID (0 = no filter)")
	secretFolderCmd.AddCommand(secretFolderListCmd)
}

func runSecretFolderList(cmd *cobra.Command, args []string) error {
	if err := checkOutputFormat(folderListFormat); err != nil {
		return err
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	params := &apiclient.ListFoldersParams{}
	if secretFolderListProject != 0 {
		params.ProjectId = &secretFolderListProject
	}
	if secretFolderListParent != 0 {
		params.ParentId = &secretFolderListParent
	}
	resp, err := client.ListFoldersWithResponse(context.Background(), params)
	if err != nil {
		return fmt.Errorf("failed to list folders: %w", err)
	}
	if resp.JSON200 == nil {
		return httpStatusError("failed to list folders", resp.StatusCode(), resp.Body)
	}
	folders := derefSecretSlice(resp.JSON200.Data)
	return emitList(folderListFormat, folders, func() error {
		printFolderList(derefSecretSlice(resp.JSON200.Data))
		return nil
	})
}

func printFolderList(folders []apiclient.Secret) {
	if len(folders) == 0 {
		fmt.Println("No folders found.")
		return
	}
	fmt.Printf("%-6s  %-30s  %-10s  %-12s  %-10s\n", "ID", "Name", "Project", "Environment", "Parent")
	fmt.Printf("%-6s  %-30s  %-10s  %-12s  %-10s\n", "------", "------------------------------", "----------", "------------", "----------")
	for _, f := range folders {
		parentStr := "-"
		if f.ParentId != nil {
			parentStr = fmt.Sprintf("%d", *f.ParentId)
		}
		fmt.Printf("%-6d  %-30s  %-10d  %-12d  %-10s\n", derefSecretInt(f.Id), derefStr(f.Name), derefSecretInt(f.ProjectId), derefSecretInt(f.EnvironmentId), parentStr)
	}
}

func derefSecretSlice(s *[]apiclient.Secret) []apiclient.Secret {
	if s == nil {
		return nil
	}
	return *s
}

// ── delete ──────────────────────────────────────────────────────────────────────

var (
	secretFolderDeleteID    int
	secretFolderDeleteForce bool
)

var secretFolderDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a folder",
	RunE:  runSecretFolderDelete,
}

func init() {
	secretFolderDeleteCmd.Flags().IntVar(&secretFolderDeleteID, "id", 0, "Folder ID to delete (required)")
	secretFolderDeleteCmd.Flags().BoolVar(&secretFolderDeleteForce, "force", false, "Skip confirmation prompt")
	secretFolderCmd.AddCommand(secretFolderDeleteCmd)
}

func confirmSecretFolderDeletion(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (yes/no): ", prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}

func runSecretFolderDelete(cmd *cobra.Command, args []string) error {
	if secretFolderDeleteID == 0 {
		return usageErrorf("folder ID is required (use --id)")
	}
	if !secretFolderDeleteForce {
		prompt := fmt.Sprintf("Delete folder %d? This cannot be undone.", secretFolderDeleteID)
		if !confirmSecretFolderDeletion(prompt) {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.DeleteFolderWithResponse(context.Background(), secretFolderDeleteID)
	if err != nil {
		return fmt.Errorf("failed to delete folder: %w", err)
	}
	if resp.StatusCode() != 204 {
		return httpStatusError("failed to delete folder", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Folder %d deleted.\n", secretFolderDeleteID)
	return nil
}
