// machine_binding.go — `keyorix machine binding` — manage a machine identity's
// OIDC federation bindings (ADR-031).
package cmd

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var (
	machineBindingProjectName string
	machineBindingIssuer      string
	machineBindingSubject     string
)

var machineBindingCmd = &cobra.Command{
	Use:   "binding",
	Short: "Manage a machine identity's OIDC federation bindings (ADR-031)",
	Long:  "Bind external OIDC principals (issuer + subject) to a machine identity so workloads can authenticate with a platform-issued JWT instead of a stored secret.",
}

var machineBindingAddCmd = &cobra.Command{
	Use:   "add <machine>",
	Short: "Bind an OIDC (issuer, subject) to a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineBindingAdd,
}

var machineBindingListCmd = &cobra.Command{
	Use:   "list <machine>",
	Short: "List a machine identity's OIDC bindings",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineBindingList,
}

var machineBindingRmCmd = &cobra.Command{
	Use:   "rm <machine> <binding-id>",
	Short: "Remove an OIDC binding from a machine identity",
	Args:  cobra.ExactArgs(2),
	RunE:  runMachineBindingRm,
}

func init() {
	for _, c := range []*cobra.Command{machineBindingAddCmd, machineBindingListCmd, machineBindingRmCmd} {
		c.Flags().StringVar(&machineBindingProjectName, "project", "", "Project name or numeric ID")
	}
	machineBindingAddCmd.Flags().StringVar(&machineBindingIssuer, "issuer", "", "OIDC issuer (the token's iss claim) (required)")
	machineBindingAddCmd.Flags().StringVar(&machineBindingSubject, "subject", "", "OIDC subject (the token's sub claim) (required)")
	machineBindingCmd.AddCommand(machineBindingAddCmd, machineBindingListCmd, machineBindingRmCmd)
	machineCmd.AddCommand(machineBindingCmd)
}

func runMachineBindingAdd(cmd *cobra.Command, args []string) error {
	if machineBindingIssuer == "" || machineBindingSubject == "" {
		return usageErrorf("--issuer and --subject are required")
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineBindingProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}

	resp, err := client.CreateOIDCBindingWithResponse(context.Background(), projectID, derefInt(m.Id), apiclient.CreateOIDCBindingJSONRequestBody{
		Issuer:  machineBindingIssuer,
		Subject: machineBindingSubject,
	})
	if err != nil {
		return fmt.Errorf("failed to create OIDC binding: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return httpStatusError("failed to create OIDC binding", resp.StatusCode(), resp.Body)
	}
	b := *resp.JSON201.Data
	fmt.Printf("OIDC binding created: id=%d issuer=%q subject=%q → machine %q\n", derefInt(b.Id), derefStr(b.Issuer), derefStr(b.Subject), derefStr(m.Name))
	return nil
}

func runMachineBindingList(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineBindingProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}

	resp, err := client.ListOIDCBindingsWithResponse(context.Background(), projectID, derefInt(m.Id))
	if err != nil {
		return fmt.Errorf("failed to list OIDC bindings: %w", err)
	}
	if resp.StatusCode() != 200 {
		return httpStatusError("failed to list OIDC bindings", resp.StatusCode(), resp.Body)
	}
	var rows []apiclient.OIDCBinding
	if resp.JSON200 != nil && resp.JSON200.Data != nil && resp.JSON200.Data.Bindings != nil {
		rows = *resp.JSON200.Data.Bindings
	}
	if len(rows) == 0 {
		fmt.Printf("No OIDC bindings for machine %q.\n", derefStr(m.Name))
		return nil
	}
	t := cliout.NewStdoutTable("ID", "ISSUER", "SUBJECT", "CREATED AT")
	for _, b := range rows {
		created := "—"
		if b.CreatedAt != nil && !b.CreatedAt.IsZero() {
			created = b.CreatedAt.Format("2006-01-02 15:04:05")
		}
		t.Row(derefInt(b.Id), derefStr(b.Issuer), derefStr(b.Subject), created)
	}
	return t.Flush()
}

func runMachineBindingRm(cmd *cobra.Command, args []string) error {
	bindingID, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid binding ID %q: must be a number", args[1])
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineBindingProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}

	resp, err := client.DeleteOIDCBindingWithResponse(context.Background(), projectID, derefInt(m.Id), bindingID)
	if err != nil {
		return fmt.Errorf("failed to remove OIDC binding: %w", err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return httpStatusError("failed to remove OIDC binding", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("OIDC binding %d removed from machine %q.\n", bindingID, derefStr(m.Name))
	return nil
}
