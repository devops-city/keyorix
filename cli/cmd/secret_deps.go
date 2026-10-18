// secret_deps.go — keyorix secret deps (ADR-052): inspect and manage a
// secret's dependency graph, and see the blast radius of rotating it.
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var secretDepNote string

var secretDepsCmd = &cobra.Command{
	Use:     "deps",
	Aliases: []string{"dependencies"},
	Short:   "Inspect and manage a secret's dependency graph",
	Long: `Manage the secret dependency graph (ADR-052): declare that one secret
depends on another, list a secret's dependencies and dependents, and see the
blast radius of rotating it.`,
}

func init() {
	SecretCmd.AddCommand(secretDepsCmd)
}

var secretDepsListCmd = &cobra.Command{
	Use:          "list <secret-id>",
	Short:        "Show what a secret depends on and what depends on it",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		if err := checkOutputFormat(depsListFormat); err != nil {
			return err
		}
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ListSecretDependenciesWithResponse(context.Background(), id)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("list secret dependencies", resp.StatusCode(), resp.Body)
		}
		if depsListFormat != outputTable {
			// One object: what the secret depends on and what depends on it.
			return printStructured(depsListFormat, resp.JSON200.Data)
		}
		printSecretDependencies(resp.JSON200.Data)
		return nil
	},
}

var secretDepsAddCmd = &cobra.Command{
	Use:          "add <secret-id> <depends-on-id>",
	Short:        "Declare that <secret-id> depends on <depends-on-id>",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		dependsOn, err := parseSecretArg(args[1])
		if err != nil {
			return err
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		body := apiclient.AddSecretDependencyJSONRequestBody{DependsOnId: dependsOn}
		if secretDepNote != "" {
			body.Note = &secretDepNote
		}
		resp, err := client.AddSecretDependencyWithResponse(context.Background(), id, body)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("add secret dependency", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Added: secret %d now depends on secret %d (edge %d).\n", id, dependsOn, derefSecretInt(resp.JSON200.Data.Id))
		return nil
	},
}

var secretDepsRemoveCmd = &cobra.Command{
	Use:          "rm <secret-id> <edge-id>",
	Aliases:      []string{"remove", "delete"},
	Short:        "Remove a dependency edge (edge id from `deps list`)",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		edgeID, err := parseSecretArg(args[1])
		if err != nil {
			return err
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.RemoveSecretDependencyWithResponse(context.Background(), id, edgeID)
		if err != nil {
			return err
		}
		// The server responds 200 with a body (sendSuccess), not 204 -- see
		// server/http/handlers/secret_dependencies.go's RemoveSecretDependency
		// and its success-path tests (e.g. TestRemoveSecretDependency_SuccessPath_DepCov).
		// This check previously required 204, so it reported failure on every
		// successful removal.
		if resp.StatusCode() != 200 {
			return httpStatusError("remove secret dependency", resp.StatusCode(), resp.Body)
		}
		fmt.Printf("Removed dependency edge %d from secret %d.\n", edgeID, id)
		return nil
	},
}

var secretDepsImpactCmd = &cobra.Command{
	Use:          "impact <secret-id>",
	Short:        "Show the blast radius of rotating a secret (transitive dependents)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.GetSecretImpactWithResponse(context.Background(), id)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return httpStatusError("get secret impact", resp.StatusCode(), resp.Body)
		}
		printSecretImpact(resp.JSON200.Data)
		return nil
	},
}

func printSecretDependencies(v *apiclient.SecretDependencies) {
	dependsOn := derefSecretDependencyEdgeSlice(v.DependsOn)
	dependents := derefSecretDependencyEdgeSlice(v.Dependents)
	fmt.Printf("Depends on (%d):\n", len(dependsOn))
	if len(dependsOn) == 0 {
		fmt.Println("  (none -- this secret stands alone)")
	}
	for _, e := range dependsOn {
		fmt.Printf("  edge %-5d -> secret %-5d %s%s\n", derefSecretInt(e.Id), derefSecretInt(e.SecretId), derefStr(e.SecretName), depNoteSuffix(derefStr(e.Note)))
	}
	fmt.Printf("Used by (%d):\n", len(dependents))
	if len(dependents) == 0 {
		fmt.Println("  (none)")
	}
	for _, e := range dependents {
		fmt.Printf("  edge %-5d <- secret %-5d %s%s\n", derefSecretInt(e.Id), derefSecretInt(e.SecretId), derefStr(e.SecretName), depNoteSuffix(derefStr(e.Note)))
	}
}

func printSecretImpact(v *apiclient.SecretImpact) {
	affected := derefSecretImpactedSlice(v.Affected)
	if len(affected) == 0 {
		fmt.Printf("Rotating %s (secret %d) affects no other secrets.\n", derefStr(v.SecretName), derefSecretInt(v.SecretId))
		return
	}
	fmt.Printf("Rotating %s (secret %d) affects %d secret(s):\n", derefStr(v.SecretName), derefSecretInt(v.SecretId), len(affected))
	for _, a := range affected {
		depth := derefSecretInt(a.Depth)
		fmt.Printf("  %-5d %-26s (%d hop%s)\n", derefSecretInt(a.SecretId), derefStr(a.SecretName), depth, depPlural(depth))
	}
}

func depNoteSuffix(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return "  -- " + note
}

func depPlural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func derefSecretDependencyEdgeSlice(s *[]apiclient.SecretDependencyEdge) []apiclient.SecretDependencyEdge {
	if s == nil {
		return nil
	}
	return *s
}

func derefSecretImpactedSlice(s *[]apiclient.SecretImpactedSecret) []apiclient.SecretImpactedSecret {
	if s == nil {
		return nil
	}
	return *s
}

func init() {
	secretDepsAddCmd.Flags().StringVar(&secretDepNote, "note", "", "Optional note describing the dependency")
	secretDepsCmd.AddCommand(secretDepsListCmd, secretDepsAddCmd, secretDepsRemoveCmd, secretDepsImpactCmd)
}
