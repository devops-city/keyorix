// secret_risk.go — keyorix secret score/blast-radius/cert/audit.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// ── score ────────────────────────────────────────────────────────────────────

var scoreID int

var secretScoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Show the risk score for a secret",
	Long: `Print the composite risk score for a secret.

The score is 0-100 (higher = riskier) and is broken down into four weighted
factors: rotation age (30%), expiry (30%), usage (20%), and exposure (20%).`,
	SilenceUsage: true,
	RunE:         runSecretScore,
}

func runSecretScore(_ *cobra.Command, _ []string) error {
	if scoreID == 0 {
		return usageErrorf("--id is required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetSecretRiskWithResponse(context.Background(), scoreID)
	if err != nil {
		return fmt.Errorf("failed to get risk score: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get risk score", resp.StatusCode(), resp.Body)
	}
	r := resp.JSON200.Data
	fmt.Printf("Secret: %s\n", derefStr(r.SecretName))
	band := ""
	if r.Band != nil {
		band = strings.ToUpper(string(*r.Band))
	}
	fmt.Printf("Score:  %d/100  band: %s\n", derefInt(r.Score), band)
	if derefBool(r.Degraded) {
		fmt.Println("  (exposure data incomplete — score is a lower bound)")
	}
	fmt.Println()
	fmt.Println("Factors:")
	if r.Factors != nil {
		for _, f := range *r.Factors {
			weight := float32(0)
			if f.Weight != nil {
				weight = *f.Weight
			}
			fmt.Printf("  %-14s score=%-3d  weight=%-4s  detail=%s\n",
				derefStr(f.Key), derefInt(f.Score), fmt.Sprintf("%.0f%%", weight*100), derefStr(f.Detail))
		}
	}
	if band == "HIGH" {
		fmt.Fprintln(os.Stderr, "This secret is HIGH risk. Consider rotating or restricting access.")
	}
	return nil
}

func init() {
	secretScoreCmd.Flags().IntVar(&scoreID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(secretScoreCmd)
}

// ── blast-radius ─────────────────────────────────────────────────────────────

var secretBlastRadiusCmd = &cobra.Command{
	Use:          "blast-radius <secret-id>",
	Short:        "Show the enriched blast radius of rotating or deleting a secret",
	Long:         `Show all downstream dependents of a secret (recursive), each annotated with owner, project, hop depth, and risk level (critical/high/medium/low).`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runSecretBlastRadius,
}

func runSecretBlastRadius(_ *cobra.Command, args []string) error {
	id, err := parseSecretArg(args[0])
	if err != nil {
		return err
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetSecretBlastRadiusWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get blast radius", resp.StatusCode(), resp.Body)
	}
	printBlastRadius(resp.JSON200.Data)
	return nil
}

func printBlastRadius(r *apiclient.BlastRadiusReport) {
	if derefInt(r.TotalImpact) == 0 {
		fmt.Printf("No dependents found for secret %q (id %d).\n", derefStr(r.SourceSecretName), derefInt(r.SourceSecretId))
		return
	}
	fmt.Printf("Blast radius of %q (id %d): %d dependent(s), max depth %d\n",
		derefStr(r.SourceSecretName), derefInt(r.SourceSecretId), derefInt(r.TotalImpact), derefInt(r.MaxDepth))
	fmt.Println(strings.Repeat("-", 60))
	if r.Dependents != nil {
		for _, dep := range *r.Dependents {
			depth := derefInt(dep.Depth)
			indent := strings.Repeat("  ", depth-1)
			risk := ""
			if dep.RiskLevel != nil {
				risk = string(*dep.RiskLevel)
			}
			fmt.Printf("%s[depth %d | %s] secret %-5d %-30s (owner %d, project %d)\n",
				indent, depth, risk,
				derefInt(dep.SecretId), derefStr(dep.SecretName),
				derefInt(dep.OwnerId), derefInt(dep.ProjectId))
		}
	}
}

func init() {
	SecretCmd.AddCommand(secretBlastRadiusCmd)
}

// ── cert ─────────────────────────────────────────────────────────────────────

var secretCertCmd = &cobra.Command{
	Use:          "cert <secret-id>",
	Aliases:      []string{"certificate"},
	Short:        "Show a certificate secret's public X.509 metadata (expiry, issuer, SANs)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runSecretCert,
}

func runSecretCert(_ *cobra.Command, args []string) error {
	id, err := parseSecretArg(args[0])
	if err != nil {
		return err
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetSecretCertificateWithResponse(context.Background(), id)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get certificate", resp.StatusCode(), resp.Body)
	}
	v := resp.JSON200.Data
	notAfter := ""
	if v.NotAfter != nil {
		notAfter = v.NotAfter.Format("2006-01-02T15:04:05Z07:00")
	}
	expiry := notAfter
	if derefBool(v.IsExpired) {
		expiry += "  (EXPIRED)"
	} else {
		expiry += fmt.Sprintf("  (%d days left)", derefInt(v.DaysUntilExpiry))
	}
	fmt.Printf("Certificate: %s (secret %d)\n", derefStr(v.SecretName), derefInt(v.SecretId))
	fmt.Printf("  Subject:    %s\n", derefStr(v.Subject))
	fmt.Printf("  Issuer:     %s%s\n", derefStr(v.Issuer), selfSignedNote(derefBool(v.SelfSigned)))
	fmt.Printf("  Serial:     %s\n", derefStr(v.SerialNumber))
	notBefore := ""
	if v.NotBefore != nil {
		notBefore = v.NotBefore.Format("2006-01-02T15:04:05Z07:00")
	}
	fmt.Printf("  Valid from: %s\n", notBefore)
	fmt.Printf("  Expires:    %s\n", expiry)
	if v.DnsNames != nil && len(*v.DnsNames) > 0 {
		fmt.Printf("  SANs:       %v\n", *v.DnsNames)
	}
	fmt.Printf("  CA:         %t\n", derefBool(v.IsCa))
	fmt.Printf("  Algorithms: %s / %s\n", derefStr(v.SignatureAlgorithm), derefStr(v.PublicKeyAlgorithm))
	return nil
}

func selfSignedNote(selfSigned bool) string {
	if selfSigned {
		return "  (self-signed)"
	}
	return ""
}

func init() {
	SecretCmd.AddCommand(secretCertCmd)
}

// ── audit ────────────────────────────────────────────────────────────────────

var (
	auditID    int
	auditLimit int
)

var secretAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show a secret's lifecycle events (created/rotated/suspended/shared/…)",
	Long: `List the audit trail for a secret: what happened to it and when (created, rotated,
rolled-back, suspended/resumed, shared, owner-transferred, reclassified), newest first.
Requires secrets.read at the secret's scope. Never prints a plaintext value.`,
	SilenceUsage: true,
	RunE:         runSecretAudit,
}

func runSecretAudit(_ *cobra.Command, _ []string) error {
	if auditID == 0 {
		return usageErrorf("--id is required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	var params *apiclient.GetSecretAuditTrailParams
	if auditLimit > 0 {
		params = &apiclient.GetSecretAuditTrailParams{Limit: &auditLimit}
	}
	resp, err := client.GetSecretAuditTrailWithResponse(context.Background(), auditID, params)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("get audit trail", resp.StatusCode(), resp.Body)
	}
	rows := resp.JSON200.Data.Audit
	if rows == nil || len(*rows) == 0 {
		fmt.Println("No audit events.")
		return nil
	}
	fmt.Printf("%-26s %-24s %-8s %s\n", "EVENT", "TIME", "ACTOR", "DESCRIPTION")
	for _, r := range *rows {
		fmt.Printf("%-26s %-24s %-8s %s\n", derefStr(r.EventType), derefStr(r.Timestamp), derefStr(r.ActorType), derefStr(r.Description))
	}
	return nil
}

func init() {
	secretAuditCmd.Flags().IntVar(&auditID, "id", 0, "Secret ID (required)")
	secretAuditCmd.Flags().IntVar(&auditLimit, "limit", 0, "Max events to show (default server-side: 50, cap 500)")
	SecretCmd.AddCommand(secretAuditCmd)
}
