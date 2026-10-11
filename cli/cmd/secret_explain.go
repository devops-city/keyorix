// secret_explain.go — keyorix secret explain: static lookup table explaining a
// discovered secret's risk and how to fix it. No REST calls.
package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	helpInjectAtRuntime = "Inject at runtime: keyorix run --env production --var NAME=secret-ref -- your-app"
	helpStoreAndInject  = "Store in Keyorix and inject at runtime"
)

var secretExplainCmd = &cobra.Command{
	Use:          "explain <key-name>",
	Short:        "Explain the risk of a discovered secret and how to fix it",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runSecretExplain,
}

func init() {
	SecretCmd.AddCommand(secretExplainCmd)
}

type secretExplanation struct {
	KeyPattern  string
	RiskLevel   string
	RiskSummary string
	Impact      string
	Fix         []string
	Example     string
}

var secretExplanations = []secretExplanation{
	{
		KeyPattern:  "aws_access_key",
		RiskLevel:   "HIGH",
		RiskSummary: "AWS Access Key hardcoded in source code or config",
		Impact:      "Full AWS account access. An attacker can create resources, exfiltrate data, or run up costs. Visible in git history even after deletion.",
		Fix: []string{
			"Remove from source code immediately",
			"Rotate the key in AWS IAM console",
			"Store in Keyorix: keyorix secret create --name aws-access-key --interactive",
			helpInjectAtRuntime,
			"Add to .gitignore if in a config file",
		},
		Example: "AWS_ACCESS_KEY_ID=os.getenv(\"AWS_ACCESS_KEY_ID\")",
	},
	{
		KeyPattern:  "aws_secret",
		RiskLevel:   "HIGH",
		RiskSummary: "AWS Secret Key hardcoded in source code or config",
		Impact:      "Full AWS account access combined with Access Key. Immediate rotation required.",
		Fix: []string{
			"Rotate the key pair in AWS IAM console immediately",
			helpStoreAndInject,
			"Never commit AWS credentials to any repository",
		},
		Example: "AWS_SECRET_ACCESS_KEY=os.getenv(\"AWS_SECRET_ACCESS_KEY\")",
	},
	{
		KeyPattern:  "db_password",
		RiskLevel:   "HIGH",
		RiskSummary: "Database password hardcoded in source code or config file",
		Impact:      "Direct database access. An attacker can read, modify, or delete all data. Often reused across environments.",
		Fix: []string{
			"Move to environment variable: DB_PASSWORD=os.getenv(\"DB_PASSWORD\")",
			"Store in Keyorix: keyorix secret create --name db-password --interactive",
			helpInjectAtRuntime,
			"Rotate the database password after removing from code",
			"Check if same password is used in other environments",
		},
		Example: "DB_PASSWORD = os.environ.get(\"DB_PASSWORD\")",
	},
	{
		KeyPattern:  "api_key",
		RiskLevel:   "HIGH",
		RiskSummary: "API key hardcoded in source code",
		Impact:      "Unauthorized API access. Visible in git history. May allow data access, quota abuse, or service disruption.",
		Fix: []string{
			"Move to environment variable",
			helpStoreAndInject,
			"Rotate the API key in the service dashboard",
			"Check git history: git log --all -S '<key-value>'",
		},
		Example: "API_KEY = os.environ.get(\"API_KEY\")",
	},
	{
		KeyPattern:  "jwt_secret",
		RiskLevel:   "HIGH",
		RiskSummary: "JWT signing secret hardcoded",
		Impact:      "An attacker can forge valid JWT tokens, impersonating any user including admins. All existing tokens must be invalidated on rotation.",
		Fix: []string{
			"Generate a new strong secret (min 256 bits): openssl rand -hex 32",
			"Store in Keyorix: keyorix secret create --name jwt-secret --interactive",
			"Inject at runtime and invalidate all existing sessions",
			"Never use the same JWT secret across environments",
		},
		Example: "JWT_SECRET = os.environ.get(\"JWT_SECRET\")",
	},
	{
		KeyPattern:  "private_key",
		RiskLevel:   "HIGH",
		RiskSummary: "Private key committed to repository",
		Impact:      "Complete cryptographic identity compromise. Anyone with this key can impersonate your server, decrypt communications, or sign malicious code.",
		Fix: []string{
			"Revoke this key pair immediately",
			"Generate a new key pair",
			"Store private key securely — never in a repository",
			"Use git-filter-repo to remove from git history",
			"Audit all systems that trusted this key",
		},
		Example: "Load from file path stored in environment variable",
	},
	{
		KeyPattern:  "stripe",
		RiskLevel:   "HIGH",
		RiskSummary: "Stripe API key hardcoded",
		Impact:      "Full access to Stripe account. An attacker can process charges, issue refunds, access customer data, or drain your account.",
		Fix: []string{
			"Rotate the key in Stripe dashboard immediately",
			"Use test keys (sk_test_) in development, never production keys",
			"Store production key in Keyorix",
			helpInjectAtRuntime,
		},
		Example: "STRIPE_SECRET_KEY = os.environ.get(\"STRIPE_SECRET_KEY\")",
	},
	{
		KeyPattern:  "password",
		RiskLevel:   "MEDIUM",
		RiskSummary: "Password value found in source code or config",
		Impact:      "Credential exposure. Risk depends on what system this password protects.",
		Fix: []string{
			"Move to environment variable",
			helpStoreAndInject,
			"Rotate the password on the target system",
		},
		Example: "PASSWORD = os.environ.get(\"PASSWORD\")",
	},
}

func runSecretExplain(_ *cobra.Command, args []string) error {
	keyName := strings.ToLower(args[0])

	var match *secretExplanation
	for i := range secretExplanations {
		if strings.Contains(keyName, secretExplanations[i].KeyPattern) {
			match = &secretExplanations[i]
			break
		}
	}

	if match == nil {
		fmt.Printf("Key: %s\n\n", args[0])
		fmt.Printf("Risk: UNKNOWN — no specific pattern matched\n\n")
		fmt.Printf("General guidance:\n")
		fmt.Printf("  - Never hardcode credentials in source code\n")
		fmt.Printf("  - Move to environment variable\n")
		fmt.Printf("  - Store in Keyorix: keyorix secret create --name %s --interactive\n", strings.ToLower(args[0]))
		fmt.Printf("  - Inject at runtime: keyorix run --env production --var %s=%s -- your-app\n\n", strings.ToUpper(args[0]), strings.ToLower(args[0]))
		fmt.Printf("Next:\n")
		fmt.Printf("  keyorix secret fix %s\n", args[0])
		return nil
	}

	fmt.Printf("Key:    %s\n", args[0])
	fmt.Printf("Risk:   %s\n", match.RiskLevel)
	fmt.Printf("\n%s\n", match.RiskSummary)
	fmt.Printf("\nImpact:\n  %s\n", match.Impact)
	fmt.Printf("\nHow to fix:\n")
	for i, fix := range match.Fix {
		fmt.Printf("  %d. %s\n", i+1, fix)
	}
	fmt.Printf("\nExample (safe pattern):\n  %s\n", match.Example)
	fmt.Printf("\nNext:\n  keyorix secret fix %s\n", args[0])

	return nil
}
