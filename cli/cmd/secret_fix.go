// secret_fix.go — keyorix secret fix: move a hardcoded secret into an environment
// variable. Pure local source-tree rewriter, no REST calls.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/keyorixhq/keyorix/cli/internal/securefiles"
	"github.com/spf13/cobra"
)

var secretFixCmd = &cobra.Command{
	Use:          "fix <key-name>",
	Short:        "Fix a hardcoded secret by moving it to an environment variable",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runSecretFix,
}

var (
	fixDryRun      bool
	fixInteractive bool
	fixEnvFile     string
	fixPath        string
)

func init() {
	secretFixCmd.Flags().BoolVar(&fixDryRun, "dry-run", true, "Preview changes without applying (default: true)")
	secretFixCmd.Flags().BoolVar(&fixInteractive, "interactive", false, "Step through each fix interactively")
	secretFixCmd.Flags().StringVar(&fixEnvFile, "env-file", ".env", "Target .env file for extracted secrets")
	secretFixCmd.Flags().StringVar(&fixPath, "path", ".", "Path to scan for the secret")
	SecretCmd.AddCommand(secretFixCmd)
}

type fixPlan struct {
	File         string
	Line         int
	OriginalLine string
	NewLine      string
	EnvVarName   string
	SecretValue  string
}

func runSecretFix(_ *cobra.Command, args []string) error {
	keyName := args[0]
	envVarName := strings.ToUpper(strings.ReplaceAll(keyName, "-", "_"))

	absPath, err := filepath.Abs(fixPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	fmt.Printf("Analysing %s...\n\n", keyName)

	plans, err := findAndPlanFix(absPath, envVarName)
	if err != nil {
		return err
	}

	if len(plans) == 0 {
		fmt.Printf("No hardcoded occurrences of %s found in %s\n", keyName, absPath)
		fmt.Printf("\nIf the secret is in a .env file, it is already in the right place.\n")
		fmt.Printf("Store it in Keyorix:\n")
		fmt.Printf("  keyorix secret create --name %s --interactive\n", strings.ToLower(keyName))
		return nil
	}

	fmt.Printf("Fix plan for %s:\n\n", keyName)
	for _, plan := range plans {
		fmt.Printf("  File: %s (line %d)\n", plan.File, plan.Line)
		fmt.Printf("  Before: %s\n", strings.TrimSpace(plan.OriginalLine))
		fmt.Printf("  After:  %s\n", strings.TrimSpace(plan.NewLine))
		fmt.Println()
	}

	fmt.Printf("  Add to %s:\n", fixEnvFile)
	fmt.Printf("  %s=<your-value-here>\n\n", envVarName)

	if fixDryRun && !fixInteractive {
		fmt.Println("Dry run — no changes made.")
		fmt.Printf("\nTo apply: keyorix secret fix %s --dry-run=false\n", keyName)
		fmt.Printf("To review interactively: keyorix secret fix %s --interactive\n", keyName)
		return nil
	}

	if fixInteractive {
		fmt.Print("Apply these changes? (y/n): ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	for _, plan := range plans {
		if err := applyFix(absPath, plan); err != nil {
			fmt.Printf("Error fixing %s: %v\n", plan.File, err)
			continue
		}
		fmt.Printf("Fixed %s:%d\n", plan.File, plan.Line)
	}

	// Append to .env file via securefiles.SecureOpenBeneath: an append-only open doesn't
	// fit SecureCreateFileHandle's O_EXCL semantics (the whole point here is to append
	// across repeated runs, not refuse a pre-existing file), but the per-path-component
	// O_NOFOLLOW walk still applies.
	f, err := securefiles.SecureOpenBeneath(absPath, fixEnvFile, unix.O_APPEND|unix.O_CREAT|unix.O_WRONLY, 0600) // #nosec G304 -- absPath is operator-supplied --path, walked via SecureOpenBeneath
	if err == nil {
		_, _ = fmt.Fprintf(f, "\n# Added by keyorix fix\n%s=\n", envVarName) // #nosec G104
		_ = f.Close()                                                        // #nosec G104
		fmt.Printf("Added %s= to %s (fill in the value)\n", envVarName, fixEnvFile)
	}

	fmt.Printf("\nDone. Next steps:\n")
	fmt.Printf("  1. Fill in the value in %s\n", fixEnvFile)
	fmt.Printf("  2. Add %s to .gitignore\n", fixEnvFile)
	fmt.Printf("  3. Store in Keyorix: keyorix secret create --name %s --interactive\n", strings.ToLower(keyName))
	fmt.Printf("  4. Run with injection: keyorix run --env production --var %s=%s -- your-app\n", envVarName, strings.ToLower(keyName))

	return nil
}

func findAndPlanFix(basePath, envVarName string) ([]fixPlan, error) {
	var plans []fixPlan
	pattern := regexp.MustCompile(`(?i)(` + regexp.QuoteMeta(strings.ToLower(envVarName)) + `|` + regexp.QuoteMeta(envVarName) + `)\s*[=:]\s*["']([^"']+)["']`)

	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && scanSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}
		if info.Size() > 1*1024*1024 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !scanSourceExtensions[ext] && !scanConfigExtensions[ext] {
			return nil
		}

		content, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 G122 -- path comes from filepath.Walk rooted at operator-supplied absPath; symlink TOCTOU acceptable for a local developer tool
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(basePath, path)
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) >= 3 {
				value := matches[2]
				if isScanPlaceholder(value) {
					continue
				}
				newLine := pattern.ReplaceAllString(line, matches[1]+`=os.getenv("`+envVarName+`")`)
				plans = append(plans, fixPlan{
					File:         relPath,
					Line:         i + 1,
					OriginalLine: line,
					NewLine:      newLine,
					EnvVarName:   envVarName,
					SecretValue:  value,
				})
			}
		}
		return nil
	})
	return plans, err
}

func applyFix(basePath string, plan fixPlan) error {
	// plan.File was recorded by findAndPlanFix relative to basePath (the same --path
	// the plan was built from), so it must be resolved against that same basePath here.
	fullPath := filepath.Join(basePath, plan.File)
	content, err := os.ReadFile(filepath.Clean(fullPath)) // #nosec G304 -- fullPath is basePath (operator-supplied --path) joined with a relative path from filepath.Walk rooted at that same basePath
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	if plan.Line-1 >= len(lines) {
		return fmt.Errorf("line %d out of range", plan.Line)
	}
	lines[plan.Line-1] = plan.NewLine
	// SecureOpenBeneath's per-component O_NOFOLLOW walk refuses to traverse OR write
	// through a symlink at any path component — a scanned directory can contain
	// attacker-planted content, so a symlink swapped in at a discovered path (between
	// the scan and this apply) would otherwise let this overwrite an arbitrary file.
	f, err := securefiles.SecureOpenBeneath(basePath, plan.File, unix.O_WRONLY|unix.O_TRUNC, 0600) // #nosec G304 -- basePath is operator-supplied --path, plan.File is relative to it, walked via SecureOpenBeneath
	if err != nil {
		return err
	}
	_, werr := f.Write([]byte(strings.Join(lines, "\n")))
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
