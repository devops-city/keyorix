// secret_scan.go — keyorix secret scan: local filesystem/git regex scan for hardcoded
// secrets. Pure local operation, no REST calls (--import only tells the operator to run
// `secret import` separately — it does not itself create anything server-side).
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var secretScanCmd = &cobra.Command{
	Use:          "scan [path]",
	Short:        "Scan a directory for secrets and hardcoded credentials",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runSecretScan,
}

var (
	scanImport   bool
	scanReport   string
	scanSeverity string
	scanStaged   bool
	scanCommit   string
)

func init() {
	secretScanCmd.Flags().BoolVar(&scanImport, "import", false, "Print a follow-up 'secret import' hint after scanning (does not import automatically)")
	secretScanCmd.Flags().StringVar(&scanReport, "report", "", "Save scan report to file (JSON format)")
	secretScanCmd.Flags().StringVar(&scanSeverity, "severity", "", "Filter by severity: low, medium, high")
	secretScanCmd.Flags().BoolVar(&scanStaged, "staged", false, "Scan only git staged files")
	secretScanCmd.Flags().StringVar(&scanCommit, "commit", "", "Scan files changed in a specific commit (e.g. HEAD~1)")
	SecretCmd.AddCommand(secretScanCmd)
}

// ScanFinding represents a single discovered secret.
type ScanFinding struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	RiskLevel  string `json:"risk_level"`
	RiskReason string `json:"risk_reason"`
	Source     string `json:"source"`
}

// ScanReport is the full scan output.
type ScanReport struct {
	ScannedPath string        `json:"scanned_path"`
	TotalFound  int           `json:"total_found"`
	HighRisk    int           `json:"high_risk"`
	MediumRisk  int           `json:"medium_risk"`
	LowRisk     int           `json:"low_risk"`
	Findings    []ScanFinding `json:"findings"`
}

// secretPatterns — common secret formats in source code and config files.
var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
	risk    string
	reason  string
}{
	{"AWS Access Key", regexp.MustCompile(`(?i)(aws_access_key_id|aws_access_key)\s*[=:]\s*["']?([A-Z0-9]{20})["']?`), "high", "AWS credential — full account access if leaked"},
	{"AWS Secret Key", regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`), "high", "AWS secret key — full account access if leaked"},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,64})["']?`), "high", "API key hardcoded in source — visible in git history"},
	{"Database Password", regexp.MustCompile(`(?i)(db[_-]?pass(word)?|database[_-]?pass(word)?|db[_-]?pwd)\s*[=:]\s*["']?([^\s"']{6,})["']?`), "high", "Database password — direct data access if leaked"},
	{"Generic Password", regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*[=:]\s*["']([^\s"']{6,})["']`), "medium", "Password or secret value hardcoded"},
	{"JWT Secret", regexp.MustCompile(`(?i)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,})["']?`), "high", "JWT signing secret — allows token forgery if leaked"},
	{"Private Key Header", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`), "high", "Private key — cryptographic identity compromise"},
	{"Stripe Key", regexp.MustCompile(`(sk_live_|sk_test_)[A-Za-z0-9]{24,}`), "high", "Stripe API key — financial transactions access"},
	{"GitHub Token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}`), "high", "GitHub personal access token"},
	{"Generic Secret", regexp.MustCompile(`(?i)(secret|token|key|auth)\s*[=:]\s*["']([A-Za-z0-9_\-+/]{16,64})["']`), "low", "Possible secret value — review manually"},
}

var scanSourceExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".java": true,
	".rb": true, ".php": true, ".cs": true, ".cpp": true, ".c": true,
	".sh": true, ".bash": true, ".zsh": true,
}

var scanConfigExtensions = map[string]bool{
	".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".xml": true, ".conf": true, ".config": true, ".ini": true,
	".properties": true, ".env": true,
}

var scanSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".idea": true,
	"dist": true, "build": true, ".next": true, "__pycache__": true,
	"target": true, "bin": true, ".terraform": true,
	"examples": true, "demo": true,
}

func runSecretScan(_ *cobra.Command, args []string) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if scanSeverity != "" && scanSeverity != "low" && scanSeverity != "medium" && scanSeverity != "high" {
		return fmt.Errorf("invalid --severity value %q (expected one of: low, medium, high)", scanSeverity)
	}

	stagedFiles := resolveScanFileSet(absPath)

	fmt.Printf("Scanning %s for secrets...\n\n", absPath)
	report := &ScanReport{ScannedPath: absPath}

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Never follow symlinks — a malicious repo could commit a symlink pointing
		// outside the scanned tree; reading through it would leak the scanning user's
		// own files into the report. Use os.Lstat explicitly, not the Walk-supplied info.
		lstatInfo, lerr := os.Lstat(path)
		if lerr != nil {
			return nil
		}
		if lstatInfo.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.IsDir() {
			if scanSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if stagedFiles != nil && !stagedFiles[path] {
			return nil
		}
		if info.Size() > 1*1024*1024 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		relPath, _ := filepath.Rel(absPath, path)

		if strings.HasSuffix(info.Name(), "_test.go") || strings.HasSuffix(info.Name(), ".test.js") || strings.HasSuffix(info.Name(), ".spec.ts") {
			return nil
		}

		baseName := strings.ToLower(filepath.Base(path))
		if baseName == ".env" || strings.HasPrefix(baseName, ".env.") {
			report.Findings = append(report.Findings, scanEnvFile(path, relPath)...)
			return nil
		}
		if scanConfigExtensions[ext] {
			report.Findings = append(report.Findings, scanConfigFile(path, relPath)...)
		} else if scanSourceExtensions[ext] {
			report.Findings = append(report.Findings, scanSourceFile(path, relPath)...)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	tallyScanReport(report)
	if scanSeverity != "" {
		filterScanReportBySeverity(report, scanSeverity)
	}

	printScanReport(report)

	if report.TotalFound > 0 {
		fmt.Println("\nNext:")
		fmt.Println("  keyorix secret explain <key-name>   Explain risk and how to fix")
		fmt.Println("  keyorix secret fix <key-name>        Fix the issue automatically")
	}

	if scanReport != "" {
		if err := writeScanReport(report); err != nil {
			return err
		}
	}

	if scanImport && len(report.Findings) > 0 {
		fmt.Printf("\nRun 'keyorix secret import' to store these values in Keyorix (%d unique name(s) found).\n", countUniqueScanNames(report.Findings))
	}

	return nil
}

// resolveScanFileSet returns the file allowlist for --staged/--commit, or nil to scan
// everything under absPath. exec.Command args are never shell-interpreted (no shell
// involved), but --commit is still rejected if it looks like a git flag (leading '-')
// to avoid arg injection — see the flag's own doc comment on secretScanCmd.
func resolveScanFileSet(absPath string) map[string]bool {
	if scanStaged {
		out, err := exec.Command("git", "-C", absPath, "diff", "--cached", "--name-only").Output() // #nosec G204
		if err == nil && len(out) > 0 {
			return scanFileListToSet(absPath, string(out))
		}
	}
	if scanCommit != "" {
		if strings.HasPrefix(scanCommit, "-") {
			fmt.Fprintf(os.Stderr, "invalid --commit value %q: must not start with '-' — ignoring\n", scanCommit)
			return nil
		}
		out, err := exec.Command("git", "-C", absPath, "diff-tree", "--no-commit-id", "-r", "--name-only", scanCommit).Output() // #nosec G204
		if err == nil && len(out) > 0 {
			return scanFileListToSet(absPath, string(out))
		}
	}
	return nil
}

func scanFileListToSet(absPath, out string) map[string]bool {
	set := map[string]bool{}
	for f := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if f != "" {
			set[filepath.Join(absPath, f)] = true
		}
	}
	fmt.Printf("Scanning %d file(s)...\n\n", len(set))
	return set
}

func tallyScanReport(report *ScanReport) {
	for _, f := range report.Findings {
		switch f.RiskLevel {
		case "high":
			report.HighRisk++
		case "medium":
			report.MediumRisk++
		case "low":
			report.LowRisk++
		}
	}
	report.TotalFound = len(report.Findings)
}

func filterScanReportBySeverity(report *ScanReport, severity string) {
	filtered := []ScanFinding{}
	for _, f := range report.Findings {
		if f.RiskLevel == severity {
			filtered = append(filtered, f)
		}
	}
	report.Findings = filtered
	report.TotalFound = len(filtered)
	report.HighRisk, report.MediumRisk, report.LowRisk = 0, 0, 0
	for _, f := range filtered {
		switch f.RiskLevel {
		case "high":
			report.HighRisk++
		case "medium":
			report.MediumRisk++
		case "low":
			report.LowRisk++
		}
	}
}

func writeScanReport(report *ScanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	// #nosec G304 -- operator-provided --report path; secureCreateOutputFile refuses to
	// write through a symlink at any path component and refuses a pre-existing path.
	rf, err := secureCreateOutputFile(scanReport)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}
	_, werr := rf.Write(data)
	cerr := rf.Close()
	if werr != nil {
		return fmt.Errorf("failed to save report: %w", werr)
	}
	if cerr != nil {
		return fmt.Errorf("failed to save report: %w", cerr)
	}
	fmt.Printf("\nReport saved to %s\n", scanReport)
	return nil
}

func countUniqueScanNames(findings []ScanFinding) int {
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Name != "" && f.Value != "" {
			seen[f.Name] = true
		}
	}
	return len(seen)
}
