// secret_scan_files.go — per-file-type scanning for `secret scan`: scanEnvFile,
// scanConfigFile, scanSourceFile.
package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
)

func scanEnvFile(path, relPath string) []ScanFinding {
	content, err := regularfile.ReadFile("scanned file", filepath.Clean(path)) // a non-regular file (FIFO planted in the tree) is skipped, never read
	if err != nil {
		return nil
	}
	var findings []ScanFinding
	for i, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if value == "" || value == "changeme" || value == "your_secret_here" || value == "xxx" {
			continue
		}
		findings = append(findings, ScanFinding{
			File:       relPath,
			Line:       i + 1,
			Name:       name,
			Value:      value,
			RiskLevel:  "medium",
			RiskReason: "Secret in .env file — ensure file is in .gitignore",
			Source:     "env_file",
		})
	}
	return findings
}

func scanConfigFile(path, relPath string) []ScanFinding {
	content, err := regularfile.ReadFile("scanned file", filepath.Clean(path)) // a non-regular file (FIFO planted in the tree) is skipped, never read
	if err != nil {
		return nil
	}
	var findings []ScanFinding
	seen := map[string]bool{}
	for i, line := range strings.Split(string(content), "\n") {
		for _, p := range secretPatterns {
			matches := p.pattern.FindStringSubmatch(line)
			if len(matches) < 2 {
				continue
			}
			name := sanitizeScanName(matches[1])
			value := ""
			if len(matches) >= 3 {
				value = matches[len(matches)-1]
			}
			if isScanPlaceholder(value) {
				continue
			}
			key := fmt.Sprintf("%s:%d", relPath, i+1)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, ScanFinding{
					File:       relPath,
					Line:       i + 1,
					Name:       name,
					Value:      value,
					RiskLevel:  p.risk,
					RiskReason: p.reason,
					Source:     "config_file",
				})
			}
		}
	}
	return findings
}

func scanSourceFile(path, relPath string) []ScanFinding {
	content, err := regularfile.ReadFile("scanned file", filepath.Clean(path)) // a non-regular file (FIFO planted in the tree) is skipped, never read
	if err != nil {
		return nil
	}
	var findings []ScanFinding
	seen := map[string]bool{}
	for i, line := range strings.Split(string(content), "\n") {
		for _, p := range secretPatterns {
			matches := p.pattern.FindStringSubmatch(line)
			if len(matches) < 2 {
				continue
			}
			name := sanitizeScanName(matches[1])
			value := ""
			if len(matches) >= 3 {
				value = matches[len(matches)-1]
			}
			if isScanPlaceholder(value) {
				continue
			}
			risk := "high"
			if p.risk == "low" {
				risk = "medium"
			}
			key := fmt.Sprintf("%s:%d", relPath, i+1)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, ScanFinding{
					File:       relPath,
					Line:       i + 1,
					Name:       name,
					Value:      value,
					RiskLevel:  risk,
					RiskReason: p.reason + " — HARDCODED IN SOURCE CODE",
					Source:     "hardcoded",
				})
			}
		}
	}
	return findings
}
