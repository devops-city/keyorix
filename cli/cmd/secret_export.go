// secret_export.go — keyorix secret export.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

const fmtEncryptedJSON = "encrypted-json"

var (
	exportFormat     string
	exportOutput     string
	exportProject    int
	exportEnv        int
	exportEncryptFor string
)

var secretExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets to a file or stdout",
	Long: `Export secrets from Keyorix to dotenv, JSON, Vault YAML, or encrypted-json format.

Examples:
  keyorix secret export --project 7 --env 3 --format dotenv
  keyorix secret export --project 7 --env 3 --format json --output secrets.json
  keyorix secret export --project 7 --env 3 --format vault --output vault-export.yaml
  keyorix secret export --project 7 --env 3 --encrypt-for recipient.pub.pem --output secrets.enc.json

Supported formats:
  dotenv         .env files (KEY=VALUE)
  json           Flat key-value JSON object
  vault          Medusa/Vault YAML (importable back via 'keyorix secret import --format vault')
  encrypted-json RSA-OAEP-SHA256 + AES-256-GCM encrypted envelope (safe for airgap transfer)

Output goes to stdout unless --output is specified.
Warnings and summary are always printed to stderr.`,
	SilenceUsage: true,
	RunE:         runSecretExport,
}

// exportedSecret holds a secret's name and decrypted value.
type exportedSecret struct {
	ID    int
	Name  string
	Value string
}

func runSecretExport(_ *cobra.Command, _ []string) (retErr error) {
	if exportProject == 0 || exportEnv == 0 {
		return fmt.Errorf("--project and --env are both required")
	}
	client, err := secretAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	list, err := listSecretsForExport(ctx, client, exportProject, exportEnv)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found.")
		return nil
	}

	fetched, err := fetchSecretValuesForExport(ctx, client, list)
	if err != nil {
		return err
	}

	format := applyEncryptForDefault(exportFormat, exportEncryptFor)

	var out io.Writer = os.Stdout
	if exportOutput != "" {
		f, err := secureCreateOutputFile(exportOutput)
		if err != nil {
			return fmt.Errorf("cannot create output file %q (it may already exist — remove it or choose a different path): %w", exportOutput, err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil && retErr == nil {
				retErr = fmt.Errorf("failed to close output file: %w", cerr)
			}
		}()
		out = f
	}

	if strings.ToLower(format) != fmtEncryptedJSON {
		fmt.Fprintln(os.Stderr, "WARNING: exported secrets are in plaintext. Handle with care.")
	}

	if err := writeExportedSecrets(out, format, fetched, exportEncryptFor); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Exported %d secrets\n", len(fetched))
	return nil
}

// applyEncryptForDefault switches format to encrypted-json when --encrypt-for is set
// but the operator did not explicitly choose that format.
func applyEncryptForDefault(format, encryptFor string) string {
	if encryptFor != "" && strings.ToLower(format) != fmtEncryptedJSON {
		fmt.Fprintf(os.Stderr, "NOTE: --encrypt-for is set; switching format to encrypted-json.\n")
		return fmtEncryptedJSON
	}
	return format
}

func writeExportedSecrets(out io.Writer, format string, fetched []exportedSecret, encryptFor string) error {
	switch strings.ToLower(format) {
	case "dotenv", "env":
		return writeDotenv(out, fetched)
	case "json":
		return writeExportJSON(out, fetched)
	case "vault":
		return writeVault(out, fetched, exportEnv)
	case fmtEncryptedJSON:
		if encryptFor == "" {
			return fmt.Errorf("--encrypt-for <pubkey.pem> is required for the encrypted-json format")
		}
		return writeEncryptedJSON(out, fetched, encryptFor)
	default:
		return fmt.Errorf("unknown format %q (supported: dotenv, json, vault, encrypted-json)", format)
	}
}

// ── Fetch helpers ────────────────────────────────────────────────────────────

// listSecretsForExport GETs /secrets scoped to (projectID, envID), decoded off the raw
// (non-typed) generated method since listSecrets has no response schema yet (PR 4's job).
func listSecretsForExport(ctx context.Context, client *apiclient.ClientWithResponses, projectID, envID int) ([]struct {
	ID   int
	Name string
}, error) {
	params := &apiclient.ListSecretsParams{
		ProjectId:     &projectID,
		EnvironmentId: &envID,
		PageSize:      intPtr(1000),
	}
	resp, err := client.ListSecretsWithResponse(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	if resp.StatusCode() != 200 {
		return nil, httpStatusError("list secrets", resp.StatusCode(), resp.Body)
	}
	var body struct {
		Data struct {
			Secrets []struct {
				ID   int    `json:"ID"`
				Name string `json:"Name"`
			} `json:"secrets"`
		} `json:"data"`
	}
	if err := decodeJSONBody(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("decode secret list: %w", err)
	}
	out := make([]struct {
		ID   int
		Name string
	}, len(body.Data.Secrets))
	for i, s := range body.Data.Secrets {
		out[i] = struct {
			ID   int
			Name string
		}{ID: s.ID, Name: s.Name}
	}
	return out, nil
}

// fetchSecretValuesForExport GETs each secret's value via ?include_value=true (getSecret
// has no response schema yet either — PR 4's job), skipping (with a stderr warning) any
// secret whose read fails rather than aborting the whole export.
func fetchSecretValuesForExport(ctx context.Context, client *apiclient.ClientWithResponses, list []struct {
	ID   int
	Name string
}) ([]exportedSecret, error) {
	result := make([]exportedSecret, 0, len(list))
	trueVal := true
	for _, s := range list {
		resp, err := client.GetSecretWithResponse(ctx, s.ID, &apiclient.GetSecretParams{IncludeValue: &trueVal})
		if err == nil && resp.StatusCode() != 200 {
			// The server's reason, e.g. a secret that is expired or suspended (ERRMAP-1).
			err = httpStatusError("read refused", resp.StatusCode(), resp.Body)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: skipping %q (id=%d): %v\n", s.Name, s.ID, err)
			continue
		}
		var body struct {
			Data struct {
				Value string `json:"value"`
			} `json:"data"`
		}
		if err := decodeJSONBody(resp.Body, &body); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: skipping %q (id=%d): %v\n", s.Name, s.ID, err)
			continue
		}
		result = append(result, exportedSecret{ID: s.ID, Name: s.Name, Value: body.Data.Value})
	}
	return result, nil
}

// ── Format writers ───────────────────────────────────────────────────────────

// dotenvPlainSafe matches values that need no quoting at all in the emitted dotenv
// file: alnum plus a small allowlist of punctuation common in real secret values
// (paths, URLs, timestamps) that carries no shell meaning.
var dotenvPlainSafe = regexp.MustCompile(`^[A-Za-z0-9_.,:/@+-]*$`)

// writeDotenv emits KEY=VALUE lines. Any value outside dotenvPlainSafe is wrapped in
// SINGLE quotes — the only POSIX-shell quoting form that suppresses ALL expansion
// (command substitution, parameter/arithmetic expansion, globbing, tilde expansion) —
// with only the literal single-quote character escaped via the standard
// close-escape-reopen idiom (parseDotenv's own quote-stripping reverses this exact
// escape, see its doc comment). Several shapes have no lossless representation in the
// dotenv format's line-oriented, first-'='-splits, whole-line-TrimSpace'd KEY=VALUE
// grammar, and are refused outright rather than emitted in a form that would re-parse
// to something else (FuzzDotenvRoundTrip, CLI-FUZZ target 3b):
//   - A KEY containing an embedded newline (also lets a secret named e.g.
//     "FOO\nINJECTED=evil" inject an extra, attacker-controlled KEY=VALUE line into an
//     artifact downstream tooling treats as fully trusted).
//   - A KEY containing '=': parseDotenv splits each line on the FIRST '=', so a name
//     like "A=B" would come back on reimport as key "A", value "B=<original value>".
//   - A KEY beginning with '#' once written: parseDotenv treats any line starting with
//     '#' as a comment and silently skips it, so the entry would vanish on reimport.
//   - A KEY with leading or trailing whitespace: parseDotenv TrimSpaces the whole line
//     before splitting on '=', so e.g. a name of " " (with value "0") reparses the
//     line " =0" as "=0" -- an empty key, silently dropped rather than round-tripped.
//   - A VALUE containing an embedded newline: parseDotenv reads the file line by line,
//     so an embedded '\n' splits one logical KEY=VALUE entry across two scanned lines
//     no matter how the value portion is quoted.
func writeDotenv(w io.Writer, secrets []exportedSecret) error {
	for _, s := range secrets {
		if strings.ContainsAny(s.Name, "\r\n") {
			return fmt.Errorf("secret %q (id=%d) has a name containing a newline, which cannot be safely represented as a dotenv key — rename the secret before exporting to dotenv format", s.Name, s.ID)
		}
		if strings.Contains(s.Name, "=") {
			return fmt.Errorf("secret %q (id=%d) has a name containing '=', which cannot be safely represented as a dotenv key (it would split into a different key/value pair on reimport) — rename the secret before exporting to dotenv format", s.Name, s.ID)
		}
		if s.Name != strings.TrimSpace(s.Name) {
			return fmt.Errorf("secret %q (id=%d) has a name with leading or trailing whitespace, which is stripped by dotenv parsers on reimport — rename the secret before exporting to dotenv format", s.Name, s.ID)
		}
		if strings.HasPrefix(s.Name, "#") {
			return fmt.Errorf("secret %q (id=%d) has a name starting with '#', which would be silently skipped as a comment on reimport — rename the secret before exporting to dotenv format", s.Name, s.ID)
		}
		if strings.Contains(s.Value, "\n") {
			return fmt.Errorf("secret %q (id=%d) has a value containing a newline, which cannot be safely represented as a single dotenv line — export to json or vault format instead", s.Name, s.ID)
		}
	}
	fmt.Fprintf(w, "# Exported by Keyorix — %s\n", time.Now().Format("2006-01-02")) //nolint:errcheck
	for _, s := range secrets {
		val := s.Value
		if !dotenvPlainSafe.MatchString(val) {
			val = "'" + strings.ReplaceAll(val, `'`, `'\''`) + "'"
		}
		fmt.Fprintf(w, "%s=%s\n", s.Name, val) //nolint:errcheck
	}
	return nil
}

// writeExportJSON emits a flat {"name": "value"} object. json.Marshal requires valid
// UTF-8 in a Go string it encodes and, for an invalid byte sequence, silently
// substitutes the Unicode replacement character (U+FFFD) rather than erroring --
// parseJSONBytes then reads that substitution back as a DIFFERENT value than what was
// exported (found by FuzzJSONRoundTrip: name "\xa5" round-tripped as name "�").
// Refuse up front instead of exporting a value JSON cannot represent losslessly.
func writeExportJSON(w io.Writer, secrets []exportedSecret) error {
	for _, s := range secrets {
		if !utf8.ValidString(s.Name) || !utf8.ValidString(s.Value) {
			return fmt.Errorf("secret %q (id=%d) has a name or value that is not valid UTF-8, which JSON cannot represent losslessly — export to dotenv format instead", s.Name, s.ID)
		}
	}
	m := make(map[string]string, len(secrets))
	for _, s := range secrets {
		m[s.Name] = s.Value
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// writeEncryptedJSON produces the RSA-OAEP + AES-256-GCM envelope JSON on w.
func writeEncryptedJSON(w io.Writer, secrets []exportedSecret, pubKeyPath string) error {
	var buf strings.Builder
	if err := writeExportJSON(&buf, secrets); err != nil {
		return err
	}
	envelope, err := encryptExport([]byte(buf.String()), pubKeyPath)
	if err != nil {
		return err
	}
	_, err = w.Write(envelope)
	return err
}

// writeVault emits a Format-1 Medusa/Vault YAML export (see parseVault's doc comment).
// A name containing '/' has no lossless representation: parseVault recovers a secret's
// name from only the LAST '/'-delimited segment of its YAML path key, so a name like
// "has/a/slash" would come back on reimport as just "slash" (FuzzVaultRoundTrip,
// CLI-FUZZ target 3b) -- refused outright rather than silently truncated.
//
// The value node is force-quoted (DoubleQuotedStyle) rather than left as a bare plain
// scalar: parseVault reads it back through yaml.Unmarshal into map[string]interface{},
// and YAML's default schema retypes an unquoted value that merely LOOKS like a number,
// bool, or null (e.g. a secret value of "00", "1e3", "true", "~") into that Go type --
// fmt.Sprintf("%v", ...) on the retyped value then silently changes the string (found by
// FuzzVaultRoundTrip: value "00" round-tripped as "0", octal-resolved to the int 0).
// Force-quoting removes the ambiguity at the source instead of trying to out-guess
// every string that YAML's scalar resolver would otherwise reinterpret.
func writeVault(w io.Writer, secrets []exportedSecret, envID int) error {
	for _, s := range secrets {
		if strings.Contains(s.Name, "/") {
			return fmt.Errorf("secret %q (id=%d) has a name containing '/', which cannot be safely represented in vault YAML export (only the last path segment survives reimport) — rename the secret before exporting to vault format", s.Name, s.ID)
		}
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, s := range secrets {
		pathKey := fmt.Sprintf("secret/env-%d/%s", envID, s.Name)
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: pathKey},
			&yaml.Node{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "value"},
					{Kind: yaml.ScalarNode, Value: s.Value, Tag: "!!str", Style: yaml.DoubleQuotedStyle},
				},
			},
		)
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close() //nolint:errcheck
	return enc.Encode(doc)
}

func init() {
	secretExportCmd.Flags().StringVar(&exportFormat, "format", "dotenv", "Output format: dotenv, json, vault, encrypted-json")
	secretExportCmd.Flags().StringVar(&exportOutput, "output", "", "Output file path (default: stdout)")
	secretExportCmd.Flags().IntVar(&exportProject, "project", 0, "Project ID (required)")
	secretExportCmd.Flags().IntVar(&exportEnv, "env", 0, "Environment ID (required)")
	secretExportCmd.Flags().StringVar(&exportEncryptFor, "encrypt-for", "", "Path to RSA public key PEM (switches format to encrypted-json)")
	SecretCmd.AddCommand(secretExportCmd)
}
