// docs_no_literal_secrets_test.go -- DOCS-SECRETS-1. A secret placed on a command
// line is visible to every local user via ps//proc and is saved in shell history.
// The CLI warns about --value / --password / --admin-password / --bootstrap-token /
// --mfa-code and offers safe forms (hidden prompt, --interactive, --from-file,
// KEYORIX_* environment variables), so the documentation must never teach the
// unsafe one.
//
// What this checks: every Markdown file and Helm NOTES.txt in the repository, and
// the example/hint text in the non-test Go sources, for a secret-carrying flag
// followed by a value (`--password hunter2`, `--value "x"`, `--token=abc`,
// `--admin-password "$PW"`, `--bootstrap-token <token>`). A $VARIABLE or a
// <placeholder> still lands in argv, so those are flagged too.
//
// Scope, stated so a green run is not read as more than it is:
//   - Markdown: fenced code blocks (whole lines) and inline `code spans`. Plain
//     prose is not scanned, so "the --password flag" is fine.
//   - Go and NOTES.txt: any line that is a quoted/$/<..> value after the flag, or
//     any value on a line that mentions `keyorix`.
//   - Shell scripts (scripts/**/*.sh, deploy/**/*.sh; SCRIPTS-SECRETS-1): an argv
//     is visible in ps and CI logs whether or not a human reads the script, so any
//     secretFlags flag followed by a value on a non-comment line is a hit. There is
//     no allowlist: a script that needs a secret uses KEYORIX_* env vars (the
//     *_FILE form where a file is natural), --from-file, or a stdin pipe. This
//     also catches (SCRIPTS-SECRETS-2) a credential in curl -H/-d/--json/-u and in
//     docker -e NAME=VALUE; the exact shapes and what is NOT recognised (variable-held
//     headers/bodies, helm --set, kubectl --from-literal, interpreter argv) are listed
//     above findSecretArgvShape.
//   - Only the flags in secretFlags. A new secret-carrying flag must be added.
//
// An intentional "don't do this" example opts out per line with the marker
// `docs-secrets:allow` (in Markdown: `<!-- docs-secrets:allow -->` on the line, or
// `# docs-secrets:allow` inside a code block). The marker is deliberately explicit
// so every exemption is greppable.
package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const docsSecretsAllowMarker = "docs-secrets:allow"

// secretFlags are the flags whose value is a secret. Longest names first is not
// required: the regex anchors on the exact name followed by '=' or whitespace.
var secretFlags = []string{
	"password", "admin-password", "new-password", "current-password", "initial-password",
	"value", "token", "bootstrap-token", "vault-token", "vault-secret-id",
	"mfa-code", "code", "passphrase",
}

var secretFlagRE = regexp.MustCompile(`(?:^|[\s"'` + "`" + `(])--(` + strings.Join(secretFlags, "|") + `)(?:=|\s+)(\S+)`)

var inlineCodeRE = regexp.MustCompile("`([^`]+)`")

// literalValue reports whether v (the token after the flag) is a value rather than
// the next flag or prose punctuation. strict is used for free text (Go, NOTES.txt):
// only an obviously-a-value token counts unless the line is a keyorix command.
func literalValue(v string, eq bool, strict bool, line string) bool {
	if strings.HasPrefix(v, "-") {
		return false
	}
	if !strict || eq {
		return true
	}
	if strings.ContainsAny(v[:1], `"'$<`) {
		return true
	}
	return strings.Contains(line, "keyorix")
}

// findSecretOnCommandLine returns the offending flag for a segment of text, or "".
func findSecretOnCommandLine(segment string, strict bool) string {
	if strings.Contains(segment, docsSecretsAllowMarker) {
		return ""
	}
	for _, m := range secretFlagRE.FindAllStringSubmatchIndex(segment, -1) {
		name := segment[m[2]:m[3]]
		val := segment[m[4]:m[5]]
		whole := segment[m[0]:m[1]]
		eq := strings.Contains(whole, name+"=")
		if literalValue(val, eq, strict, segment) {
			return "--" + name + " " + val
		}
	}
	return ""
}

// docsSecretsAllowedElsewhere lists intentional "don't do this" examples in files
// that must not carry the inline marker (ADRs are owner-reviewed records; touching
// one only to silence a lint is not worth the sign-off). Keyed by repo-relative
// path, the value is a substring of the offending line, so the entry survives line
// shifts but only exempts that one example, not the whole file.
var docsSecretsAllowedElsewhere = map[string][]string{
	"docs/adr-099-master-passphrase-sourcing.md": {
		"**A `--passphrase <value>` flag.**", // the rejected design, shown on purpose
	},
}

func allowedElsewhere(rel, line string) bool {
	for _, frag := range docsSecretsAllowedElsewhere[filepath.ToSlash(rel)] {
		if strings.Contains(line, frag) {
			return true
		}
	}
	return false
}

type docsSecretHit struct {
	line int
	flag string
	text string
}

func scanMarkdownForSecrets(content string) []docsSecretHit {
	var hits []docsSecretHit
	inFence := false
	for i, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if strings.Contains(line, docsSecretsAllowMarker) {
			continue
		}
		if inFence {
			if f := findSecretOnCommandLine(line, false); f != "" {
				hits = append(hits, docsSecretHit{i + 1, f, strings.TrimSpace(line)})
			}
			continue
		}
		for _, sm := range inlineCodeRE.FindAllStringSubmatch(line, -1) {
			if f := findSecretOnCommandLine(sm[1], false); f != "" {
				hits = append(hits, docsSecretHit{i + 1, f, strings.TrimSpace(line)})
				break
			}
		}
	}
	return hits
}

func scanTextForSecrets(content string) []docsSecretHit {
	var hits []docsSecretHit
	for i, line := range strings.Split(content, "\n") {
		if f := findSecretOnCommandLine(line, true); f != "" {
			hits = append(hits, docsSecretHit{i + 1, f, strings.TrimSpace(line)})
		}
	}
	return hits
}

// scanShellForSecrets flags a secretFlags flag with a value on any non-comment line of a
// shell script, and the tool-specific argv shapes in findSecretArgvShape. Comment-only
// lines are skipped (they document, they do not execute); a trailing comment on a code
// line is still scanned, and the explicit marker opts a line out.
func scanShellForSecrets(content string) []docsSecretHit {
	var hits []docsSecretHit
	for i, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if f := findSecretOnCommandLine(line, false); f != "" {
			hits = append(hits, docsSecretHit{i + 1, f, strings.TrimSpace(line)})
			continue
		}
		if f := findSecretArgvShape(line); f != "" {
			hits = append(hits, docsSecretHit{i + 1, f, strings.TrimSpace(line)})
		}
	}
	return hits
}

// SCRIPTS-SECRETS-2: the argv shapes that are not "--secret-flag value".
//
// Recognised (one line at a time, comment-only lines already skipped):
//   - curl/wget header flag (-H, --header) whose header NAME is a credential header
//     (Authorization, Proxy-Authorization, Cookie, and any X-*Token / *Key / *Secret /
//     *Auth / *Password header, e.g. X-Vault-Token, X-Keyorix-Bootstrap-Token).
//     `-H @file` is the safe form. The header value is not inspected: a
//     credential header on argv is the problem whatever it expands to.
//   - curl body flags (-d, --data, --data-raw, --data-binary, --data-urlencode,
//     --data-ascii, --json) whose literal value (the next quoted word, or bare word)
//     does not start with '@' and mentions a credential word (password, passphrase,
//     token, secret, totp, mfa, otp, api key, credential). `--data-binary @-`
//     and `-d @file` are the safe forms.
//   - docker/podman env flag (-e, --env) with NAME=VALUE where NAME contains
//     PASSWORD, PASSWD, TOKEN, SECRET, PASSPHRASE, API_KEY, MFA, TOTP or CODE.
//     `-e NAME` (inherit from the environment) and `--env-file` are the safe forms.
//   - curl -u/--user USER:PASS.
//
// NOT recognised, so a green run is not more than this: a header or body held in a
// variable ("$hdr", "$body") or built by a function; a header split from its flag by a
// line continuation; helm --set, kubectl --from-literal and an interpreter's argv
// (python3 -c / jq --arg). `NAME=value cmd` environment prefixes are not argv and are
// deliberately allowed.
var (
	credHeaderFlagRE = regexp.MustCompile(`(?i)(?:^|[\s(])(?:-H|--header)(?:=|\s+)["']?(?:Authorization|Proxy-Authorization|Cookie|X-[A-Za-z0-9-]*(?:Token|Key|Secret|Auth|Password)[A-Za-z0-9-]*)\s*:`)
	curlBodyFlagRE   = regexp.MustCompile(`(?:^|[\s(])(-d|--data|--data-raw|--data-binary|--data-urlencode|--data-ascii|--json)(?:=|\s+)(\S.*)$`)
	credWordRE       = regexp.MustCompile(`(?i)pass(?:word|wd|phrase)?|token|totp|mfa|otp|api[_-]?key|credential|secret[_-]?(?:value|key|id)|client_secret|\\?"value\\?"`)
	envFlagCredRE    = regexp.MustCompile(`(?:^|[\s(])(?:-e|--env)(?:=|\s+)["']?[A-Za-z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|PASSPHRASE|API_?KEY|MFA|TOTP|CODE)[A-Za-z0-9_]*=`)
	curlUserFlagRE   = regexp.MustCompile(`(?:^|[\s(])(?:-u|--user)(?:=|\s+)["']?[^\s"':@]+:[^\s"']`)
)

// firstWord returns the first shell word of s: a quoted string (to its closing quote,
// honouring backslash escapes inside double quotes) or a bare run up to whitespace.
func firstWord(s string) string {
	if s == "" {
		return ""
	}
	q := s[0]
	if q != '"' && q != '\'' {
		if i := strings.IndexAny(s, " \t"); i >= 0 {
			return s[:i]
		}
		return s
	}
	for i := 1; i < len(s); i++ {
		if q == '"' && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == q {
			return s[1:i]
		}
	}
	return s[1:]
}

func findSecretArgvShape(line string) string {
	if strings.Contains(line, docsSecretsAllowMarker) {
		return ""
	}
	if m := credHeaderFlagRE.FindString(line); m != "" {
		return "credential header on argv: " + strings.TrimSpace(m)
	}
	for _, m := range curlBodyFlagRE.FindAllStringSubmatch(line, -1) {
		val := firstWord(m[2])
		if strings.HasPrefix(val, "@") {
			continue
		}
		if credWordRE.MatchString(val) {
			return "credential in " + m[1] + " body on argv"
		}
	}
	if m := envFlagCredRE.FindString(line); m != "" {
		return "credential container env on argv: " + strings.TrimSpace(m)
	}
	// -u means "UTC" to date and "unique" to sort, so only a line that names curl counts.
	if strings.Contains(line, "curl") && curlUserFlagRE.MatchString(line) {
		return "credential in curl -u on argv"
	}
	return ""
}

var docsSecretsSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".scratch": true,
	"dist": true, "build": true, ".next": true, "target": true,
}

// TestDocsShowNoLiteralSecretOnCommandLine is the guard. See the file header.
func TestDocsShowNoLiteralSecretOnCommandLine(t *testing.T) {
	root := repoRoot(t)
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if docsSecretsSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		isMD := strings.HasSuffix(name, ".md")
		isNotes := name == "NOTES.txt"
		isGo := strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
		relSh, _ := filepath.Rel(root, path)
		relSh = filepath.ToSlash(relSh)
		isShell := strings.HasSuffix(name, ".sh") &&
			(strings.HasPrefix(relSh, "scripts/") || strings.HasPrefix(relSh, "deploy/"))
		if !isMD && !isNotes && !isGo && !isShell {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- walk of the repo checkout
		if rerr != nil {
			return rerr
		}
		scanned++
		var hits []docsSecretHit
		switch {
		case isMD:
			hits = scanMarkdownForSecrets(string(b))
		case isShell:
			hits = scanShellForSecrets(string(b))
		default:
			hits = scanTextForSecrets(string(b))
		}
		rel, _ := filepath.Rel(root, path)
		for _, h := range hits {
			if allowedElsewhere(rel, h.text) {
				continue
			}
			t.Errorf("%s:%d shows a secret on the command line (%s): %s\n"+
				"  use a hidden prompt, --interactive, --from-file, or a KEYORIX_* env var; "+
				"for an intentional \"don't do this\" example add the marker %q to the line",
				rel, h.line, h.flag, h.text, docsSecretsAllowMarker)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	// Liveness: a walk that matched nothing would pass vacuously.
	if scanned < 20 {
		t.Fatalf("scanned only %d files under %s; the walk is not reaching the docs", scanned, root)
	}
}

// TestDocsSecretGuardCalibration proves the guard is red on the shapes it exists
// to catch and green on the safe forms, so a green TestDocsShowNoLiteralSecret...
// means something.
func TestDocsSecretGuardCalibration(t *testing.T) {
	fence := "```bash\n"
	end := "\n```"
	mustFlag := map[string]string{
		"literal value":       fence + `keyorix secret create --name a --value "hunter2"` + end,
		"bare value":          fence + `keyorix login --username admin --password hunter2` + end,
		"equals form":         fence + `keyorix login --password=hunter2` + end,
		"variable still argv": fence + `keyorix system init --admin-password "$PW"` + end,
		"placeholder":         fence + `keyorix system init --bootstrap-token <token>` + end,
		"continuation line":   fence + "keyorix system init \\\n  --admin-password secret \\\n  --admin-email a@b.c" + end,
		"inline code span":    "Run `keyorix secret rotate --id 1 --value abc` now.",
		"mfa code":            fence + `keyorix mfa activate --code 123456` + end,
		"token":               fence + `keyorix secret list --token abc123` + end,
	}
	for name, md := range mustFlag {
		if len(scanMarkdownForSecrets(md)) == 0 {
			t.Errorf("guard missed (%s): %q", name, md)
		}
	}
	mustPass := map[string]string{
		"interactive":       fence + `keyorix secret create --name a --interactive` + end,
		"from-file":         fence + `keyorix secret create --name a --from-file ./v.txt` + end,
		"token-file":        fence + `keyorix-migrate vault --token-file ./k.token` + end,
		"prose mention":     "Omit the --password flag and you are prompted; `--value`, which leaks, is avoided.",
		"flag then flag":    fence + `keyorix secret create --value --name a` + end,
		"allow marker":      fence + `keyorix login --password hunter2   # docs-secrets:allow (what not to do)` + end,
		"html allow marker": "Never run `keyorix login --password hunter2`. <!-- docs-secrets:allow -->",
		"env var":           fence + `KEYORIX_ADMIN_PASSWORD=x keyorix system init --server http://h` + end,
	}
	for name, md := range mustPass {
		if hits := scanMarkdownForSecrets(md); len(hits) != 0 {
			t.Errorf("guard false positive (%s): %q -> %+v", name, md, hits)
		}
	}

	// Shell scripts: red on the shapes the scripts used to carry, green on the safe forms.
	for name, sh := range map[string]string{
		"smoke init":       "\"$CLI_BIN\" system init --server \"$URL\" \\\n    --admin-password \"$ADMIN_PASSWORD\" --admin-email a@b.c",
		"login password":   `"$CLI" login --server "$URL" --username admin --password "$PW"`,
		"mfa code":         `"$CLI" login --username admin --mfa-code "$CODE"`,
		"secret value":     `kx secret create --name x --value 'literal' --project 1`,
		"vault token":      `keyorix-migrate vault --vault-addr "$A" --vault-token "$T"`,
		"pat token":        `keyorix-migrate vault plan-access --server "$S" --token "$PAT"`,
		"equals form":      `"$CLI" login --password="$PW"`,
		"trailing comment": `"$CLI" login --password "$PW" # not a comment-only line`,
		// SCRIPTS-SECRETS-2 shapes.
		"bearer header":        `curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/v1/x"`,
		"bearer header equals": `curl -s --header="Authorization: Bearer $TOKEN" "$URL"`,
		"header array":         `H=(-H "X-Vault-Token: ${ROOT_TOKEN}")`,
		"header in args+=":     `[ -n "$t" ] && args+=(-H "Authorization: Bearer $t")`,
		"vault token single":   `curl -sf -H 'X-Vault-Token: abc' "$A"`,
		"cookie header":        `curl -H "Cookie: session=$S" "$URL"`,
		"bootstrap header":     `curl -H "X-Keyorix-Bootstrap-Token: ${T:-}" "$URL"`,
		"login json body":      `curl -s -X POST "$URL" -d "{\"username\":\"a\",\"password\":\"$PW\"}"`,
		"data-raw body":        `curl -s --data-raw '{"password":"x"}' "$URL"`,
		"json flag body":       `curl -s --json "{\"mfa_code\":\"$C\"}" "$URL"`,
		"urlencode body":       `curl --data-urlencode "token=$T" "$URL"`,
		"docker env password":  `docker run -d -e KEYORIX_MASTER_PASSWORD="$PW" img`,
		"docker env token":     `    -e KEYORIX_BOOTSTRAP_TOKEN="$TOK" \`,
		"docker env long":      `docker run --env POSTGRES_PASSWORD=x img`,
		"curl user":            `curl -u "admin:$PW" "$URL"`,
	} {
		if len(scanShellForSecrets(sh)) == 0 {
			t.Errorf("shell guard missed (%s): %q", name, sh)
		}
	}
	for name, sh := range map[string]string{
		"env prefix":     `KEYORIX_PASSWORD="$PW" "$CLI" login --server "$URL" --username admin`,
		"from-file":      `"$CLI" secret create --name x --from-file ./v.txt --project 1`,
		"token-file":     `keyorix-migrate vault --vault-token-file ./t --token-file ./k`,
		"stdin pipe":     `printf '%s\n' "$PW" | "$CLI" login --server "$URL" --username admin`,
		"comment only":   `# the old form was --password "$PW" and leaked into ps`,
		"flag then flag": `"$CLI" secret create --value --name x`,
		"allow marker":   `"$CLI" login --password "$PW" # docs-secrets:allow (fixture)`,
		// SCRIPTS-SECRETS-2 safe forms.
		"header file":          `curl -s -H @"$hdr" "$URL/api/v1/x"`,
		"header file plain":    `curl -s -H @.hdr "$URL"`,
		"content type header":  `curl -s -H "Content-Type: application/json" "$URL"`,
		"data from stdin":      `printf '%s' "$body" | curl -s --data-binary @- "$URL"`,
		"data from file":       `curl -s -d @"$f" "$URL"`,
		"quoted at file":       `curl -s -d "@$f" "$URL"`,
		"data without secret":  `curl -s -X POST -d '{"name":"p1"}' "$URL"`,
		"tr -d":                `printf x | tr -d '\n'`,
		"docker env-file":      `docker run --env-file "$envf" img`,
		"docker env inherit":   `docker run -e KEYORIX_MASTER_PASSWORD img`,
		"docker env plain":     `docker run -e TZ=UTC -e LOG_LEVEL=debug img`,
		"bootstrap env prefix": `KEYORIX_BOOTSTRAP_TOKEN="$T" "$CLI" system init`,
		"test -e":              `[ -e "$TOKEN_FILE" ] && echo ok`,
		"curl user no pass":    `curl -u admin "$URL"`,
		"allow marker curl":    `curl -H "Authorization: Bearer $T" "$URL" # docs-secrets:allow (fixture)`,
	} {
		if hits := scanShellForSecrets(sh); len(hits) != 0 {
			t.Errorf("shell guard false positive (%s): %q -> %+v", name, sh, hits)
		}
	}

	// Free-text (Go example/hint text, NOTES.txt).
	if len(scanTextForSecrets(`fmt.Printf("  keyorix secret create --name %s --value <value>\n", n)`)) == 0 {
		t.Error("guard missed a Go hint line with --value <value>")
	}
	for _, ok := range []string{
		`return fmt.Errorf("admin password is required (--admin-password, KEYORIX_ADMIN_PASSWORD, or the prompt)")`,
		`// the (insecure, warned) --password flag, or else a prompt`,
		`fmt.Fprintln(os.Stderr, "Warning: --code/--password are visible in your shell history")`,
	} {
		if hits := scanTextForSecrets(ok); len(hits) != 0 {
			t.Errorf("guard false positive on prose line %q -> %+v", ok, hits)
		}
	}
}

// TestDocsSecretsPathAllowlist: the ADR-099 exemption must (a) be needed -- the
// line is a real hit for the scanner -- and (b) exempt only that example, in that
// file, so it cannot become a general escape hatch.
func TestDocsSecretsPathAllowlist(t *testing.T) {
	adr := "docs/adr-099-master-passphrase-sourcing.md"
	line := "- **A `--passphrase <value>` flag.** Rejected outright: a value on the"
	if len(scanMarkdownForSecrets(line)) == 0 {
		t.Fatal("scanner no longer flags the ADR-099 line; the allowlist entry is dead, remove it")
	}
	if !allowedElsewhere(adr, line) {
		t.Error("ADR-099 rejected-design line should be allowlisted")
	}
	if allowedElsewhere(adr, "Run `keyorix login --password hunter2` now.") {
		t.Error("allowlist must not exempt other lines in the same file")
	}
	if allowedElsewhere("docs/other.md", line) {
		t.Error("allowlist must not exempt the same text in another file")
	}
}
