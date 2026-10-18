package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
	"github.com/keyorixhq/keyorix/cli/internal/skew"
)

// Statuses of one doctor check.
const (
	doctorPass = "pass"
	doctorWarn = "warn"
	doctorFail = "fail"
	doctorSkip = "skip"
)

// Clock-skew thresholds. TOTP codes are valid for about 30 seconds and session tokens
// carry issued-at/expiry times, so a clock a minute off already causes "invalid code" and
// "token expired" reports that look like something else.
const (
	clockSkewWarn = 30 * time.Second
	clockSkewFail = 5 * time.Minute
)

// A certificate this close to expiry is a warning; once expired, a failure.
const certExpiryWarnDays = 30

var (
	// doctorNow is the clock the checks compare the server against (a var for tests).
	doctorNow    = time.Now
	doctorOutput string
)

type doctorCheck struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	NextStep string `json:"next_step,omitempty"`
}

type doctorReport struct {
	Server     string        `json:"server,omitempty"`
	CLIVersion string        `json:"cli_version"`
	Checks     []doctorCheck `json:"checks"`
	Passed     int           `json:"passed"`
	Warnings   int           `json:"warnings"`
	Failed     int           `json:"failed"`
	Skipped    int           `json:"skipped"`
	OK         bool          `json:"ok"`
}

func (r *doctorReport) add(name, status, detail, next string) {
	r.Checks = append(r.Checks, doctorCheck{Name: name, Status: status, Detail: detail, NextStep: next})
	switch status {
	case doctorPass:
		r.Passed++
	case doctorWarn:
		r.Warnings++
	case doctorFail:
		r.Failed++
	default:
		r.Skipped++
	}
	r.OK = r.Failed == 0
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose the connection to the server: reachability, TLS, login, clock, version, audit chain",
	Long: `doctor runs a read-only checklist against the configured server and says, for each
item that is not healthy, what to do next. It only reads: it never changes anything on the
server and never runs the long full audit walk (use "keyorix audit verify --full" for that).

Checks, in order:
  config      the server URL, token and CA file the CLI would use, and where each came from
  reachable   the server answers GET /health
  tls         the TLS chain verifies for the host (against --ca-file or the system roots), and when it expires
  version     the server's API version and minimum CLI version against this CLI
  clock       this machine's clock against the server's (a skewed clock breaks TOTP codes and sessions)
  auth        the stored token is accepted, and who it belongs to
  audit       the audit hash chain's integrity as the server last proved it

Checks that need an earlier one to pass are skipped, not failed. The exit code is 0 when
nothing failed (warnings do not fail it) and 1 otherwise (2 for a bad flag; see the
exit-code table in "keyorix --help").`,
	Example: `  # Run every check against the configured server
  keyorix doctor
  # The same, for a script: JSON, and a non-zero exit if any check failed
  keyorix doctor -o json
  # Check a private-CA server without changing your saved settings
  keyorix doctor --ca-file /etc/keyorix/ca.pem`,
	Args: cobra.NoArgs,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().StringVarP(&doctorOutput, "output", "o", "table", "Output format: table, json or yaml")
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	switch doctorOutput {
	case "table", "json", "yaml":
	default:
		return usageErrorf("unsupported output format %q: use table, json or yaml", doctorOutput)
	}
	rep := collectDoctorReport(cmd.Context())
	if err := printDoctorReport(rep); err != nil {
		return err
	}
	if rep.Failed > 0 {
		return fmt.Errorf("doctor found %d problem(s)", rep.Failed)
	}
	return nil
}

// collectDoctorReport runs every check. It never returns an error: each problem is a
// check result.
func collectDoctorReport(ctx context.Context) *doctorReport {
	if ctx == nil {
		ctx = context.Background()
	}
	rep := &doctorReport{CLIVersion: cliversion.Version, OK: true}

	store, err := resolveCredStore()
	if err != nil {
		rep.add("config", doctorFail, "cannot locate the credentials file: "+err.Error(), "check that your user config directory is available")
		skipRest(rep, "config")
		return rep
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		rep.add("config", doctorFail, "no server is configured", "run `keyorix login --server <url>` (or set KEYORIX_SERVER and KEYORIX_TOKEN)")
		skipRest(rep, "config")
		return rep
	}
	rep.Server = serverURL
	caFile, caSource := resolveCAFile()
	rep.add(doctorConfigCheck(serverURL, token, caFile, caSource))

	client, err := newAPIClient(serverURL, token)
	if err != nil {
		// The only way to get here is an unusable CA file.
		rep.add("reachable", doctorSkip, "cannot build a client: "+err.Error(), "fix or remove the CA file setting (`keyorix config unset ca_file`)")
		rep.add("tls", doctorSkip, "needs a working CA file setting", "")
		skipRest(rep, "tls")
		return rep
	}

	reachable := doctorReachable(ctx, rep, client, serverURL)
	doctorTLS(ctx, rep, serverURL, caFile, reachable)
	versionOK := doctorVersionAndClock(ctx, rep, client, token, reachable)
	authOK := doctorAuth(ctx, rep, client, token, reachable && versionOK)
	doctorAudit(ctx, rep, client, authOK)
	return rep
}

// skipRest records the checks after `after` as skipped because it failed.
func skipRest(rep *doctorReport, after string) {
	order := []string{"config", "reachable", "tls", "version", "clock", "auth", "audit"}
	seen := false
	have := map[string]bool{}
	for _, c := range rep.Checks {
		have[c.Name] = true
	}
	for _, name := range order {
		if name == after {
			seen = true
			continue
		}
		if seen && !have[name] {
			rep.add(name, doctorSkip, "not checked: "+after+" failed", "")
		}
	}
}

func doctorConfigCheck(serverURL, token, caFile, caSource string) (string, string, string, string) {
	var parts []string
	srcServer := "the credentials file"
	if os.Getenv("KEYORIX_SERVER") != "" {
		srcServer = "KEYORIX_SERVER"
	}
	parts = append(parts, fmt.Sprintf("server %s (from %s)", cliout.SanitizeForTerminal(serverURL), srcServer))
	switch {
	case token == "":
		parts = append(parts, "no token")
	case os.Getenv("KEYORIX_TOKEN") != "":
		parts = append(parts, "token from KEYORIX_TOKEN")
	default:
		parts = append(parts, "token from the credentials file")
	}
	if caFile != "" {
		parts = append(parts, fmt.Sprintf("CA file %s (from %s)", cliout.SanitizeForTerminal(caFile), caSource))
		if _, err := apiclient.LoadCAPool(caFile); err != nil {
			return "config", doctorFail, strings.Join(parts, "; ") + ": " + err.Error(),
				"fix the path or contents of the CA file, or remove it with `keyorix config unset ca_file`"
		}
	}
	if u, err := url.Parse(serverURL); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "config", doctorFail, strings.Join(parts, "; ") + ": the server URL is not an http(s) URL",
			"log in again with a full URL: `keyorix login --server https://host`"
	}
	return "config", doctorPass, strings.Join(parts, "; "), ""
}

// doctorReachable checks GET /health and reports whether the server answered at all.
func doctorReachable(ctx context.Context, rep *doctorReport, client *apiclient.ClientWithResponses, serverURL string) bool {
	start := doctorNow()
	resp, err := client.HealthCheckWithResponse(ctx)
	elapsed := doctorNow().Sub(start).Round(time.Millisecond)
	if err != nil {
		next := "check that the server is running and the URL is right (`keyorix status` shows the URL in use); if it is behind a proxy or VPN, check that too"
		detail := cliout.SanitizeForTerminal(err.Error())
		if described, ok := apiclient.DescribeTransportError(err); ok {
			// The same plain-language text every other command prints; its "Next step:" tail
			// moves into next_step so the report keeps its two columns.
			detail = cliout.SanitizeForTerminal(described)
			if head, tail, found := strings.Cut(detail, " Next step: "); found {
				detail, next = head, tail
			}
		}
		rep.add("reachable", doctorFail, "no answer from "+cliout.SanitizeForTerminal(serverURL)+": "+detail, next)
		return false
	}
	switch {
	case resp.StatusCode() == http.StatusOK:
		rep.add("reachable", doctorPass, fmt.Sprintf("GET /health answered %d in %s", resp.StatusCode(), elapsed), "")
		return true
	default:
		rep.add("reachable", doctorFail, fmt.Sprintf("GET /health answered HTTP %d in %s", resp.StatusCode(), elapsed),
			"the server is up but unhealthy: check its logs; if a proxy sits in front, check that it forwards to the server")
		return true // it answered; later checks can still say more
	}
}

func doctorTLS(ctx context.Context, rep *doctorReport, serverURL, caFile string, reachable bool) {
	u, err := url.Parse(serverURL)
	if err != nil {
		rep.add("tls", doctorSkip, "invalid server URL", "")
		return
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" {
			rep.add("tls", doctorSkip, "plain http to a loopback address; nothing leaves this machine", "")
			return
		}
		rep.add("tls", doctorWarn, "the server URL is plain http: your token and secrets travel unencrypted",
			"use an https URL (`keyorix login --server https://...`); enable TLS on the server or put it behind a TLS proxy")
		return
	}
	// Inspected even when /health got no answer: a certificate the CLI does not trust is
	// exactly why a request fails, and this check explains it.
	tr, err := apiclient.InspectTLS(ctx, serverURL, caFile)
	if err != nil {
		if !reachable {
			rep.add("tls", doctorSkip, "not checked: could not connect to "+tr.Host, "")
			return
		}
		rep.add("tls", doctorFail, "TLS handshake with "+tr.Host+" failed: "+cliout.SanitizeForTerminal(err.Error()),
			"check that the server really serves TLS on that port")
		return
	}
	chain := describeChain(tr.Chain)
	if !tr.Verified {
		rep.add("tls", doctorFail, fmt.Sprintf("the certificate does not verify against %s: %s%s", tr.TrustSource, tr.VerifyError, chain),
			"if the server uses a private CA, trust it with `keyorix config set ca_file <ca.pem>` (or --ca-file); otherwise fix the certificate on the server (name, expiry, intermediate certificates)")
		return
	}
	detail := fmt.Sprintf("chain verifies against %s (%s)%s", tr.TrustSource, tr.TLSVersion, chain)
	if len(tr.Chain) > 0 {
		left := tr.Chain[0].NotAfter.Sub(doctorNow())
		days := int(left.Hours() / 24)
		detail += fmt.Sprintf("; leaf expires %s (in %d days)", tr.Chain[0].NotAfter.UTC().Format("2006-01-02"), days)
		switch {
		case left <= 0:
			rep.add("tls", doctorFail, detail, "renew the server certificate")
			return
		case days < certExpiryWarnDays:
			rep.add("tls", doctorWarn, detail, "renew the server certificate soon")
			return
		}
	}
	rep.add("tls", doctorPass, detail, "")
}

func describeChain(chain []apiclient.CertInfo) string {
	if len(chain) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("; chain: ")
	for i, c := range chain {
		if i > 0 {
			b.WriteString(" <- ")
		}
		b.WriteString(cliout.SanitizeForTerminal(c.Subject))
	}
	return b.String()
}

// doctorVersionAndClock calls GET /api/v1/version once and derives two checks from it:
// compatibility (the response body) and clock skew (its Date header). It returns whether
// the server answered the version call.
func doctorVersionAndClock(ctx context.Context, rep *doctorReport, client *apiclient.ClientWithResponses, token string, reachable bool) bool {
	if !reachable {
		rep.add("version", doctorSkip, "not checked: the server did not answer", "")
		rep.add("clock", doctorSkip, "not checked: the server did not answer", "")
		return false
	}
	sent := doctorNow()
	resp, err := client.GetVersionWithResponse(ctx)
	received := doctorNow()
	if err != nil {
		rep.add("version", doctorFail, "GET /api/v1/version failed: "+cliout.SanitizeForTerminal(err.Error()),
			"the server answered /health but not the API: check that the URL points at the Keyorix server (not just its web front end)")
		rep.add("clock", doctorSkip, "not checked: no answer from the API", "")
		return false
	}

	switch {
	case resp.StatusCode() == http.StatusNotFound:
		rep.add("version", doctorWarn, "the server predates the version endpoint (GET /api/v1/version): it is a much older release and some commands may not work",
			"upgrade the server, or use a matching older CLI")
	case resp.JSON200 == nil:
		rep.add("version", doctorFail, fmt.Sprintf("GET /api/v1/version answered HTTP %d", resp.StatusCode()),
			"check that the URL points at the Keyorix server")
	default:
		apiVersion, minCLI := 0, ""
		if resp.JSON200.ApiVersion != nil {
			apiVersion = *resp.JSON200.ApiVersion
		}
		if resp.JSON200.MinimumCliVersion != nil {
			minCLI = *resp.JSON200.MinimumCliVersion
		}
		detail := fmt.Sprintf("server API v%d; this CLI %s targets v%d", apiVersion, cliversion.Version, cliversion.TargetAPIVersion)
		if minCLI != "" {
			detail += fmt.Sprintf("; server requires CLI >= %s", minCLI)
		}
		if sv := doctorServerBuild(ctx, client, token); sv != "" {
			detail += "; server build " + sv
		}
		res := skew.Check(cliversion.Version, cliversion.TargetAPIVersion, apiVersion, minCLI)
		switch {
		case res.Refuse:
			rep.add("version", doctorFail, detail+": "+res.Reason, "install a CLI release that this server accepts")
		case res.Warning != "":
			rep.add("version", doctorWarn, detail+": "+res.Warning, "upgrade whichever side is older")
		default:
			rep.add("version", doctorPass, detail+": compatible", "")
		}
	}

	offset, ok := apiclient.ServerClockOffset(resp.HTTPResponse, sent, received)
	doctorClock(rep, offset, ok)
	return true
}

// doctorServerBuild returns the server's build version when the token may read
// /api/v1/system/info; any failure just means "unknown".
func doctorServerBuild(ctx context.Context, client *apiclient.ClientWithResponses, token string) string {
	if token == "" {
		return ""
	}
	resp, err := client.GetSystemInfoWithResponse(ctx)
	if err != nil || resp.StatusCode() != http.StatusOK {
		return ""
	}
	info, err := decodeData[struct {
		Version string `json:"version"`
	}](resp.Body)
	if err != nil {
		return ""
	}
	return cliout.SanitizeForTerminal(info.Version)
}

// doctorClock compares the server's clock with this machine's (see
// apiclient.ServerClockOffset for how the offset is estimated from the Date header).
func doctorClock(rep *doctorReport, offset time.Duration, ok bool) {
	if !ok {
		rep.add("clock", doctorSkip, "the server sent no usable Date header, so its clock cannot be compared", "")
		return
	}
	abs := offset
	if abs < 0 {
		abs = -abs
	}
	dir := "ahead of"
	if offset < 0 {
		dir = "behind"
	}
	detail := fmt.Sprintf("this machine's clock differs from the server's by %s (the server is %s this machine)", abs.Round(time.Second), dir)
	if abs < 2*time.Second {
		detail = "this machine's clock matches the server's (within 2s)"
	}
	const next = "sync this machine's clock (NTP: `timedatectl set-ntp true` on Linux, Date & Time settings on macOS/Windows); if the server's clock is the wrong one, fix it there"
	switch {
	case abs > clockSkewFail:
		rep.add("clock", doctorFail, detail+": TOTP codes and session expiry will misbehave", next)
	case abs > clockSkewWarn:
		rep.add("clock", doctorWarn, detail+": TOTP codes (valid ~30s) may be rejected", next)
	default:
		rep.add("clock", doctorPass, detail, "")
	}
}

// doctorAuth checks that the token is accepted. It returns whether it is.
func doctorAuth(ctx context.Context, rep *doctorReport, client *apiclient.ClientWithResponses, token string, canTry bool) bool {
	if !canTry {
		rep.add("auth", doctorSkip, "not checked: the server's API did not answer", "")
		return false
	}
	if token == "" {
		rep.add("auth", doctorFail, "not logged in: no token is stored or set", "run `keyorix login --server <url>`")
		return false
	}
	resp, err := client.GetAuthProfileWithResponse(ctx)
	if err != nil {
		rep.add("auth", doctorFail, "GET /api/v1/auth/profile failed: "+cliout.SanitizeForTerminal(err.Error()), "retry; if it persists, check `keyorix status`")
		return false
	}
	switch resp.StatusCode() {
	case http.StatusOK:
		who, err := decodeData[struct {
			Username     string   `json:"username"`
			Roles        []string `json:"roles"`
			PendingSteps []string `json:"pending_steps"`
		}](resp.Body)
		if err != nil || who.Username == "" {
			rep.add("auth", doctorPass, "the server accepts the token", "")
			return true
		}
		detail := "logged in as " + cliout.SanitizeForTerminal(who.Username)
		if len(who.Roles) > 0 {
			detail += " (roles: " + cliout.SanitizeForTerminal(strings.Join(who.Roles, ", ")) + ")"
		}
		if len(who.PendingSteps) > 0 {
			rep.add("auth", doctorWarn, detail+"; account setup is not finished: "+cliout.SanitizeForTerminal(strings.Join(who.PendingSteps, ", ")),
				"finish the setup steps (for MFA: `keyorix mfa enroll`, then `keyorix mfa activate`)")
			return true
		}
		rep.add("auth", doctorPass, detail, "")
		return true
	case http.StatusUnauthorized:
		rep.add("auth", doctorFail, "the server rejected the token (HTTP 401): the session expired or was revoked", "run `keyorix login`")
		return false
	case http.StatusForbidden:
		var eb apiErrorBody
		_ = json.Unmarshal(resp.Body, &eb)
		if h := nextStepHint(eb); h != "" {
			rep.add("auth", doctorWarn, "the token is valid but the server blocks it: "+cliout.SanitizeForTerminal(eb.Message), strings.TrimSpace(strings.TrimPrefix(h, " Next step:")))
			return true
		}
		rep.add("auth", doctorFail, "the server refused the token (HTTP 403): "+cliout.SanitizeForTerminal(eb.Message), "ask an administrator what the account is missing")
		return false
	default:
		rep.add("auth", doctorFail, fmt.Sprintf("GET /api/v1/auth/profile answered HTTP %d", resp.StatusCode()), "check the server logs")
		return false
	}
}

// doctorAudit reads the audit chain status the server already holds. It never starts the
// full walk, which can run for a long time.
func doctorAudit(ctx context.Context, rep *doctorReport, client *apiclient.ClientWithResponses, authOK bool) {
	if !authOK {
		rep.add("audit", doctorSkip, "not checked: needs a working login", "")
		return
	}
	resp, err := client.VerifyAuditChainWithResponse(ctx, nil)
	if err != nil {
		rep.add("audit", doctorFail, "audit verification request failed: "+cliout.SanitizeForTerminal(err.Error()), "retry; if it persists, check the server logs")
		return
	}
	switch resp.StatusCode() {
	case http.StatusOK:
	case http.StatusForbidden:
		rep.add("audit", doctorSkip, "this account may not read the audit trail (needs audit.read)", "run doctor as an auditor or administrator to include this check")
		return
	case http.StatusNotFound:
		rep.add("audit", doctorSkip, "this server does not offer audit verification", "")
		return
	default:
		rep.add("audit", doctorFail, fmt.Sprintf("audit verification answered HTTP %d", resp.StatusCode()), "check the server logs")
		return
	}
	v, err := decodeData[verifyResult](resp.Body)
	if err != nil {
		rep.add("audit", doctorFail, "unreadable audit verification response", "check that the CLI and server versions match (`keyorix status`)")
		return
	}
	detail := fmt.Sprintf("%d chained events, head id %d", v.ChainedEvents, v.HeadID)
	switch v.verifyStatus() {
	case "valid":
		if v.Mode == "incremental" && v.LastFullVerificationAt != "" {
			detail += "; last full re-walk " + cliout.SanitizeForTerminal(v.LastFullVerificationAt)
		}
		rep.add("audit", doctorPass, "audit chain valid: "+detail, "")
	case "not_proven":
		rep.add("audit", doctorWarn, "audit chain integrity not proven: "+cliout.SanitizeForTerminal(v.NotProvenReason)+" ("+detail+")",
			"run `keyorix audit verify --full` to prove it now")
	default:
		rep.add("audit", doctorFail, fmt.Sprintf("audit chain BROKEN at event %d: %s", v.FirstBrokenID, cliout.SanitizeForTerminal(v.Reason)),
			"treat this as a security incident: preserve the database and follow your incident process; `keyorix audit verify` shows the details")
	}
}

func printDoctorReport(rep *doctorReport) error {
	switch doctorOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "yaml":
		raw, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return err
		}
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)
		if err := enc.Encode(generic); err != nil {
			return err
		}
		return enc.Close()
	}

	title := "keyorix doctor"
	if rep.Server != "" {
		title += " -- " + cliout.SanitizeForTerminal(rep.Server)
	}
	fmt.Printf("%s (CLI %s)\n\n", title, rep.CLIVersion)
	label := map[string]string{doctorPass: "PASS", doctorWarn: "WARN", doctorFail: "FAIL", doctorSkip: "SKIP"}
	for _, c := range rep.Checks {
		fmt.Printf("  %s  %-10s %s\n", label[c.Status], c.Name, c.Detail)
		if c.NextStep != "" {
			fmt.Printf("        %-10s Next step: %s\n", "", c.NextStep)
		}
	}
	fmt.Printf("\n%d passed, %d warning(s), %d failed, %d skipped\n", rep.Passed, rep.Warnings, rep.Failed, rep.Skipped)
	return nil
}
