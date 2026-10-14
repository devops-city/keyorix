package healthscan

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
)

// Report is the result of one scan run.
type Report struct {
	GeneratedBy string `json:"generated_by"`
	VaultAddr   string `json:"vault_addr"`

	// Score, ScoreFormula, and TopRisks are the executive summary (SESSION-G3). Score and
	// ScoreFormula are computed together (score.go's Score/ScoreFormula) so the number and the
	// prose describing it can never drift apart.
	Score        int       `json:"score"`
	ScoreFormula string    `json:"score_formula"`
	TopRisks     []Finding `json:"top_risks"`

	Findings   []Finding    `json:"findings"`
	NotChecked []NotChecked `json:"not_checked"`

	// MigrationReadiness is nil when the migration-readiness check didn't run (not registered,
	// denied, or errored) — WriteMarkdown/HTML render its absence plainly rather than omitting
	// the section outright, so a reader always knows the section was considered.
	MigrationReadiness *MigrationReadiness `json:"migration_readiness,omitempty"`

	// Footer is the neutral, no-marketing-tone closing line SESSION-G3 specifies.
	Footer string `json:"footer"`
}

// SchemaVersion is the JSON report's own schema version — bumped whenever a field is added,
// renamed, or removed, so a consumer of the JSON output (the "share the JSON with us" flow) can
// tell which shape it's reading. Bumped to 2 in G3: added score/score_formula/top_risks/
// migration_readiness/footer to G1's skeleton envelope. Bumped to 3 (MIG-3, release-readiness
// pass): Finding/NotChecked never had json tags, so every entry in top_risks/findings/
// not_checked rendered PascalCase field names (ID, WhyItMatters, ...) inconsistent with the rest
// of this envelope's snake_case convention — a real blemish for the one JSON surface this tool
// explicitly asks customers to hand to an external consumer ("Sharing the JSON with us").
const SchemaVersion = 3

// jsonReport is the on-the-wire shape written by WriteJSON — SchemaVersion is a field on the
// envelope, not on Report itself, so Report's Go shape can evolve without every caller of Run
// needing to thread a schema version through.
type jsonReport struct {
	SchemaVersion int `json:"schema_version"`
	Report
}

// WriteJSON writes r as the versioned JSON report schema.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{SchemaVersion: SchemaVersion, Report: *r})
}

// WriteMarkdown writes r as a Markdown report: executive summary (score + formula + top 5
// risks), a findings table, per-check detail, "Not checked" (with the policy line that would
// enable each), "Migration readiness", and the neutral footer. No marketing tone anywhere in
// findings text — that discipline lives in each check's own Finding text, not here.
func WriteMarkdown(w io.Writer, r *Report) error {
	p := &errPrinter{w: w}
	p.f("# Vault Health Scan\n\n%s against `%s`\n\n", r.GeneratedBy, r.VaultAddr)

	p.f("## Executive summary\n\n")
	p.f("**Score: %d/100**\n\n_%s_\n\n", r.Score, r.ScoreFormula)
	if len(r.TopRisks) == 0 {
		p.f("No risk-weighted findings — either nothing was found, or every check that ran came back clean.\n\n")
	} else {
		p.f("Top risks:\n\n")
		for i, f := range r.TopRisks {
			p.f("%d. **[%s] %s** (%s) — %s\n", i+1, f.ID, f.Title, f.Severity, f.Evidence)
		}
		p.f("\n")
	}

	p.f("## Findings\n\n")
	if len(r.Findings) == 0 {
		p.f("_No findings._\n\n")
	} else {
		p.f("| ID | Title | Severity | Evidence |\n|---|---|---|---|\n")
		for _, f := range r.Findings {
			p.f("| %s | %s | %s | %s |\n", f.ID, f.Title, f.Severity, mdEscapeCell(f.Evidence))
		}
		p.f("\n")
	}

	p.f("## Per-check detail\n\n")
	for _, f := range r.Findings {
		p.f("### [%s] %s (%s)\n\n- **Evidence:** %s\n- **Why it matters:** %s\n- **Remediation:** %s\n\n",
			f.ID, f.Title, f.Severity, f.Evidence, emptyDash(f.WhyItMatters), emptyDash(f.Remediation))
	}

	if len(r.NotChecked) > 0 {
		p.f("## Not checked\n\n")
		for _, nc := range r.NotChecked {
			p.f("- **%s**: %s%s\n", nc.ID, nc.Reason, policyLineSuffix(nc.PolicyLine))
		}
		p.f("\n")
	}

	p.f("## Migration readiness\n\n")
	if r.MigrationReadiness == nil {
		p.f("Not available for this scan (the migration-readiness check didn't run or was denied — see \"Not checked\" above).\n\n")
	} else {
		mr := r.MigrationReadiness
		p.f("- KV v1 mounts: %d\n- KV v2 mounts: %d\n- Approximate top-level secrets (importable via `keyorix-migrate vault`): %d%s\n- Dynamic-secrets mounts (NOT importable — no static value to migrate): %s\n\n",
			mr.KVv1Mounts, mr.KVv2Mounts, mr.KVTopLevelSecrets, truncatedSuffix(mr.Truncated), listOrNone(mr.DynamicMounts))
	}

	p.f("---\n\n%s\n", r.Footer)
	return p.err
}

// WriteHTML writes r as a single-file HTML report (inline CSS, no external assets, prints well).
// Every dynamic value is HTML-escaped — a Vault error message or path reflected into
// evidence/reason text must never be interpreted as markup.
func WriteHTML(w io.Writer, r *Report) error {
	p := &errPrinter{w: w}
	p.f("<!doctype html><html><head><meta charset=\"utf-8\"><title>Vault Health Scan</title>" +
		"<style>body{font-family:sans-serif;max-width:60rem;margin:2rem auto;line-height:1.5;padding:0 1rem}" +
		"h3{margin-bottom:.25rem}.sev-critical{color:#b00}.sev-high{color:#c60}.sev-medium{color:#996800}" +
		".sev-low{color:#555}.sev-info{color:#555}code{background:#f2f2f2;padding:.1rem .3rem}" +
		"table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}" +
		"footer{margin-top:2rem;border-top:1px solid #ccc;padding-top:1rem;color:#555}" +
		"@media print{body{max-width:100%%}}</style></head><body>\n")

	p.f("<h1>Vault Health Scan</h1><p>%s against <code>%s</code></p>\n", esc(r.GeneratedBy), esc(r.VaultAddr))

	p.f("<h2>Executive summary</h2><p><strong>Score: %d/100</strong></p><p><em>%s</em></p>\n", r.Score, esc(r.ScoreFormula))
	if len(r.TopRisks) == 0 {
		p.f("<p>No risk-weighted findings — either nothing was found, or every check that ran came back clean.</p>\n")
	} else {
		p.f("<p>Top risks:</p><ol>\n")
		for _, f := range r.TopRisks {
			p.f("<li class=\"sev-%s\"><strong>[%s] %s</strong> (%s) — %s</li>\n", esc(string(f.Severity)), esc(f.ID), esc(f.Title), esc(string(f.Severity)), esc(f.Evidence))
		}
		p.f("</ol>\n")
	}

	p.f("<h2>Findings</h2>\n")
	if len(r.Findings) == 0 {
		p.f("<p><em>No findings.</em></p>\n")
	} else {
		p.f("<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Evidence</th></tr>\n")
		for _, f := range r.Findings {
			p.f("<tr><td>%s</td><td>%s</td><td class=\"sev-%s\">%s</td><td>%s</td></tr>\n",
				esc(f.ID), esc(f.Title), esc(string(f.Severity)), esc(string(f.Severity)), esc(f.Evidence))
		}
		p.f("</table>\n")
	}

	p.f("<h2>Per-check detail</h2>\n")
	for _, f := range r.Findings {
		p.f("<h3 class=\"sev-%s\">[%s] %s (%s)</h3><ul>"+
			"<li><strong>Evidence:</strong> %s</li>"+
			"<li><strong>Why it matters:</strong> %s</li>"+
			"<li><strong>Remediation:</strong> %s</li></ul>\n",
			esc(string(f.Severity)), esc(f.ID), esc(f.Title), esc(string(f.Severity)),
			esc(f.Evidence), esc(emptyDash(f.WhyItMatters)), esc(emptyDash(f.Remediation)))
	}

	if len(r.NotChecked) > 0 {
		p.f("<h2>Not checked</h2><ul>\n")
		for _, nc := range r.NotChecked {
			p.f("<li><strong>%s</strong>: %s%s</li>\n", esc(nc.ID), esc(nc.Reason), esc(policyLineSuffix(nc.PolicyLine)))
		}
		p.f("</ul>\n")
	}

	p.f("<h2>Migration readiness</h2>\n")
	if r.MigrationReadiness == nil {
		p.f("<p>Not available for this scan (the migration-readiness check didn't run or was denied — see \"Not checked\" above).</p>\n")
	} else {
		mr := r.MigrationReadiness
		p.f("<ul><li>KV v1 mounts: %d</li><li>KV v2 mounts: %d</li>"+
			"<li>Approximate top-level secrets (importable via <code>keyorix-migrate vault</code>): %d%s</li>"+
			"<li>Dynamic-secrets mounts (NOT importable — no static value to migrate): %s</li></ul>\n",
			mr.KVv1Mounts, mr.KVv2Mounts, mr.KVTopLevelSecrets, esc(truncatedSuffix(mr.Truncated)), esc(listOrNone(mr.DynamicMounts)))
	}

	p.f("<footer>%s</footer>\n", esc(r.Footer))
	p.f("</body></html>\n")
	return p.err
}

// errPrinter accumulates the first write error (if any) so every WriteMarkdown/WriteHTML call
// site doesn't need its own `if err != nil { return err }` after every Fprintf.
type errPrinter struct {
	w   io.Writer
	err error
}

func (p *errPrinter) f(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

func esc(s string) string { return html.EscapeString(s) }

func mdEscapeCell(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '|' || s[i] == '\n' {
			out = append(out, ' ')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

func emptyDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func policyLineSuffix(policyLine string) string {
	if policyLine == "" {
		return ""
	}
	return fmt.Sprintf(" (enable with: %s)", policyLine)
}

func truncatedSuffix(truncated bool) string {
	if !truncated {
		return ""
	}
	return " (truncated — this is a lower bound)"
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return fmt.Sprintf("%v", items)
}
