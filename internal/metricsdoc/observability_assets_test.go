package metricsdoc

// Guards for deploy/observability/: the Prometheus alert rules, the Grafana dashboard
// and the runbook. promtool is not assumed to be installed (CI has none), so these are
// structural checks plus the one that matters most for a rules file: every keyorix_*
// metric and label it mentions must exist in the code-derived inventory. A metric
// renamed in code without updating the rules fails here instead of silently never
// firing.
//
// What this does NOT prove: that the PromQL parses or evaluates as intended, or that
// thresholds are sensible. When promtool is on PATH, TestAlertRules_PromtoolCheck runs
// `promtool check rules` as well; otherwise it says it was skipped.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	obsDir      = "deploy/observability"
	runbookBase = "https://github.com/keyorixhq/keyorix/blob/main/deploy/observability/runbook.md#"
)

// implicit labels that exist on any scraped series or histogram/summary family.
var implicitLabels = []string{"instance", "job", "le", "quantile"}

var (
	metricTokenRe  = regexp.MustCompile(`\bkeyorix_[a-z0-9_]+`)
	selectorRe     = regexp.MustCompile(`(keyorix_[a-z0-9_]+)\s*\{([^}]*)\}`)
	matcherNameRe  = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=~|!~|!=|=)`)
	byClauseRe     = regexp.MustCompile(`\b(?:by|without|on|ignoring)\s*\(([^)]*)\)`)
	durationRe     = regexp.MustCompile(`^[0-9]+[smhdw]$`)
	severities     = []string{"critical", "warning", "info"}
	derivedSuffix  = []string{"_bucket", "_sum", "_count"}
	runbookHeading = regexp.MustCompile(`(?m)^## (Keyorix[A-Za-z]+)\s*$`)
)

type metricInfo struct {
	typ    string
	labels []string
}

func inventory(t *testing.T) map[string]metricInfo {
	t.Helper()
	out := map[string]metricInfo{}
	for _, d := range scanned(t) {
		out[d.Name] = metricInfo{typ: d.Type, labels: d.Labels}
	}
	return out
}

// resolveMetric maps a token to its inventory entry, accepting the _bucket/_sum/_count
// series of histograms and summaries.
func resolveMetric(inv map[string]metricInfo, tok string) (metricInfo, bool) {
	if m, ok := inv[tok]; ok {
		return m, true
	}
	for _, suf := range derivedSuffix {
		if base, ok := strings.CutSuffix(tok, suf); ok {
			if m, ok := inv[base]; ok && (m.typ == "histogram" || m.typ == "summary") {
				return m, true
			}
		}
	}
	return metricInfo{}, false
}

// checkExpr returns the problems found in one PromQL expression or dashboard query.
func checkExpr(inv map[string]metricInfo, expr string) []string {
	var problems []string
	if strings.TrimSpace(expr) == "" {
		return []string{"empty expression"}
	}
	for open, closer := range map[rune]rune{'(': ')', '[': ']', '{': '}'} {
		if strings.Count(expr, string(open)) != strings.Count(expr, string(closer)) {
			problems = append(problems, "unbalanced "+string(open)+string(closer))
		}
	}
	if strings.Count(expr, `"`)%2 != 0 {
		problems = append(problems, "odd number of double quotes")
	}
	used := map[string]metricInfo{}
	for _, tok := range metricTokenRe.FindAllString(expr, -1) {
		m, ok := resolveMetric(inv, tok)
		if !ok {
			problems = append(problems, "unknown metric "+tok+" (not in the code-derived inventory)")
			continue
		}
		used[tok] = m
	}
	for _, sel := range selectorRe.FindAllStringSubmatch(expr, -1) {
		m, ok := resolveMetric(inv, sel[1])
		if !ok {
			continue // already reported
		}
		for _, mm := range matcherNameRe.FindAllStringSubmatch(sel[2], -1) {
			if !slices.Contains(m.labels, mm[1]) && !slices.Contains(implicitLabels, mm[1]) {
				problems = append(problems, "metric "+sel[1]+" has no label "+mm[1])
			}
		}
	}
	// by/without/on/ignoring clauses: each label must exist on some metric in the expression.
	known := slices.Clone(implicitLabels)
	for _, m := range used {
		known = append(known, m.labels...)
	}
	for _, cl := range byClauseRe.FindAllStringSubmatch(expr, -1) {
		for name := range strings.SplitSeq(cl[1], ",") {
			name = strings.TrimSpace(name)
			if name != "" && !slices.Contains(known, name) {
				problems = append(problems, "grouping label "+name+" exists on none of the metrics used")
			}
		}
	}
	return problems
}

type alertRule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type ruleGroup struct {
	Name  string      `yaml:"name"`
	Rules []alertRule `yaml:"rules"`
}

func loadRules(t *testing.T) []ruleGroup {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(), obsDir, "prometheus-alerts.yaml")) //nolint:gosec // fixed repo path
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []ruleGroup `yaml:"groups"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a misspelt key (e.g. `annotation:`) must fail, not be ignored
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("prometheus-alerts.yaml does not parse: %v", err)
	}
	return doc.Groups
}

func TestAlertRules_StructureMetricsAndRunbooks(t *testing.T) {
	inv := inventory(t)
	groups := loadRules(t)
	if len(groups) == 0 {
		t.Fatal("no rule groups")
	}
	rb, err := os.ReadFile(filepath.Join(repoRoot(), obsDir, "runbook.md")) //nolint:gosec // fixed repo path
	if err != nil {
		t.Fatal(err)
	}
	headings := map[string]bool{}
	for _, m := range runbookHeading.FindAllStringSubmatch(string(rb), -1) {
		headings[m[1]] = true
	}

	seenGroup, seenAlert := map[string]bool{}, map[string]bool{}
	total := 0
	for _, g := range groups {
		if g.Name == "" || seenGroup[g.Name] {
			t.Errorf("group name %q is empty or duplicated", g.Name)
		}
		seenGroup[g.Name] = true
		for _, r := range g.Rules {
			total++
			id := g.Name + "/" + r.Alert
			if !strings.HasPrefix(r.Alert, "Keyorix") || seenAlert[r.Alert] {
				t.Errorf("%s: alert name must start with Keyorix and be unique", id)
			}
			seenAlert[r.Alert] = true
			if r.For != "" && !durationRe.MatchString(r.For) {
				t.Errorf("%s: for: %q is not a duration like 5m", id, r.For)
			}
			if !slices.Contains(severities, r.Labels["severity"]) {
				t.Errorf("%s: labels.severity %q not in %v", id, r.Labels["severity"], severities)
			}
			for _, k := range []string{"summary", "description", "runbook_url"} {
				if strings.TrimSpace(r.Annotations[k]) == "" {
					t.Errorf("%s: annotations.%s is missing", id, k)
				}
			}
			if want := runbookBase + strings.ToLower(r.Alert); r.Annotations["runbook_url"] != want {
				t.Errorf("%s: runbook_url = %q, want %q", id, r.Annotations["runbook_url"], want)
			}
			if !headings[r.Alert] {
				t.Errorf("%s: runbook.md has no `## %s` section", id, r.Alert)
			}
			for _, p := range checkExpr(inv, r.Expr) {
				t.Errorf("%s: %s\n  expr: %s", id, p, strings.TrimSpace(r.Expr))
			}
		}
	}
	if total < 20 {
		t.Errorf("only %d alerts; the coverage of item 2's metrics needs more", total)
	}
	for h := range headings {
		if !seenAlert[h] {
			t.Errorf("runbook.md documents %s but no such alert exists", h)
		}
	}
}

// operatorCritical are the metrics OBS-1 item 2 added or relied on; the shipped
// dashboard must chart each and the alert rules must cover the ones that signal an
// outage or an integrity problem.
var dashboardMustChart = []string{
	"keyorix_audit_write_duration_seconds", "keyorix_audit_write_failures_total",
	"keyorix_audit_group_commit_wait_seconds", "keyorix_db_pool_connections", "keyorix_db_pool_wait_seconds_total",
	"keyorix_audit_verify_last_success_timestamp_seconds", "keyorix_audit_verify_failure_recorded",
	"keyorix_encryption_state", "keyorix_tls_certificate_not_after_timestamp_seconds",
	"keyorix_rate_limit_rejections_total", "keyorix_single_writer_state", "keyorix_scheduler_runs_total",
	"keyorix_scheduler_last_success_timestamp_seconds", "keyorix_http_requests_total",
}

var alertsMustCover = []string{
	"keyorix_audit_write_failures_total", "keyorix_audit_verify_failure_recorded", "keyorix_audit_verify_last_success_timestamp_seconds",
	"keyorix_db_pool_connections", "keyorix_encryption_state", "keyorix_tls_certificate_not_after_timestamp_seconds",
	"keyorix_rate_limit_rejections_total", "keyorix_single_writer_state", "keyorix_scheduler_runs_total",
	"keyorix_encryption_operation_failures_total",
}

func TestAlertRules_CoverTheOperatorCriticalMetrics(t *testing.T) {
	var all strings.Builder
	for _, g := range loadRules(t) {
		for _, r := range g.Rules {
			all.WriteString(r.Expr + "\n")
		}
	}
	for _, m := range alertsMustCover {
		if !strings.Contains(all.String(), m) {
			t.Errorf("no alert uses %s", m)
		}
	}
}

type dashPanel struct {
	ID         int    `json:"id"`
	Type       string `json:"type"`
	Title      string `json:"title"`
	Datasource *struct {
		UID string `json:"uid"`
	} `json:"datasource"`
	GridPos struct{ H, W, X, Y int } `json:"gridPos"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
}

func TestGrafanaDashboard_StructureAndMetrics(t *testing.T) {
	inv := inventory(t)
	raw, err := os.ReadFile(filepath.Join(repoRoot(), obsDir, "grafana-dashboard.json")) //nolint:gosec // fixed repo path
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Title      string      `json:"title"`
		UID        string      `json:"uid"`
		Panels     []dashPanel `json:"panels"`
		Templating struct {
			List []struct {
				Name string `json:"name"`
			} `json:"list"`
		} `json:"templating"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("grafana-dashboard.json is not valid JSON: %v", err)
	}
	if d.Title == "" || d.UID == "" || len(d.Panels) == 0 {
		t.Fatalf("dashboard needs a title, uid and panels: %q %q %d", d.Title, d.UID, len(d.Panels))
	}
	vars := map[string]bool{}
	for _, v := range d.Templating.List {
		vars[v.Name] = true
	}
	for _, v := range []string{"DS_PROMETHEUS", "instance"} {
		if !vars[v] {
			t.Errorf("templating variable %q missing", v)
		}
	}

	ids := map[int]bool{}
	var charted strings.Builder
	var boxes []dashPanel
	for _, p := range d.Panels {
		if ids[p.ID] {
			t.Errorf("duplicate panel id %d", p.ID)
		}
		ids[p.ID] = true
		if p.GridPos.W <= 0 || p.GridPos.X < 0 || p.GridPos.X+p.GridPos.W > 24 {
			t.Errorf("panel %q gridPos out of the 24-column grid: %+v", p.Title, p.GridPos)
		}
		if p.Type == "row" {
			continue
		}
		boxes = append(boxes, p)
		if p.Datasource == nil || p.Datasource.UID != "${DS_PROMETHEUS}" {
			t.Errorf("panel %q must use the ${DS_PROMETHEUS} datasource", p.Title)
		}
		if len(p.Targets) == 0 {
			t.Errorf("panel %q has no queries", p.Title)
		}
		for _, tg := range p.Targets {
			charted.WriteString(tg.Expr + "\n")
			for _, pr := range checkExpr(inv, tg.Expr) {
				t.Errorf("panel %q: %s\n  expr: %s", p.Title, pr, tg.Expr)
			}
		}
	}
	for i, a := range boxes {
		for _, b := range boxes[i+1:] {
			if a.GridPos.X < b.GridPos.X+b.GridPos.W && b.GridPos.X < a.GridPos.X+a.GridPos.W &&
				a.GridPos.Y < b.GridPos.Y+b.GridPos.H && b.GridPos.Y < a.GridPos.Y+a.GridPos.H {
				t.Errorf("panels %q and %q overlap", a.Title, b.Title)
			}
		}
	}
	for _, m := range dashboardMustChart {
		if !strings.Contains(charted.String(), m) {
			t.Errorf("dashboard does not chart %s", m)
		}
	}
}

func TestAlertRules_PromtoolCheck(t *testing.T) {
	bin, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool not on PATH: only the structural checks ran (install promtool to also run `promtool check rules`)")
	}
	out, err := exec.Command(bin, "check", "rules", filepath.Join(repoRoot(), obsDir, "prometheus-alerts.yaml")).CombinedOutput() //nolint:gosec // fixed args
	if err != nil {
		t.Fatalf("promtool check rules failed: %v\n%s", err, out)
	}
}

// TestCheckExpr_Detector watches the expression checker fail: a guard that has only
// ever passed proves nothing.
func TestCheckExpr_Detector(t *testing.T) {
	inv := map[string]metricInfo{
		"keyorix_a_total":   {typ: "counter", labels: []string{"outcome"}},
		"keyorix_h_seconds": {typ: "histogram"},
	}
	good := []string{
		`sum(rate(keyorix_a_total{outcome="x"}[5m]))`,
		`histogram_quantile(0.99, sum by (le) (rate(keyorix_h_seconds_bucket[5m])))`,
		`sum by (outcome, instance) (increase(keyorix_a_total[1h])) > 0`,
	}
	for _, e := range good {
		if p := checkExpr(inv, e); len(p) != 0 {
			t.Errorf("good expression %q reported problems: %v", e, p)
		}
	}
	bad := map[string]string{
		`rate(keyorix_a_totl[5m])`:                     "unknown metric",
		`rate(keyorix_a_total{outcom="x"}[5m])`:        "has no label outcom",
		`sum by (nope) (rate(keyorix_a_total[5m]))`:    "grouping label nope",
		`sum(rate(keyorix_a_total[5m])`:                "unbalanced",
		`rate(keyorix_a_total{outcome="x}[5m])`:        "double quotes",
		`rate(keyorix_a_total_bucket[5m])`:             "unknown metric", // _bucket only valid on histograms
		`   `:                                          "empty",
		`sum(rate(keyorix_a_total{outcome=~"x"}[5m]))`: "", // regex matcher is fine
	}
	for e, want := range bad {
		p := strings.Join(checkExpr(inv, e), "; ")
		switch {
		case want == "" && p != "":
			t.Errorf("%q should be accepted, got: %s", e, p)
		case want != "" && !strings.Contains(p, want):
			t.Errorf("%q should report %q, got: %q", e, want, p)
		}
	}
}
