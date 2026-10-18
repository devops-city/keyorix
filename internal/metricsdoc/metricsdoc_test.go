// Package metricsdoc holds the guard tests for docs/operations/metrics.md.
//
// The inventory is generated from the Go AST (see scan_test.go); the tests here
//   - fail when the committed doc differs from what the code defines (so adding,
//     renaming or relabelling a metric without regenerating the doc fails CI),
//   - fail when a metric label is not on the bounded-label allowlist or looks like
//     it could carry a secret name, path, user id or other unbounded value,
//   - cross-check the static scan against the live default registry so a metric
//     registered through an idiom the scanner cannot read is not silently missed.
//
// Regenerate the doc with:
//
//	go test ./internal/metricsdoc -run TestMetricsDocIsCurrent -update
//
// What this does NOT prove: that label VALUES are bounded. It bounds label NAMES
// and forces a written justification for each; a value bound depends on the call
// sites (e.g. `step` values are string literals at besteffort.Run call sites).
package metricsdoc

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	_ "github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/besteffort"
	_ "github.com/keyorixhq/keyorix/internal/core"
	_ "github.com/keyorixhq/keyorix/internal/encryption"
	_ "github.com/keyorixhq/keyorix/internal/notifychan"
	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
	_ "github.com/keyorixhq/keyorix/internal/ratelimitmetrics"
	_ "github.com/keyorixhq/keyorix/internal/solewriter"
	_ "github.com/keyorixhq/keyorix/internal/storage"
	_ "github.com/keyorixhq/keyorix/internal/storage/store"
	_ "github.com/keyorixhq/keyorix/internal/tlsmetrics"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/middleware"
)

var update = flag.Bool("update", false, "rewrite docs/operations/metrics.md from code")

const docRel = "docs/operations/metrics.md"

// boundedLabels is the complete set of label names any Keyorix metric may use,
// with the reason its values are a small closed set. Adding a label means adding
// a line here, which is the review point for cardinality.
var boundedLabels = map[string]string{
	"method":    "HTTP method collapsed to the 9 RFC verbs plus `other` (middleware.normalizeMethod)",
	"route":     "chi route pattern (`/api/v1/secrets/{id}`), never the raw path; unmatched requests share `unmatched`",
	"status":    "HTTP status code (a few dozen values) or gRPC `success`/`error`",
	"scheduler": "name of a built-in background job (fixed set registered in server startup)",
	"outcome":   "closed enum documented in the metric help (success/failure/skipped, delivered/failed/dropped, ...)",
	"budget":    "name of a built-in auth rate-limit budget (fixed set in internal/core)",
	"step":      "string literal at each besteffort.Run call site (fixed set in source)",
	"channel":   "notification channel type (webhook/email/slack/... fixed set)",
	"state":     "closed enum: source states (suspended/expired/expiring), pool connection state (in_use/idle), single_writer guard state (settling/authoritative/confirming), encryption state (disabled/uninitialized/ready)",
	"pool":      "fixed names of the database pools (request, scheduler_lock, named_lock; storage/db_pool_metrics.go)",
	"limiter":   "closed set of rate limiters (ratelimitmetrics.Limiter: principal, token_auth_failure, grpc_principal, grpc_token_auth_failure)",
	"check":     "closed set: tail, full (audit verification kinds)",
	"listener":  "closed set: http, grpc (tlsmetrics.HTTP / tlsmetrics.GRPC)",
	"op":        "closed set: encrypt, decrypt",
	"provider":  "KEK provider type normalised to the 9 known provider names plus `other` (encryption.providerLabel)",
	"reason":    "closed enum documented in the metric help (unreachable/timeout/server_error)",
}

// forbiddenLabelTokens: if any `_`-separated token of a label name is in this set the
// metric is rejected even when someone adds it to boundedLabels. These are the
// things that are unbounded or sensitive: secret names, filesystem/URL paths,
// user/principal identifiers, addresses and tokens.
var forbiddenLabelTokens = []string{
	"id", "ids", "uid", "uuid", "user", "users", "username", "email", "principal", "actor",
	"secret", "secrets", "key", "keys", "token", "session", "path", "file", "url", "uri",
	"host", "hostname", "ip", "addr", "address", "name", "project", "tenant", "namespace",
	"org", "account", "machine", "identity", "version",
}

const (
	epPublic    = "server `GET /metrics` (unauthenticated; keep inside your perimeter)"
	epScheduler = "server `GET /api/v1/admin/scheduler-metrics` (needs `system.write`; NOT on `/metrics`): metrics that would reveal security-job timing or integrity-check results to an anonymous reader"
	epOperator  = "operator manager metrics endpoint (controller-runtime registry)"
)

// endpointOverrides lists metrics that are not on the public /metrics endpoint.
var endpointOverrides = map[string]string{
	"keyorix_scheduler_last_run_timestamp_seconds":     epScheduler,
	"keyorix_scheduler_last_success_timestamp_seconds": epScheduler,

	// internal/protectedmetrics.Registry (TestProtectedMetricsAreDocumentedAndNotPublic).
	"keyorix_audit_verify_last_success_timestamp_seconds": epScheduler,
	"keyorix_audit_verify_failure_recorded":               epScheduler,
	"keyorix_audit_verify_state_rejected":                 epScheduler,
	"keyorix_audit_owed_pending":                          epScheduler,
}

func endpointOf(d metricDef) string {
	if e, ok := endpointOverrides[d.Name]; ok {
		return e
	}
	if strings.HasPrefix(d.File, "operator/") {
		return epOperator
	}
	return epPublic
}

func scanned(t *testing.T) []metricDef {
	t.Helper()
	defs, err := scanRepo(repoRoot())
	if err != nil {
		t.Fatalf("metric scan failed: %v", err)
	}
	return defs
}

func render(defs []metricDef) string {
	var b strings.Builder
	b.WriteString("# Prometheus metrics reference\n\n")
	b.WriteString("<!-- GENERATED FILE: do not edit by hand.\n")
	b.WriteString("     Regenerate: go test ./internal/metricsdoc -run TestMetricsDocIsCurrent -update\n")
	b.WriteString("     Source of truth: the promauto/prometheus definitions in the Go code. -->\n\n")
	b.WriteString("Every metric the server and the Kubernetes operator define, generated from the code. ")
	b.WriteString("A test fails if a metric is added, renamed or relabelled without regenerating this file, ")
	b.WriteString("and another fails if a label is not on the bounded-label list below.\n\n")
	b.WriteString("Go runtime (`go_*`) and process (`process_*`) metrics from the default collectors are also ")
	b.WriteString("served on `/metrics`; `go_info` and `process_start_time_seconds` are deliberately suppressed. ")
	b.WriteString("Series for a labelled metric appear only after its first observation, so a missing series ")
	b.WriteString("can mean \"never happened\"; use `absent()` only on metrics documented as pre-registered.\n\n")

	groups := []struct{ title, ep string }{
		{"Server: public `/metrics`", epPublic},
		{"Server: authenticated-only (`/api/v1/admin/scheduler-metrics`)", epScheduler},
		{"Operator", epOperator},
	}
	for _, g := range groups {
		var rows []metricDef
		for _, d := range defs {
			if endpointOf(d) == g.ep {
				rows = append(rows, d)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s\n\nServed at: %s\n\n", g.title, g.ep)
		b.WriteString("| Metric | Type | Labels | Meaning |\n|---|---|---|---|\n")
		for _, d := range rows {
			labels := "-"
			if len(d.Labels) > 0 {
				labels = "`" + strings.Join(d.Labels, "`, `") + "`"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", d.Name, d.Type, labels, strings.ReplaceAll(d.Help, "|", "\\|"))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Label cardinality\n\nEvery label used above and why its values are bounded. ")
	b.WriteString("Secret names, paths, user ids and other unbounded values must never be labels.\n\n")
	b.WriteString("| Label | Why bounded |\n|---|---|\n")
	used := map[string]bool{}
	for _, d := range defs {
		for _, l := range d.Labels {
			used[l] = true
		}
	}
	names := make([]string, 0, len(used))
	for l := range used {
		names = append(names, l)
	}
	slices.Sort(names)
	for _, l := range names {
		fmt.Fprintf(&b, "| `%s` | %s |\n", l, boundedLabels[l])
	}
	return b.String()
}

func TestMetricsDocIsCurrent(t *testing.T) {
	want := render(scanned(t))
	path := filepath.Join(repoRoot(), filepath.FromSlash(docRel))
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing (%v); generate it with: go test ./internal/metricsdoc -run TestMetricsDocIsCurrent -update", docRel, err)
	}
	if string(got) != want {
		t.Fatalf("%s is stale: a metric was added, renamed or relabelled. Regenerate with:\n  go test ./internal/metricsdoc -run TestMetricsDocIsCurrent -update", docRel)
	}
}

func TestMetricNamesAndLabelsAreBounded(t *testing.T) {
	defs := scanned(t)
	if len(defs) == 0 {
		t.Fatal("scan found no metrics; the scanner is broken")
	}
	seen := map[string]string{}
	for _, d := range defs {
		if prev, dup := seen[d.Name]; dup {
			t.Errorf("metric %s defined twice (%s and %s)", d.Name, prev, d.File)
		}
		seen[d.Name] = d.File
		if !strings.HasPrefix(d.Name, "keyorix_") {
			t.Errorf("%s (%s): metric names must start with keyorix_", d.Name, d.File)
		}
		if d.Help == "" {
			t.Errorf("%s (%s): empty Help", d.Name, d.File)
		}
		if d.Type == "const" {
			t.Errorf("%s (%s): NewDesc collector type not found; the Desc must be a struct field passed to prometheus.MustNewConstMetric with a Counter/Gauge/UntypedValue", d.Name, d.File)
		}
		for _, l := range d.Labels {
			if why := forbiddenLabel(l); why != "" {
				t.Errorf("%s (%s): label %q rejected: %s", d.Name, d.File, l, why)
			}
			if _, ok := boundedLabels[l]; !ok {
				t.Errorf("%s (%s): label %q is not in boundedLabels; add it with a justification of why its values are a small closed set", d.Name, d.File, l)
			}
		}
	}
	for k := range endpointOverrides {
		if _, ok := seen[k]; !ok {
			t.Errorf("endpointOverrides names unknown metric %s", k)
		}
	}
	for l := range boundedLabels {
		if why := forbiddenLabel(l); why != "" {
			t.Errorf("boundedLabels allows %q but it is forbidden: %s", l, why)
		}
	}
}

func forbiddenLabel(label string) string {
	for tok := range strings.SplitSeq(label, "_") {
		if slices.Contains(forbiddenLabelTokens, tok) {
			return fmt.Sprintf("token %q suggests an unbounded or sensitive value (secret name, path, user id, address, ...)", tok)
		}
	}
	return ""
}

// TestForbiddenLabelDetector watches the detector fail: without this the cardinality
// guard could be vacuous.
func TestForbiddenLabelDetector(t *testing.T) {
	for _, bad := range []string{"secret_name", "user_id", "path", "client_ip", "token", "project", "request_id"} {
		if forbiddenLabel(bad) == "" {
			t.Errorf("label %q should be rejected", bad)
		}
	}
	for l := range boundedLabels {
		if forbiddenLabel(l) != "" {
			t.Errorf("label %q should be accepted", l)
		}
	}
}

// TestScannerRejectsUnreadableDefinitions: a metric the scanner cannot read must
// fail the scan, not vanish from the inventory.
func TestScannerRejectsUnreadableDefinitions(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ok.go", `package x
import ("github.com/prometheus/client_golang/prometheus"; "github.com/prometheus/client_golang/prometheus/promauto")
var a = promauto.NewCounterVec(prometheus.CounterOpts{Name: "keyorix_a_total", Help: "h"}, []string{"outcome"})
`)
	defs, err := scanRepo(dir)
	if err != nil || len(defs) != 1 || defs[0].Name != "keyorix_a_total" || !slices.Equal(defs[0].Labels, []string{"outcome"}) {
		t.Fatalf("good definition not read: %v %v", defs, err)
	}
	for name, src := range map[string]string{
		"nonliteral.go": `package x
var n = "keyorix_b_total"
var b = promauto.NewCounter(prometheus.CounterOpts{Name: n, Help: "h"})`,
		"subsystem.go": `package x
var c = promauto.NewCounter(prometheus.CounterOpts{Subsystem: "s", Name: "c", Help: "h"})`,
		"optsvar.go": `package x
var o = prometheus.CounterOpts{Name: "keyorix_d", Help: "h"}
var d = promauto.NewCounter(o)`,
		"labelsvar.go": `package x
var l = []string{"a"}
var e = promauto.NewCounterVec(prometheus.CounterOpts{Name: "keyorix_e", Help: "h"}, l)`,
	} {
		d2 := t.TempDir()
		if err := os.WriteFile(filepath.Join(d2, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := scanRepo(d2); err == nil {
			t.Errorf("%s: unreadable metric definition was silently accepted", name)
		}
	}
}

// TestStaticScanMatchesLiveRegistry: every keyorix_* family on the default registry
// must be in the static inventory, with the same type, so a registration idiom the
// scanner cannot see is caught.
func TestStaticScanMatchesLiveRegistry(t *testing.T) {
	// Touch the packages so their init-time registrations are linked in, and
	// register the lazily-registered gRPC collector.
	_ = besteffort.Run
	interceptors.RegisterPrometheusMetrics()
	middleware.RegisterScheduler("metricsdoc_probe")

	static := map[string]metricDef{}
	for _, d := range scanned(t) {
		static[d.Name] = d
	}
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	for _, mf := range fams {
		if !strings.HasPrefix(mf.GetName(), "keyorix_") {
			continue
		}
		live++
		d, ok := static[mf.GetName()]
		if !ok {
			t.Errorf("live metric %s is not found by the static scan (unsupported registration idiom?)", mf.GetName())
			continue
		}
		if got := strings.ToLower(mf.GetType().String()); got != d.Type {
			t.Errorf("%s: live type %s != documented type %s", mf.GetName(), got, d.Type)
		}
	}
	if live == 0 {
		t.Fatal("no keyorix_* metric visible on the live registry; the cross-check is vacuous")
	}
}

// TestProtectedMetricsAreDocumentedAndNotPublic: whatever is registered on the
// protected registry must be documented as authenticated-only, and must not also be
// reachable on the public /metrics registry. Conversely, nothing the doc calls
// authenticated-only may be on the default registry.
func TestProtectedMetricsAreDocumentedAndNotPublic(t *testing.T) {
	protected, err := protectedmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) == 0 {
		t.Fatal("protected registry is empty; the check is vacuous")
	}
	public, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	onPublic := map[string]bool{}
	for _, mf := range public {
		onPublic[mf.GetName()] = true
	}
	for _, mf := range protected {
		if endpointOverrides[mf.GetName()] != epScheduler {
			t.Errorf("%s is on the protected registry but not documented as authenticated-only in endpointOverrides", mf.GetName())
		}
		if onPublic[mf.GetName()] {
			t.Errorf("%s is on BOTH the protected and the public registry", mf.GetName())
		}
	}
	for name, ep := range endpointOverrides {
		if ep == epScheduler && onPublic[name] {
			t.Errorf("%s is documented as authenticated-only but is served on the public /metrics registry", name)
		}
	}
}
