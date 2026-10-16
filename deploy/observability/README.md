# Keyorix observability kit

| File | What it is |
|---|---|
| [prometheus-alerts.yaml](prometheus-alerts.yaml) | Alert rules (`groups:`) across availability, audit, database, security, encryption, HA and background jobs |
| [runbook.md](runbook.md) | One section per alert: what it means, what to check, what to do. Every alert's `runbook_url` points here |
| [grafana-dashboard.json](grafana-dashboard.json) | Grafana dashboard (import it; it asks for a Prometheus data source) |

The metrics themselves are documented in [docs/operations/metrics.md](../../docs/operations/metrics.md),
generated from the code.

## Scraping

Two scrape jobs. Most alerts only need the first.

```yaml
scrape_configs:
  - job_name: keyorix
    metrics_path: /metrics
    # If server.http.metrics_token is set:
    # authorization: { type: Bearer, credentials_file: /etc/prometheus/keyorix-metrics-token }
    static_configs: [{ targets: ["keyorix.internal:8080"] }]

  # Audit-verification health and scheduler last-success times. These are NOT served on
  # /metrics: they would tell an anonymous reader when an integrity check last ran and
  # whether it found a break. Needs a token whose holder has system.write.
  - job_name: keyorix-protected
    metrics_path: /api/v1/admin/scheduler-metrics
    authorization: { type: Bearer, credentials_file: /etc/prometheus/keyorix-admin-token }
    static_configs: [{ targets: ["keyorix.internal:8080"] }]
```

The four audit-verification alerts (`KeyorixAuditChainBreakRecorded`, `KeyorixAuditVerifyStateRejected`,
`KeyorixAuditVerifyStale`, `KeyorixAuditVerifyNeverPassed`) and the dashboard panels that say "needs the
keyorix-protected scrape job" depend on the second job. Without it
`KeyorixAuditVerifyNeverPassed` fires after two days, which is the intended signal.

`/metrics` is unauthenticated by default and must stay inside your network perimeter.

## Using the rules

Prometheus: add the file under `rule_files:`. Prometheus Operator: put the `groups:` list under
`spec.groups` of a `PrometheusRule`. Edit the `up{job="keyorix"}` selector if your job is named
differently. Thresholds are starting points, not tuned values.

## Validating

`internal/metricsdoc` (run by `go test ./internal/metricsdoc`) checks the YAML structure and that every
`keyorix_*` metric and label used in the rules and the dashboard exists in the code, that each alert has a
severity, summary, description and a `runbook_url` that matches a section in `runbook.md`, and that the
dashboard's panels do not overlap and chart the operator-critical metrics. If `promtool` is on `PATH` the same
test also runs `promtool check rules`; run it yourself with:

```
promtool check rules deploy/observability/prometheus-alerts.yaml
```

Not checked by tests: that the PromQL evaluates the way the description says.
