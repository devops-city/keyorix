package deploy

import (
	"testing"
)

// serverProbe returns the named probe of the server container in the rendered chart.
func serverProbe(t *testing.T, docs []map[string]any, probe string) map[string]any {
	t.Helper()
	for _, d := range docs {
		meta, _ := d["metadata"].(map[string]any)
		labels, _ := meta["labels"].(map[string]any)
		if d["kind"] != "Deployment" || labels["app.kubernetes.io/component"] != "server" {
			continue
		}
		spec, _ := d["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		podSpec, _ := tmpl["spec"].(map[string]any)
		containers, _ := podSpec["containers"].([]any)
		for _, c := range containers {
			cm, _ := c.(map[string]any)
			if cm["name"] != "server" {
				continue
			}
			p, _ := cm[probe].(map[string]any)
			if p == nil {
				t.Fatalf("server container has no %s", probe)
			}
			return p
		}
	}
	t.Fatal("no server Deployment/container rendered")
	return nil
}

// The server container carries startup, liveness and readiness probes on the
// endpoints the server really serves (/health never touches the database, /readyz
// does -- server/http/handlers/readiness.go), over HTTPS exactly when the secure
// baseline makes the server TLS-only, with explicit timings, and the liveness
// probe does not use an initialDelay (the startup probe gates it).
//
// Not covered: that the real server answers these paths (the kind install in the
// PR does that) or that the timings suit a given database size.
func TestHelmServerProbes(t *testing.T) {
	requireHelm(t)
	chart := chartWithValues(t, "")

	for _, tc := range []struct {
		name   string
		sets   []string
		scheme string
	}{
		{"secure baseline (default)", nil, "HTTPS"},
		{"baseline off", []string{"secureBaseline.enabled=false"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs := helmTemplateDocs(t, chart, tc.sets...)
			for probe, want := range map[string]struct {
				path    string
				period  int
				timeout int
				fails   int
			}{
				"startupProbe":   {"/health", 5, 3, 36},
				"livenessProbe":  {"/health", 20, 5, 3},
				"readinessProbe": {"/readyz", 10, 5, 3},
			} {
				p := serverProbe(t, docs, probe)
				get, _ := p["httpGet"].(map[string]any)
				if get["path"] != want.path {
					t.Errorf("%s path = %v, want %s", probe, get["path"], want.path)
				}
				gotScheme, _ := get["scheme"].(string)
				if gotScheme != tc.scheme {
					t.Errorf("%s scheme = %q, want %q", probe, gotScheme, tc.scheme)
				}
				if p["periodSeconds"] != want.period || p["timeoutSeconds"] != want.timeout || p["failureThreshold"] != want.fails {
					t.Errorf("%s timings period/timeout/failures = %v/%v/%v, want %d/%d/%d", probe,
						p["periodSeconds"], p["timeoutSeconds"], p["failureThreshold"], want.period, want.timeout, want.fails)
				}
				if _, has := p["initialDelaySeconds"]; has {
					t.Errorf("%s has initialDelaySeconds: the startup probe gates it, a fixed delay only slows crash detection", probe)
				}
			}
		})
	}
}

// A user override of one field keeps the defaults of the other fields of that
// probe and of the other probes: a partial server.probes must never blank a timing.
func TestHelmServerProbes_PartialOverrideKeepsOtherDefaults(t *testing.T) {
	requireHelm(t)
	chart := chartWithValues(t, "")
	docs := helmTemplateDocs(t, chart, "server.probes.startup.failureThreshold=120", "server.probes.readiness.periodSeconds=3")

	start := serverProbe(t, docs, "startupProbe")
	if start["failureThreshold"] != 120 || start["periodSeconds"] != 5 || start["timeoutSeconds"] != 3 {
		t.Errorf("startupProbe = %v, want failureThreshold 120 with default period 5 and timeout 3", start)
	}
	ready := serverProbe(t, docs, "readinessProbe")
	if ready["periodSeconds"] != 3 || ready["timeoutSeconds"] != 5 || ready["failureThreshold"] != 3 {
		t.Errorf("readinessProbe = %v, want period 3 with default timeout 5 and failureThreshold 3", ready)
	}
	live := serverProbe(t, docs, "livenessProbe")
	if live["periodSeconds"] != 20 {
		t.Errorf("livenessProbe period = %v, want the untouched default 20", live["periodSeconds"])
	}
}
