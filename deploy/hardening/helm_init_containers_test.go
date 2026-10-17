package hardening

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// allowedAddedCapabilities is every capability a chart container may ADD on top
// of drop: [ALL]: exactly what the Pod Security "restricted" profile allows.
// NET_BIND_SERVICE is used by the web container (non-root nginx on port 80,
// templates/web-deployment.yaml).
var allowedAddedCapabilities = []string{"NET_BIND_SERVICE"}

// rootByDesign names the one container the chart may render that runs as root
// and adds capabilities: the opt-in postgresql.migrateOwnership init container
// (off by default; values.yaml says why it exists, and
// TestHelmChart_PostgresOwnershipMigrationIsOptInAndNarrow pins its exact shape:
// CHOWN + DAC_READ_SEARCH only, data volume only). It is exempt only from the
// root and capabilities.add checks, and only in the opt-in render below.
const rootByDesign = "kx-keyorix-postgresql/fix-data-ownership"

// TestHelmChart_EveryPodSpecIncludingInitAndTestPodsIsHardened extends
// TestHelmChart_WorkloadsAreHardened (Deployment containers only) to the pod specs
// it does not look at: init containers and the `helm test` Pod. Every container in
// every rendered pod spec must drop ALL capabilities and add none
// (allowedAddedCapabilities), forbid privilege escalation, have a read-only root
// filesystem and not run as root at container level (a container's
// securityContext.runAsUser / runAsNonRoot override the pod's); the pod must run
// non-root under the RuntimeDefault seccomp profile.
//
// Calibration (#3360, REVIEW-1): the guard is also run on the
// postgresql.migrateOwnership=true render, where it must report the root init
// container, and nothing else. Before #3360 the guard read runAsNonRoot/runAsUser
// only at pod level and never read capabilities.add, so that render passed.
func TestHelmChart_EveryPodSpecIncludingInitAndTestPodsIsHardened(t *testing.T) {
	forEachBaseline(t, func(t *testing.T) {
		got := podHardeningViolations(t, renderChart(t), true)
		for _, v := range got {
			t.Error(v)
		}

		// Calibration: the opt-in root container must be caught, by both the
		// container-level root check and the capabilities.add check.
		got = podHardeningViolations(t, renderChartWith(t, "--set", "postgresql.migrateOwnership=true"), false)
		var flagged []string
		for _, v := range got {
			if !strings.HasPrefix(v, rootByDesign+":") {
				t.Errorf("migrateOwnership=true render: unexpected violation outside %s: %s", rootByDesign, v)
				continue
			}
			flagged = append(flagged, v)
		}
		for _, want := range []string{"runAsUser 0", "runAsNonRoot false", "capabilities.add"} {
			if !slices.ContainsFunc(flagged, func(v string) bool { return strings.Contains(v, want) }) {
				t.Errorf("calibration: the guard did not flag %s for %q (flagged: %v) -- it would pass a root container", rootByDesign, want, flagged)
			}
		}
	})
}

// podHardeningViolations returns one line per hardening violation in docs, as
// "<pod>/<container>: <what>" (or "<pod>: <what>" for pod-level ones).
// requireInit additionally fails the guard as vacuous when the secure baseline
// renders no init container.
func podHardeningViolations(t *testing.T, docs []m, requireInit bool) []string {
	t.Helper()
	var out []string
	var pods, initContainers, containers int
	sawTestPod := false
	for _, d := range docs {
		var spec m
		switch d["kind"] {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			if d["kind"] == "CronJob" {
				spec = asMap(asMap(asMap(asMap(asMap(d["spec"])["jobTemplate"])["spec"])["template"])["spec"])
			} else {
				spec = asMap(asMap(asMap(d["spec"])["template"])["spec"])
			}
		case "Pod":
			spec = asMap(d["spec"])
			sawTestPod = true
		default:
			continue
		}
		name, _ := asMap(d["metadata"])["name"].(string)
		pods++
		pod := asMap(spec["securityContext"])
		if pod["runAsNonRoot"] != true {
			out = append(out, fmt.Sprintf("%s: pod runAsNonRoot must be true", name))
		}
		if uid, ok := pod["runAsUser"].(int); !ok || uid == 0 {
			out = append(out, fmt.Sprintf("%s: pod runAsUser must be set and non-zero (got %v)", name, pod["runAsUser"]))
		}
		if asMap(pod["seccompProfile"])["type"] != "RuntimeDefault" {
			out = append(out, fmt.Sprintf("%s: pod seccompProfile.type must be RuntimeDefault", name))
		}
		if spec["automountServiceAccountToken"] != false {
			out = append(out, fmt.Sprintf("%s: automountServiceAccountToken must be false", name))
		}
		for _, key := range []string{"initContainers", "containers"} {
			for _, c := range asList(spec[key]) {
				cm := asMap(c)
				cname, _ := cm["name"].(string)
				id := name + "/" + cname
				containers++
				if key == "initContainers" {
					initContainers++
				}
				sc := asMap(cm["securityContext"])
				if sc["allowPrivilegeEscalation"] != false {
					out = append(out, id+": allowPrivilegeEscalation must be false")
				}
				if sc["readOnlyRootFilesystem"] != true {
					out = append(out, id+": readOnlyRootFilesystem must be true")
				}
				if sc["privileged"] == true {
					out = append(out, id+": privileged must not be set")
				}
				caps := asMap(sc["capabilities"])
				if !hasString(caps["drop"], "ALL") {
					out = append(out, id+": capabilities.drop must contain ALL")
				}
				for _, a := range asList(caps["add"]) {
					if s, _ := a.(string); !slices.Contains(allowedAddedCapabilities, s) {
						out = append(out, fmt.Sprintf("%s: capabilities.add %v is not allowed (allowed: %v)", id, a, allowedAddedCapabilities))
					}
				}
				// Container-level settings override the pod's: a container may
				// tighten them, never run as root.
				if uid, ok := sc["runAsUser"].(int); ok && uid == 0 {
					out = append(out, id+": container runAsUser 0 overrides the pod's non-root user")
				}
				if v, ok := sc["runAsNonRoot"]; ok && v != true {
					out = append(out, fmt.Sprintf("%s: container runAsNonRoot %v overrides the pod's runAsNonRoot", id, v))
				}
			}
		}
	}
	if pods == 0 || containers == 0 {
		t.Fatal("no pod spec or container rendered -- the guard would be vacuous")
	}
	if !sawTestPod {
		out = append(out, "no `helm test` Pod rendered -- the guard would be vacuous; update it if the test pod was removed")
	}
	if requireInit && initContainers == 0 && baselineEnabled() {
		out = append(out, "secureBaseline renders no init container -- the init-container half of the guard is vacuous")
	}
	return out
}

// baselineEnabled reports whether the current forEachBaseline subtest renders with
// the secure baseline (the chart default, so empty args count as enabled).
func baselineEnabled() bool {
	for i, a := range baselineArgs {
		if a == "secureBaseline.enabled=false" && i > 0 {
			return false
		}
	}
	return true
}
