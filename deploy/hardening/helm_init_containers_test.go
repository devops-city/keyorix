package hardening

import (
	"testing"
)

// TestHelmChart_EveryPodSpecIncludingInitAndTestPodsIsHardened extends
// TestHelmChart_WorkloadsAreHardened (Deployment containers only) to the pod specs
// it does not look at: init containers and the `helm test` Pod. Every container in
// every rendered pod spec must drop ALL capabilities, forbid privilege escalation
// and have a read-only root filesystem, and the pod must run non-root under the
// RuntimeDefault seccomp profile.
//
// Not covered: the opt-in postgresql.migrateOwnership init container, which is
// root by design and pinned by TestHelmChart_PostgresOwnershipMigrationIsOptInAndNarrow;
// it is not rendered here.
func TestHelmChart_EveryPodSpecIncludingInitAndTestPodsIsHardened(t *testing.T) {
	forEachBaseline(t, func(t *testing.T) {
		docs := renderChart(t)
		var pods, initContainers int
		sawTestPod := false
		for _, d := range docs {
			var spec m
			switch d["kind"] {
			case "Deployment", "StatefulSet", "DaemonSet":
				spec = asMap(asMap(asMap(d["spec"])["template"])["spec"])
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
				t.Errorf("%s: pod runAsNonRoot must be true", name)
			}
			if uid, ok := pod["runAsUser"].(int); !ok || uid == 0 {
				t.Errorf("%s: pod runAsUser must be set and non-zero (got %v)", name, pod["runAsUser"])
			}
			if asMap(pod["seccompProfile"])["type"] != "RuntimeDefault" {
				t.Errorf("%s: pod seccompProfile.type must be RuntimeDefault", name)
			}
			if spec["automountServiceAccountToken"] != false {
				t.Errorf("%s: automountServiceAccountToken must be false", name)
			}
			for _, key := range []string{"initContainers", "containers"} {
				for _, c := range asList(spec[key]) {
					cm := asMap(c)
					cname, _ := cm["name"].(string)
					if key == "initContainers" {
						initContainers++
					}
					sc := asMap(cm["securityContext"])
					if sc["allowPrivilegeEscalation"] != false {
						t.Errorf("%s/%s: allowPrivilegeEscalation must be false", name, cname)
					}
					if sc["readOnlyRootFilesystem"] != true {
						t.Errorf("%s/%s: readOnlyRootFilesystem must be true", name, cname)
					}
					if sc["privileged"] == true {
						t.Errorf("%s/%s: privileged must not be set", name, cname)
					}
					if !hasString(asMap(sc["capabilities"])["drop"], "ALL") {
						t.Errorf("%s/%s: capabilities.drop must contain ALL", name, cname)
					}
				}
			}
		}
		if pods == 0 {
			t.Fatal("no pod spec rendered -- the guard would be vacuous")
		}
		if !sawTestPod {
			t.Error("no `helm test` Pod rendered -- the guard would be vacuous; update it if the test pod was removed")
		}
		if initContainers == 0 && baselineEnabled() {
			t.Error("secureBaseline renders no init container -- the init-container half of the guard is vacuous")
		}
	})
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
