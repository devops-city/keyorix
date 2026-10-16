package deploy

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// podContainers maps "<workload>/<container>" to the container spec of every
// Deployment and Pod (init containers included) in the rendered chart.
func podContainers(docs []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, d := range docs {
		var spec map[string]any
		switch d["kind"] {
		case "Deployment":
			s, _ := d["spec"].(map[string]any)
			tmpl, _ := s["template"].(map[string]any)
			spec, _ = tmpl["spec"].(map[string]any)
		case "Pod":
			spec, _ = d["spec"].(map[string]any)
		default:
			continue
		}
		meta, _ := d["metadata"].(map[string]any)
		for _, key := range []string{"initContainers", "containers"} {
			list, _ := spec[key].([]any)
			for _, c := range list {
				cm, _ := c.(map[string]any)
				out[fmt.Sprintf("%v/%v", meta["name"], cm["name"])] = cm
			}
		}
	}
	return out
}

func resourceQty(c map[string]any, kind, res string) string {
	r, _ := c["resources"].(map[string]any)
	k, _ := r[kind].(map[string]any)
	return fmt.Sprint(k[res])
}

// Every container the chart renders (init containers and the helm test pod
// included) declares cpu and memory requests and a memory limit, so no pod is
// BestEffort and none can take a node's memory unbounded. The server container
// is Guaranteed QoS (requests == limits for cpu and memory): that is the only
// control keeping decrypted secret memory out of swap (ADR-100).
//
// Not covered: that the sizes suit a workload (they are starting points; see
// values-production.yaml for sizing guidance).
func TestHelmResources_EveryContainerIsBounded(t *testing.T) {
	requireHelm(t)
	docs := helmTemplateDocs(t, chartWithValues(t, ""))
	cs := podContainers(docs)
	if len(cs) < 5 {
		t.Fatalf("only %d containers rendered (%v) -- the guard would be vacuous", len(cs), cs)
	}
	for name, c := range cs {
		for _, kr := range [][2]string{{"requests", "cpu"}, {"requests", "memory"}, {"limits", "memory"}} {
			if v := resourceQty(c, kr[0], kr[1]); v == "<nil>" {
				t.Errorf("%s: resources.%s.%s is not set", name, kr[0], kr[1])
			}
		}
	}
	var server map[string]any
	for name, c := range cs {
		if strings.HasSuffix(name, "-server/server") {
			server = c
		}
	}
	if server == nil {
		t.Fatal("server container not found")
	}
	for _, res := range []string{"cpu", "memory"} {
		if rq, lim := resourceQty(server, "requests", res), resourceQty(server, "limits", res); rq != lim {
			t.Errorf("server %s requests (%s) != limits (%s): not Guaranteed QoS", res, rq, lim)
		}
	}
}

// With server.resources / web.resources removed (`null`, or a values file reused
// from a release that never had them) the templates fall back to built-in
// defaults. Those must equal values.yaml's, GOMEMLIMIT included, or the same chart
// would size a pod differently depending on how it was installed.
func TestHelmResources_TemplateFallbackEqualsValuesDefaults(t *testing.T) {
	requireHelm(t)
	chart := chartWithValues(t, "")
	want := podContainers(helmTemplateDocs(t, chart))
	got := podContainers(helmTemplateDocs(t, chart, "server.resources=null", "web.resources=null"))
	for name, w := range want {
		g := got[name]
		if g == nil {
			t.Errorf("%s missing from the fallback render", name)
			continue
		}
		if !reflect.DeepEqual(w["resources"], g["resources"]) {
			t.Errorf("%s: fallback resources %v != values.yaml defaults %v", name, g["resources"], w["resources"])
		}
		if !reflect.DeepEqual(w["env"], g["env"]) {
			t.Errorf("%s: fallback env (GOMEMLIMIT) %v != values.yaml defaults %v", name, g["env"], w["env"])
		}
	}
}

// GOMEMLIMIT is a soft heap limit and must leave headroom under the container's
// memory limit (stacks, runtime overhead, non-heap memory), for the default and for
// a resized limit, whatever percent is chosen in 1..99.
func TestHelmResources_GoMemLimitStaysBelowTheContainerLimit(t *testing.T) {
	requireHelm(t)
	chart := chartWithValues(t, "")
	for _, tc := range []struct {
		sets     []string
		limitKiB int
	}{
		{nil, 512 * 1024},
		{[]string{"server.resources.limits.memory=2Gi", "server.resources.requests.memory=2Gi"}, 2 * 1024 * 1024},
		{[]string{"server.goMemLimitPercent=99"}, 512 * 1024},
		{[]string{"server.goMemLimitPercent=1"}, 512 * 1024},
	} {
		c := podContainers(helmTemplateDocs(t, chart, tc.sets...))
		var env []any
		for name, cm := range c {
			if strings.HasSuffix(name, "-server/server") {
				env, _ = cm["env"].([]any)
			}
		}
		found := false
		for _, e := range env {
			em, _ := e.(map[string]any)
			if em["name"] != "GOMEMLIMIT" {
				continue
			}
			found = true
			s, _ := em["value"].(string)
			kib, err := strconv.Atoi(strings.TrimSuffix(s, "KiB"))
			if err != nil {
				t.Fatalf("%v: GOMEMLIMIT %q is not a KiB value", tc.sets, s)
			}
			if kib <= 0 || kib >= tc.limitKiB {
				t.Errorf("%v: GOMEMLIMIT %d KiB must be in (0, %d KiB)", tc.sets, kib, tc.limitKiB)
			}
		}
		if !found {
			t.Errorf("%v: GOMEMLIMIT not set", tc.sets)
		}
	}
}
