package deploy

import (
	"strings"
	"testing"
)

// The Helm install recipes in the docs build the chart's auth.existingSecret from files in
// keyorix-secrets/. With KEYORIX_ADMIN_PASSWORD in that Secret the server's entrypoint refuses
// to start unless KEYORIX_BOOTSTRAP_TOKEN is there too ("KEYORIX_ADMIN_PASSWORD is set but
// KEYORIX_BOOTSTRAP_TOKEN ... is not"), so a recipe without the token file crash-loops the
// server pod at first boot. Found by DEMO-WALK-4 on kind: the chart README's quick start did
// exactly that, and docs/operator/j8-kubernetes.md said the token "is optional in the Secret".
//
// secretRecipeProblems returns what is wrong with one document's recipe; empty means fine. A
// document with no admin-password file in a recipe is not constrained.
func secretRecipeProblems(doc string) []string {
	var problems []string
	if strings.Contains(doc, "keyorix-secrets/KEYORIX_ADMIN_PASSWORD") &&
		!strings.Contains(doc, "keyorix-secrets/KEYORIX_BOOTSTRAP_TOKEN") {
		problems = append(problems, "writes keyorix-secrets/KEYORIX_ADMIN_PASSWORD but no keyorix-secrets/KEYORIX_BOOTSTRAP_TOKEN")
	}
	if strings.Contains(doc, "KEYORIX_BOOTSTRAP_TOKEN` is optional in the Secret") {
		problems = append(problems, "says KEYORIX_BOOTSTRAP_TOKEN is optional in the Secret (it is required with an admin password)")
	}
	return problems
}

func TestHelmSecretRecipesCarryTheBootstrapToken(t *testing.T) {
	for _, name := range []string{
		"deploy/helm/keyorix/README.md",
		"docs/operator/j8-kubernetes.md",
	} {
		doc := readRepoFile(t, name)
		if !strings.Contains(doc, "keyorix-secrets/KEYORIX_ADMIN_PASSWORD") {
			t.Errorf("%s no longer carries the existingSecret recipe this guard watches; update the guard, do not delete it", name)
			continue
		}
		for _, p := range secretRecipeProblems(doc) {
			t.Errorf("%s: %s: the server pod would crash-loop at first boot", name, p)
		}
	}
}

// Both directions of the check itself: the broken shape is caught, the fixed shape passes.
func TestSecretRecipeProblemsBothDirections(t *testing.T) {
	broken := "printf '%s' \"$v\" > keyorix-secrets/KEYORIX_ADMIN_PASSWORD\nkubectl create secret generic keyorix-auth --from-file=keyorix-secrets/\n"
	if len(secretRecipeProblems(broken)) == 0 {
		t.Error("a recipe with an admin password and no bootstrap token must be reported")
	}
	if len(secretRecipeProblems("`KEYORIX_BOOTSTRAP_TOKEN` is optional in the Secret.")) == 0 {
		t.Error("the 'optional' sentence must be reported")
	}
	fixed := broken + "tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 > keyorix-secrets/KEYORIX_BOOTSTRAP_TOKEN\n"
	if p := secretRecipeProblems(fixed); len(p) != 0 {
		t.Errorf("a recipe with both files must pass, got %v", p)
	}
}
