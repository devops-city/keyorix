//go:build e2e

package e2e

import "strings"

// groupCLISmoke exercises the thin `keyorix` CLI binary against the same
// running server the rest of this driver's HTTP client talks to -- the "and
// the thin CLI where a command exists" half of I2's brief (mirroring
// scripts/smoke.sh's own CLI-driven flow, but folded into this Go driver
// instead of a separate shell script). A separate CLI login (its own
// isolated ~/.keyorix session, via ctx.cliEnv's isolated HOME) so it doesn't
// interfere with ctx.c's own bearer-token session.
func groupCLISmoke(ctx *smokeCtx) {
	ctx.runCLIWithEnv([]string{"KEYORIX_PASSWORD=" + ctx.adminPassword},
		"login", "--server", ctx.c.baseURL, "--username", ctx.adminUsername)

	projectList := ctx.runCLI("project", "list")
	if !strings.Contains(projectList, "e2e-smoke-project") {
		ctx.t.Fatalf("keyorix project list did not show the smoke project:\n%s", projectList)
	}

	secretList := ctx.runCLI("secret", "list", "--project", "e2e-smoke-project")
	if !strings.Contains(secretList, "e2e-smoke-secret") {
		ctx.t.Fatalf("keyorix secret list did not show the smoke secret:\n%s", secretList)
	}

	getOut := ctx.runCLI("secret", "get", "--ref", "e2e-smoke-project/e2e-main/e2e-smoke-secret", "--show-value")
	if !strings.Contains(getOut, ctx.secretValue) {
		ctx.t.Fatalf("keyorix secret get did not return the stored value:\n%s", getOut)
	}
}
