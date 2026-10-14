package i18n

import (
	"os/exec"
	"strings"
	"testing"
)

// forbiddenDepPrefixes are packages that must never be in the production
// dependency tree of internal/i18n or internal/config. Almost every package
// imports i18n to translate errors, so anything heavy here is linked into all
// of them (and into every fuzz binary built from them). Before 2026-09-23
// config imported internal/connect for one string list, which dragged the
// AWS, Azure and GCP SDKs everywhere (config's coverage map 123,619 bytes).
var forbiddenDepPrefixes = []string{
	"github.com/keyorixhq/keyorix/internal/connect", // exact package checked below; connecttypes is allowed
	"github.com/keyorixhq/keyorix/internal/core",    // exact package checked below; core/ports is allowed
	"github.com/keyorixhq/keyorix/internal/storage",
	"github.com/aws/aws-sdk-go-v2/service/",
	"github.com/Azure/azure-sdk-for-go/sdk/security/",
	"cloud.google.com/go/",
	"github.com/hashicorp/vault/api",
}

// TestI18nAndConfigStayLight fails if internal/i18n or internal/config picks
// up a heavy dependency again. It runs `go list -deps` (production deps only,
// test files excluded) and skips when the go tool isn't available.
func TestI18nAndConfigStayLight(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	for _, pkg := range []string{
		"github.com/keyorixhq/keyorix/internal/i18n",
		"github.com/keyorixhq/keyorix/internal/config",
	} {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		for dep := range strings.FieldsSeq(string(out)) {
			for _, bad := range forbiddenDepPrefixes {
				// connecttypes and core/ports are each independently guarded
				// to stay stdlib-only/integration-free (see
				// internal/core/ports/ports_deps_test.go's own
				// TestPortsStaysFree for the latter), so neither can be the
				// source of a heavy transitive dependency here -- exempting
				// them doesn't weaken what this test actually checks for.
				if dep == "github.com/keyorixhq/keyorix/internal/connect/connecttypes" ||
					dep == "github.com/keyorixhq/keyorix/internal/core/ports" {
					continue
				}
				if dep == bad || strings.HasPrefix(dep, bad+"/") || (strings.HasSuffix(bad, "/") && strings.HasPrefix(dep, bad)) {
					t.Errorf("%s depends on %s: keep i18n and config light (see forbiddenDepPrefixes)", pkg, dep)
				}
			}
		}
	}
}
