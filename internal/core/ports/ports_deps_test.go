package ports

import (
	"os/exec"
	"strings"
	"testing"
)

// forbiddenDepPrefixes are packages that would defeat the entire point of
// this package if internal/core/ports ever imported them: an integration
// package, or the cloud SDKs behind one. See the package doc comment in
// ports.go.
var forbiddenDepPrefixes = []string{
	"github.com/keyorixhq/keyorix/internal/connect",
	"github.com/keyorixhq/keyorix/internal/rotation",
	"github.com/keyorixhq/keyorix/internal/dynamic",
	"github.com/keyorixhq/keyorix/internal/encryption",
	"github.com/keyorixhq/keyorix/internal/notary",
	"github.com/keyorixhq/keyorix/internal/saml",
	// internal/delivery and internal/license (ADR-109 "last decoupling", B5):
	// ports_delivery.go/ports_license.go declare their own canonical types
	// (or alias straight to pkg/licenseverify, license's own upstream), so
	// this package has no legitimate reason to import either.
	"github.com/keyorixhq/keyorix/internal/delivery",
	"github.com/keyorixhq/keyorix/internal/license",
	"github.com/aws/aws-sdk-go-v2/service/",
	"github.com/Azure/azure-sdk-for-go/sdk/security/",
	"cloud.google.com/go/",
	"github.com/hashicorp/vault/api",
}

// TestPortsStaysFree fails if internal/core/ports picks up a dependency on
// any integration package or its SDK. It runs `go list -deps` (production
// deps only, test files excluded) and skips when the go tool isn't
// available.
func TestPortsStaysFree(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	out, err := exec.Command("go", "list", "-deps", "github.com/keyorixhq/keyorix/internal/core/ports").Output()
	if err != nil {
		t.Fatalf("go list -deps internal/core/ports: %v", err)
	}
	for dep := range strings.FieldsSeq(string(out)) {
		for _, bad := range forbiddenDepPrefixes {
			if dep == bad || strings.HasPrefix(dep, bad+"/") || (strings.HasSuffix(bad, "/") && strings.HasPrefix(dep, bad)) {
				t.Errorf("internal/core/ports depends on %s: this package must stay free of every integration it abstracts (see ports.go)", dep)
			}
		}
	}
}
