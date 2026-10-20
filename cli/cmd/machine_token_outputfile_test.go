package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const rawMachineToken = "kx_machine_the_raw_secret"

// machineTokenFixture serves the three calls `machine token issue` makes and counts how
// many tokens it minted.
func machineTokenFixture(t *testing.T, tokenStatus int) (minted *atomic.Int32) {
	t.Helper()
	minted = new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"infra"}]}}`)
		case "/api/v1/projects/3/machine-identities":
			_, _ = fmt.Fprint(w, `{"data":{"machine_identities":[{"id":11,"name":"ci-runner","identity_type":"ci","state":"active"}]}}`)
		case "/api/v1/projects/3/machine-identities/11/tokens":
			minted.Add(1)
			w.WriteHeader(tokenStatus)
			if tokenStatus == http.StatusCreated {
				_, _ = fmt.Fprint(w, `{"data":{"token":"`+rawMachineToken+`","id":42,"prefix":"kx_machine_ab"}}`)
			} else {
				_, _ = fmt.Fprint(w, `{"message":"boom"}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	setMachineCreds(t, srv)
	machineTokenProjectName, machineTokenIssueName = "infra", "ci-token"
	t.Cleanup(func() { machineTokenProjectName, machineTokenIssueName, machineTokenIssueOutputFile = "", "", "" })
	return minted
}

func TestMachineTokenIssue_OutputFileKeepsTheTokenOffStdout(t *testing.T) {
	minted := machineTokenFixture(t, http.StatusCreated)
	path := filepath.Join(t.TempDir(), "ci.token")
	machineTokenIssueOutputFile = path

	var err error
	out, errOut := captureStdoutAndStderr(t, func() {
		err = runMachineTokenIssue(machineTokenIssueCmd, []string{"ci-runner"})
	})
	if err != nil {
		t.Fatalf("issue --output-file: %v", err)
	}
	if strings.Contains(out+errOut, rawMachineToken) {
		t.Fatalf("the token reached the terminal although --output-file was given:\n%s%s", out, errOut)
	}
	for _, want := range []string{path, "42", "kx_machine_ab"} {
		if !strings.Contains(out, want) {
			t.Errorf("output should say where the token went and its id/prefix; missing %q:\n%s", want, out)
		}
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != rawMachineToken+"\n" {
		t.Errorf("file content %q, want the token and one newline", got)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, want 0600", st.Mode().Perm())
	}
	if minted.Load() != 1 {
		t.Errorf("minted %d tokens, want 1", minted.Load())
	}
}

func TestMachineTokenIssue_OutputFileRefusesToOverwriteAndMintsNothing(t *testing.T) {
	minted := machineTokenFixture(t, http.StatusCreated)
	path := filepath.Join(t.TempDir(), "ci.token")
	if err := os.WriteFile(path, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	machineTokenIssueOutputFile = path

	err := runMachineTokenIssue(machineTokenIssueCmd, []string{"ci-runner"})
	if err == nil {
		t.Fatal("an existing file must be refused")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error should name the file: %v", err)
	}
	if minted.Load() != 0 {
		t.Errorf("a token was minted although it had nowhere to go (%d)", minted.Load())
	}
	if got, _ := os.ReadFile(path); string(got) != "precious\n" {
		t.Errorf("the existing file was modified: %q", got)
	}
}

func TestMachineTokenIssue_OutputFileIsRemovedWhenIssuingFails(t *testing.T) {
	machineTokenFixture(t, http.StatusInternalServerError)
	path := filepath.Join(t.TempDir(), "ci.token")
	machineTokenIssueOutputFile = path

	if err := runMachineTokenIssue(machineTokenIssueCmd, []string{"ci-runner"}); err == nil {
		t.Fatal("a server failure must be an error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the empty file created for the token must be removed when issuing fails (stat err: %v)", err)
	}
}
