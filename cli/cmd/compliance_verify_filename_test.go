package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestComplianceVerify_SendsTheSignatureBoundFilename: the server HMACs filename+data
// (AUD-009) and reads the filename from the verify request's "filename" field. The typed
// generated request body has no such field, so `keyorix compliance verify` used to send none
// and rejected every genuine, untouched pack as "presented under the wrong filename". The
// canonical filename travels in the first line of the detached .sig; it must reach the server.
func TestComplianceVerify_SendsTheSignatureBoundFilename(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/compliance/evidence/verify" && r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &got)
			_, _ = fmt.Fprint(w, `{"data":{"valid":true,"key_version":"k1"}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setRequestCreds(t, srv)

	dir := t.TempDir()
	pack := filepath.Join(dir, "my-chosen-name.json") // operator-chosen, differs from the canonical name
	if err := os.WriteFile(pack, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const canonical = "keyorix-evidence-20261016T160000Z.json"
	if err := os.WriteFile(pack+".sig", []byte(canonical+"\nk1:deadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	complianceVerifyFile, complianceVerifySig = pack, ""
	t.Cleanup(func() { complianceVerifyFile, complianceVerifySig = "", "" })
	if err := complianceVerifyCmd.RunE(complianceVerifyCmd, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got["filename"] != canonical {
		t.Fatalf("verify request filename = %q, want the canonical %q from the .sig (the server binds the signature to it)", got["filename"], canonical)
	}
	if got["signature"] != "k1:deadbeef" || got["data_b64"] == "" {
		t.Fatalf("verify request = %v, want signature and data_b64 set", got)
	}
}
