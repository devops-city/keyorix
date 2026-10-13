package cmd

// SCRIPTS-SECRETS-1: scripts must be able to hand login / mfa activate their password and
// one-time code without putting either on the command line. KEYORIX_PASSWORD and
// KEYORIX_MFA_CODE (each also as *_FILE, via lookupSecretEnv) are that path.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLoginPassword_FromEnv(t *testing.T) {
	loginPassword = ""
	t.Setenv("KEYORIX_PASSWORD_FILE", "")
	t.Setenv("KEYORIX_PASSWORD", "env-pw-1")
	p, err := resolveLoginPassword(loginCmd)
	if err != nil || p != "env-pw-1" {
		t.Fatalf("got %q, %v; want env-pw-1", p, err)
	}
}

func TestResolveLoginPassword_FromFile(t *testing.T) {
	loginPassword = ""
	f := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(f, []byte("file-pw-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYORIX_PASSWORD", "")
	t.Setenv("KEYORIX_PASSWORD_FILE", f)
	p, err := resolveLoginPassword(loginCmd)
	if err != nil || p != "file-pw-1" {
		t.Fatalf("got %q, %v; want file-pw-1", p, err)
	}
}

func TestResolveLoginPassword_EnvAndFileBothSetIsAnError(t *testing.T) {
	loginPassword = ""
	f := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYORIX_PASSWORD", "y")
	t.Setenv("KEYORIX_PASSWORD_FILE", f)
	if _, err := resolveLoginPassword(loginCmd); err == nil {
		t.Fatal("expected an error when both KEYORIX_PASSWORD and KEYORIX_PASSWORD_FILE are set")
	}
}

func TestResolveMFACode_FromEnv(t *testing.T) {
	loginMFACode = ""
	t.Setenv("KEYORIX_MFA_CODE_FILE", "")
	t.Setenv("KEYORIX_MFA_CODE", " 123456 ")
	c, err := resolveMFACode(loginCmd)
	if err != nil || c != "123456" {
		t.Fatalf("got %q, %v; want 123456", c, err)
	}
}

func TestMFAActivate_CodeAndPasswordFromEnv(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"recovery_codes":["rc-1"]}}`))
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	mfaActivateCode, mfaActivatePassword = "", ""
	t.Setenv("KEYORIX_MFA_CODE_FILE", "")
	t.Setenv("KEYORIX_PASSWORD_FILE", "")
	t.Setenv("KEYORIX_MFA_CODE", "654321")
	t.Setenv("KEYORIX_PASSWORD", "env-activate-pw")

	captureStdout(t, func() {
		if err := runMFAActivate(mfaActivateCmd, nil); err != nil {
			t.Fatalf("runMFAActivate: %v", err)
		}
	})
	if got["code"] != "654321" || got["password"] != "env-activate-pw" {
		t.Errorf("request body: %v", got)
	}
}
