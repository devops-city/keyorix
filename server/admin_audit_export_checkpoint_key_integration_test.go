package main

// admin_audit_export_checkpoint_key_integration_test.go drives `keyorix-server admin
// audit export-checkpoint-key` (INSTALL-WALK-1 F12) as a real subprocess, reusing the
// verify-audit fixtures. The air-gap drill it closes: export an anchor, extract the key
// with THIS command, and see verify-audit report the anchor as authenticated.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

func TestExportCheckpointKey_AuthenticatesExportedAnchor(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)

	keyPath := filepath.Join(dir, "checkpoint.key")
	out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint-key", "--config", "./keyorix.yaml", "--output", keyPath)
	if err != nil {
		t.Fatalf("export-checkpoint-key failed: %v\n%s", err, out)
	}
	raw, rerr := os.ReadFile(keyPath)
	if rerr != nil {
		t.Fatalf("read key file: %v", rerr)
	}
	if strings.Contains(out, strings.TrimSpace(string(raw))) {
		t.Fatalf("the key must never be printed, output contained it:\n%s", out)
	}
	key, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
	if derr != nil || len(key) != 32 {
		t.Fatalf("key file must hold 32 hex-encoded bytes, got len=%d err=%v", len(key), derr)
	}
	if st, serr := os.Stat(keyPath); serr != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v (err %v), want 0600", st.Mode().Perm(), serr)
	}

	// It must be the key the server itself derives, not merely some 32 bytes.
	cfg, cerr := config.Load(filepath.Join(dir, "keyorix.yaml"))
	if cerr != nil {
		t.Fatalf("load config: %v", cerr)
	}
	svc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if ierr := svc.Initialize("test-passphrase-verify-audit"); ierr != nil {
		t.Fatalf("initialize encryption in-process: %v", ierr)
	}
	want, _, ok := svc.AuditCheckpointKey()
	svc.Shutdown()
	if !ok || hex.EncodeToString(want) != hex.EncodeToString(key) {
		t.Fatalf("exported key does not match the server-derived audit-checkpoint key")
	}

	// End to end: a checkpoint signed with the real key, exported as an anchor, is
	// AUTHENTICATED by verify-audit using only the extracted file.
	chainedEvents, headID, headHash := seedAuditChain(t, dbPath, 6)
	writeSignedCheckpoint(t, dbPath, key, chainedEvents, headID, headHash)
	anchor := filepath.Join(dir, "anchor.json")
	if o, e := runAdmin(t, bin, dir, env, "audit", "export-checkpoint", "--config", "./keyorix.yaml", "--output", anchor); e != nil {
		t.Fatalf("export-checkpoint failed: %v\n%s", e, o)
	}
	vout, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml", "--json",
		"--anchor", anchor, "--checkpoint-key-file", keyPath)
	if code != 0 {
		t.Fatalf("verify-audit exit %d:\n%s", code, vout)
	}
	var rep struct {
		Verdict        string `json:"verdict"`
		ExternalAnchor struct {
			Supplied      bool `json:"supplied"`
			Authenticated bool `json:"authenticated"`
		} `json:"external_anchor"`
	}
	if jerr := json.Unmarshal([]byte(vout[strings.Index(vout, "{"):]), &rep); jerr != nil {
		t.Fatalf("parse verify-audit json: %v\n%s", jerr, vout)
	}
	if rep.Verdict != "VALID" || !rep.ExternalAnchor.Supplied || !rep.ExternalAnchor.Authenticated {
		t.Fatalf("want VALID + supplied + authenticated anchor, got %+v\n%s", rep, vout)
	}
}

func TestExportCheckpointKey_RefusesOverwriteAndWrongPassphrase(t *testing.T) {
	bin := buildServerBinary(t)
	dir, _, env := setupVerifyAuditDB(t, bin)

	keyPath := filepath.Join(dir, "checkpoint.key")
	if err := os.WriteFile(keyPath, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint-key", "--config", "./keyorix.yaml", "--output", keyPath)
	if err == nil || !strings.Contains(out, "already exists") {
		t.Fatalf("want an already-exists refusal, got err=%v\n%s", err, out)
	}
	if b, _ := os.ReadFile(keyPath); string(b) != "precious" {
		t.Fatalf("existing file was modified: %q", b)
	}

	wrong := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=not-the-passphrase")
	fresh := filepath.Join(dir, "fresh.key")
	out, err = runAdmin(t, bin, dir, wrong, "audit", "export-checkpoint-key", "--config", "./keyorix.yaml", "--output", fresh)
	if err == nil {
		t.Fatalf("a wrong passphrase must fail, got success:\n%s", out)
	}
	if _, statErr := os.Stat(fresh); statErr == nil {
		t.Fatalf("no key file may be left behind after a failed derivation")
	}
}
