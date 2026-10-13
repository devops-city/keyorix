//go:build unix

package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/cli/internal/credstore"
	"github.com/keyorixhq/keyorix/cli/internal/migrate"
)

// FIFO-5: every operator-supplied input path of the CLI must refuse a FIFO at once
// instead of hanging in open(2) until a writer appears. Red on the old os.Open /
// os.ReadFile code (the call never returns); green with cli/internal/regularfile.

func newFIFO(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// within1s runs fn; if it has not returned after a second it opens the FIFO itself
// (releasing the stuck goroutine and the temp dir) and fails.
func within1s[T any](t *testing.T, fifo string, fn func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- fn() }()
	select {
	case v := <-done:
		return v
	case <-time.After(time.Second):
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("blocked on a FIFO instead of refusing it within 1s")
		var zero T
		return zero
	}
}

// wantNotRegular checks the refusal and that it names the path (its base name at
// least: "secret create --from-file" takes a relative path).
func wantNotRegular(t *testing.T, err error, path string) {
	t.Helper()
	if err == nil {
		t.Fatal("succeeded on a FIFO, want a refusal")
	}
	if !strings.Contains(err.Error(), "not a regular file") || !strings.Contains(err.Error(), filepath.Base(path)) {
		t.Fatalf("error = %v, want it to name the path %q and %q", err, path, "not a regular file")
	}
}

func setStr(t *testing.T, p *string, v string) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func regularFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// One row per distinct entry point (command flag / argument).
func TestCLIInputPaths_RefuseFIFO(t *testing.T) {
	envelope := []byte(`{"format":"` + encryptedExportFormat + `"}`)
	cases := []struct {
		name string
		run  func(t *testing.T, fifo string) error
	}{
		{"compliance verify --file", func(t *testing.T, fifo string) error {
			setStr(t, &complianceVerifyFile, fifo)
			setStr(t, &complianceVerifySig, "")
			return complianceVerifyCmd.RunE(complianceVerifyCmd, nil)
		}},
		{"compliance verify --sig", func(t *testing.T, fifo string) error {
			setStr(t, &complianceVerifyFile, regularFile(t, "pack"))
			setStr(t, &complianceVerifySig, fifo)
			return complianceVerifyCmd.RunE(complianceVerifyCmd, nil)
		}},
		{"bundle verify <file>", func(t *testing.T, fifo string) error {
			return runBundleVerify(bundleVerifyCmd, []string{fifo})
		}},
		{"bundle import --license", func(t *testing.T, fifo string) error {
			setStr(t, &bundleImportDest, t.TempDir())
			setStr(t, &bundleImportLicense, fifo)
			return runBundleImport(bundleImportCmd, []string{regularFile(t, "x")})
		}},
		{"license --file (readLicenseToken)", func(t *testing.T, fifo string) error {
			_, err := readLicenseToken(fifo)
			return err
		}},
		{"secret export --encrypt-to (public key)", func(t *testing.T, fifo string) error {
			_, err := encryptExport([]byte("{}"), fifo)
			return err
		}},
		{"secret import --decrypt-with (private key)", func(t *testing.T, fifo string) error {
			_, err := decryptExport(envelope, fifo)
			return err
		}},
		{"secret render <template>", func(t *testing.T, fifo string) error {
			old := renderProject
			renderProject = 1
			t.Cleanup(func() { renderProject = old })
			return runSecretRender(nil, []string{fifo})
		}},
		{"secret import --file --decrypt-with", func(t *testing.T, fifo string) error {
			setStr(t, &importFile, fifo)
			setStr(t, &importFormat, "dotenv")
			setStr(t, &importDecryptWith, regularFile(t, "k"))
			_, err := collectImportEntries()
			return err
		}},
		{"secret import --file --format dotenv", func(t *testing.T, fifo string) error {
			_, err := parseImportFile(fifo, "dotenv")
			return err
		}},
		{"secret import --file --format vault", func(t *testing.T, fifo string) error {
			_, err := parseImportFile(fifo, "vault")
			return err
		}},
		{"secret import --file --format json", func(t *testing.T, fifo string) error {
			_, err := parseImportFile(fifo, "json")
			return err
		}},
		{"secret create --from-file", func(t *testing.T, fifo string) error {
			wd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(filepath.Dir(fifo))
			t.Cleanup(func() { _ = os.Chdir(wd) })
			_, err = readSecretValueFromFile(filepath.Base(fifo))
			return err
		}},
		{"credentials file (credstore Load)", func(t *testing.T, fifo string) error {
			_, err := credstore.NewFileStore(fifo).Load()
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fifo := newFIFO(t)
			err := within1s(t, fifo, func() error { return tc.run(t, fifo) })
			wantNotRegular(t, err, fifo)
		})
	}
}

// Walk-discovered files (a FIFO planted in a scanned tree) and the old-config
// detector have no error return: they must skip the FIFO without blocking.
func TestCLIInputPaths_FIFOSkippedWithoutBlocking(t *testing.T) {
	t.Run("secret scan file scanners", func(t *testing.T) {
		fifo := newFIFO(t)
		n := within1s(t, fifo, func() int {
			return len(scanEnvFile(fifo, "x")) + len(scanConfigFile(fifo, "x")) + len(scanSourceFile(fifo, "x"))
		})
		if n != 0 {
			t.Fatalf("findings from a FIFO = %d, want 0", n)
		}
	})
	t.Run("secret fix tree walk", func(t *testing.T) {
		dir := t.TempDir()
		fifo := filepath.Join(dir, "planted.py")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		plans := within1s(t, fifo, func() []fixPlan {
			p, err := findAndPlanFix(dir, "DB_PASSWORD")
			if err != nil {
				t.Errorf("findAndPlanFix: %v", err)
			}
			return p
		})
		if len(plans) != 0 {
			t.Fatalf("plans from a FIFO = %d, want 0", len(plans))
		}
	})
	t.Run("secret fix apply", func(t *testing.T) {
		dir := t.TempDir()
		fifo := filepath.Join(dir, "planted.py")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		err := within1s(t, fifo, func() error {
			return applyFix(dir, fixPlan{File: "planted.py", Line: 1, NewLine: "x"})
		})
		wantNotRegular(t, err, fifo)
	})
	t.Run("login old keyorix.yaml detection", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		fifo := filepath.Join(dir, "keyorix.yaml")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		type res struct{ ok bool }
		r := within1s(t, fifo, func() res {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("HOME", t.TempDir())
			_, ok := migrate.DetectOldServerURL()
			return res{ok}
		})
		if r.ok {
			t.Fatal("detected a server URL from a FIFO")
		}
	})
	t.Run("login old cli.yaml detection", func(t *testing.T) {
		xdg := t.TempDir()
		if err := os.MkdirAll(filepath.Join(xdg, "keyorix"), 0o700); err != nil {
			t.Fatal(err)
		}
		fifo := filepath.Join(xdg, "keyorix", "cli.yaml")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Chdir(t.TempDir())
		t.Setenv("XDG_CONFIG_HOME", xdg)
		ok := within1s(t, fifo, func() bool {
			_, ok := migrate.DetectOldServerURL()
			return ok
		})
		if ok {
			t.Fatal("detected a server URL from a FIFO")
		}
	})
}

// A regular file and a symlink to one still work at the same entry points (Kubernetes
// Secret volumes expose every key as a symlink).
func TestCLIInputPaths_RegularFileAndSymlinkStillWork(t *testing.T) {
	linkTo := func(t *testing.T, target string) string {
		t.Helper()
		l := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, l); err != nil {
			t.Fatal(err)
		}
		return l
	}

	t.Run("license token", func(t *testing.T) {
		p := regularFile(t, "  tok \n")
		for _, path := range []string{p, linkTo(t, p)} {
			got, err := readLicenseToken(path)
			if err != nil || got != "tok" {
				t.Fatalf("readLicenseToken(%s) = %q, %v", path, got, err)
			}
		}
	})

	t.Run("export public key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		p := regularFile(t, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
		for _, path := range []string{p, linkTo(t, p)} {
			if _, err := encryptExport([]byte(`{}`), path); err != nil {
				t.Fatalf("encryptExport(%s): %v", path, err)
			}
		}
	})

	t.Run("import dotenv, vault, json", func(t *testing.T) {
		for format, content := range map[string]string{
			"dotenv": "A=1\n",
			"json":   `{"A":"1"}`,
			"vault":  "secret/p/db:\n  value: v\n",
		} {
			p := regularFile(t, content)
			for _, path := range []string{p, linkTo(t, p)} {
				entries, err := parseImportFile(path, format)
				if err != nil || len(entries) != 1 {
					t.Fatalf("parseImportFile(%s, %s) = %v, %v", path, format, entries, err)
				}
			}
		}
	})

	t.Run("secret create --from-file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "v"), []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		got, err := readSecretValueFromFile("v")
		if err != nil || string(got) != "secret" {
			t.Fatalf("readSecretValueFromFile = %q, %v", got, err)
		}
	})

	t.Run("secret scan env file", func(t *testing.T) {
		p := regularFile(t, "API_KEY=abcdef1234567890abcdef\n")
		if got := scanEnvFile(p, "x"); len(got) == 0 {
			t.Fatal("scanEnvFile found nothing in a regular .env file")
		}
	})
}
