package deploy

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// PG-TLS-3: the compose stack's Postgres serves TLS and Keyorix connects with
// ssl_mode: verify-full against the certificate scripts/selfhost/init-secrets.sh
// generates. These tests pin the wiring between the four artefacts that must
// agree -- the generator, docker-compose.yml, keyorix.docker.yaml and the
// server's own TLS validation -- using the REAL generator output.
//
// What this does not cover: that Postgres accepts the key at the permissions the
// container gives it and that the connection really is TLS. That is verified on
// the e2e VM against the real stack (see the PR).

// composeDBCertContainerPath is where the backend sees the Postgres certificate
// (a Docker secret named postgres_tls_cert).
const composeDBCertContainerPath = "/run/secrets/postgres_tls_cert"

type postgresTLSFiles struct{ dir, cert, key string }

// generatePostgresTLS runs the real init-secrets.sh into a temp dir and returns
// the paths of the Postgres certificate and key it wrote.
func generatePostgresTLS(t *testing.T) postgresTLSFiles {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatalf("openssl is required (init-secrets.sh generates the Postgres certificate with it): %v", err)
	}
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	script, err := filepath.Abs(filepath.Join("..", "scripts", "selfhost", "init-secrets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	// A server uid that is not ours, so the script's own "files owned by the
	// server uid" refusal cannot fire on a CI runner that is uid 1001.
	uid := "65534"
	if os.Getuid() == 65534 {
		uid = "65533"
	}
	cmd := exec.Command("sh", script, "--dir", secrets, "--env-file", filepath.Join(dir, ".env")) //nolint:gosec // repo script, test-controlled args
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "INIT_SECRETS_SERVER_UID=" + uid}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init-secrets.sh: %v\n%s", err, out)
	}
	return postgresTLSFiles{dir: secrets, cert: filepath.Join(secrets, "postgres_tls.crt"), key: filepath.Join(secrets, "postgres_tls.key")}
}

func loadLocalizedComposeConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(withLocalTokenFile(t, "keyorix.docker.yaml", "/app/tls/metrics_token"))
	if err != nil {
		t.Fatalf("keyorix.docker.yaml does not load with the generated certificate: %v", err)
	}
	return cfg
}

// The server connects to the bundled Postgres with verify-full and a named CA.
func TestComposeConfig_DatabaseIsVerifyFullWithRootCert(t *testing.T) {
	db := loadLocalizedComposeConfig(t).Storage.Database
	if db.SSLMode != "verify-full" {
		t.Errorf("keyorix.docker.yaml ssl_mode = %q, want verify-full (the bundled postgres serves TLS since PG-TLS-3)", db.SSLMode)
	}
	if db.SSLRootCert == "" {
		t.Error("keyorix.docker.yaml names no ssl_root_cert: verify-full would be refused at start-up")
	}
	if db.DSN != "" {
		t.Error("keyorix.docker.yaml uses a dsn: its sslmode/sslrootcert would bypass the fields this test pins")
	}
}

// The raw config names the Docker secret path the compose file mounts.
func TestComposeConfig_RootCertIsTheMountedSecret(t *testing.T) {
	var raw struct {
		Storage struct {
			Database struct {
				Host        string `yaml:"host"`
				SSLRootCert string `yaml:"ssl_root_cert"`
			} `yaml:"database"`
		} `yaml:"storage"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "keyorix.docker.yaml")), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Storage.Database.SSLRootCert != composeDBCertContainerPath {
		t.Fatalf("ssl_root_cert = %q, want %q (the postgres_tls_cert secret)", raw.Storage.Database.SSLRootCert, composeDBCertContainerPath)
	}
	if raw.Storage.Database.Host != "postgres" {
		t.Fatalf("host = %q, want the compose service name postgres (the certificate is issued for that name)", raw.Storage.Database.Host)
	}
}

type composeSecretsFile struct {
	Services map[string]struct {
		Command []string `yaml:"command"`
		Secrets []string `yaml:"secrets"`
	} `yaml:"services"`
	Secrets map[string]struct {
		File string `yaml:"file"`
	} `yaml:"secrets"`
}

func loadComposeSecrets(t *testing.T) composeSecretsFile {
	t.Helper()
	var f composeSecretsFile
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "docker-compose.yml")), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Postgres turns ssl on from the generated files, and the backend gets the
// certificate: the secrets exist, point at the names init-secrets.sh writes,
// and are mounted where the command and the config say.
func TestComposeStack_PostgresServesTLSFromTheGeneratedSecrets(t *testing.T) {
	f := loadComposeSecrets(t)
	gen := generatePostgresTLS(t)
	pg, ok := f.Services["postgres"]
	if !ok {
		t.Fatal("no postgres service")
	}
	cmd := strings.Join(pg.Command, " ")
	for _, want := range []string{
		"ssl=on",
		"ssl_cert_file=/run/secrets/postgres_tls_cert",
		"ssl_key_file=/tmp/postgres_tls.key",
		"cp /run/secrets/postgres_tls_key /tmp/postgres_tls.key",
		"umask 077",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("postgres command lacks %q:\n%s", want, cmd)
		}
	}
	for _, name := range []string{"postgres_tls_cert", "postgres_tls_key"} {
		if !has(pg.Secrets, name) {
			t.Errorf("postgres does not mount secret %s", name)
		}
	}
	if !has(f.Services["backend"].Secrets, "postgres_tls_cert") {
		t.Error("backend does not mount postgres_tls_cert (its ssl_root_cert)")
	}
	if has(f.Services["backend"].Secrets, "postgres_tls_key") {
		t.Error("backend mounts the postgres private key: only the certificate is public")
	}
	for secret, file := range map[string]string{"postgres_tls_cert": gen.cert, "postgres_tls_key": gen.key} {
		got := f.Secrets[secret].File
		wantBase := filepath.Base(file)
		if !strings.HasSuffix(got, "/"+wantBase) {
			t.Errorf("secret %s reads %q, but init-secrets.sh writes %s", secret, got, wantBase)
		}
	}
}

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- generated in a temp dir by this test
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("%s is not a PEM certificate", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// verify-full means: the certificate chains to ssl_root_cert AND names the host
// the server dials. The generated certificate, trusted as its own root, must
// verify for the compose service name and for nothing else.
func TestInitSecretsCertificate_VerifiesForTheComposeHostOnly(t *testing.T) {
	gen := generatePostgresTLS(t)
	cert := parseCert(t, gen.cert)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	host := loadLocalizedComposeConfig(t).Storage.Database.Host

	verify := func(name string) error {
		_, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err
	}
	if err := verify(host); err != nil {
		t.Errorf("the generated certificate does not verify for the configured host %q: %v", host, err)
	}
	for _, other := range []string{"backend", "localhost", "evil.example"} {
		if err := verify(other); err == nil {
			t.Errorf("the generated certificate verifies for %q: verify-full would accept the wrong host", other)
		}
	}
	// And a different generation is not trusted.
	other := parseCert(t, generatePostgresTLS(t).cert)
	otherPool := x509.NewCertPool()
	otherPool.AddCert(other)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: otherPool, DNSName: host}); err == nil {
		t.Error("a certificate verifies against an unrelated one's root")
	}
}

// The files must not be accessible to "other", and the generator must not leave
// the working files behind in the secrets dir.
func TestInitSecretsPostgresTLS_FilesArePrivateAndTidy(t *testing.T) {
	gen := generatePostgresTLS(t)
	for _, p := range []string{gen.cert, gen.key} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o007 != 0 {
			t.Errorf("%s is accessible to other: %04o", p, info.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(gen.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("init-secrets.sh left a working file %s in the secrets dir", e.Name())
		}
	}
}
