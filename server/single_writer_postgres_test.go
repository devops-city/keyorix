package main

// single_writer_postgres_test.go — storage.database.single_writer driven the
// way an operator drives it, against the real server binary and a real
// PostgreSQL database (pg-gated): the start-up line, a direct SQL write
// refused while the server runs, a second server refused, admin --force
// refused, the emergency two-step, the posture line once the server is
// stopped, and the fence removed by a later boot without the setting.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func swWriteConfig(t *testing.T, dir, dsn string, singleWriter bool) {
	t.Helper()
	cfg := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
    single_writer: %t
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: %q
  grpc:
    enabled: false
`, dsn, singleWriter, freeTCPPort(t))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(cfg), 0o600))
}

type swServer struct {
	cmd     *exec.Cmd
	logPath string
}

func (s *swServer) output() string {
	b, _ := os.ReadFile(s.logPath)
	return string(b)
}

// swStartServer starts the server binary in dir, logging to a file in dir.
func swStartServer(t *testing.T, bin, dir string) *swServer {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-sw", "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	logPath := filepath.Join(dir, fmt.Sprintf("server-%d.log", time.Now().UnixNano()))
	f, err := os.Create(logPath) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	cmd.Stdout, cmd.Stderr = f, f
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return &swServer{cmd: cmd, logPath: logPath}
}

func (s *swServer) waitLog(t *testing.T, needle string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if strings.Contains(s.output(), needle) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server log never contained %q within %s; log:\n%s", needle, within, s.output())
}

func TestSingleWriter_Postgres_OperatorJourney(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)
	bin := buildServerBinary(t)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keys"), 0o750))
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-sw")
	swWriteConfig(t, dir, dsn, true)
	out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	require.NoError(t, err, out)
	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	require.NoError(t, err, out)

	// 1. Start-up line.
	srv := swStartServer(t, bin, dir)
	srv.waitLog(t, "single_writer: authoritative (lock held by backend pid", 60*time.Second)
	require.Contains(t, srv.output(), "Direct database writes to the security tables are refused while this server runs")

	// 2. A direct SQL revocation is refused while it runs.
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	err = db.Exec("DELETE FROM role_permissions WHERE role_id = -1").Error
	require.Error(t, err)
	require.Contains(t, err.Error(), "keyorix single_writer")

	// 3. A second server without the setting refuses to start.
	dir2 := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir2, "keys"), 0o750))
	for _, f := range []string{"keys/dek.key", "keys/kek.salt"} {
		b, rerr := os.ReadFile(filepath.Join(dir, f))
		require.NoError(t, rerr)
		require.NoError(t, os.WriteFile(filepath.Join(dir2, f), b, 0o600))
	}
	swWriteConfig(t, dir2, dsn, false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	second := exec.CommandContext(ctx, bin)
	second.Dir = dir2
	second.Env = append(baseEnv(dir2), "KEYORIX_MASTER_PASSWORD=test-passphrase-sw", "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	secondOut, err := second.CombinedOutput()
	require.Error(t, err, "a second server must not start next to a single-writer server")
	require.Contains(t, string(secondOut), "single_writer holds this database", string(secondOut))

	// 4. admin --force cannot override it.
	out, err = runAdmin(t, bin, dir, env, "migrate", "--force", "--config", "./keyorix.yaml")
	require.Error(t, err)
	require.Contains(t, out, "--force cannot override it", out)

	// The server's own boot and bootstrap writes are all accounted for by its
	// tracker: the unattributed-bump canary never fired.
	time.Sleep(time.Second)
	require.NotContains(t, srv.output(), "write epoch moved without", "the canary fired during a normal run")

	// 5. The emergency two-step: terminate the holder's lock session, then
	// the direct change commits; the server reports it no longer trusts its
	// caches.
	var terminated bool
	require.NoError(t, db.Raw("SELECT pg_terminate_backend(holder_pid) FROM keyorix_sole_writer").Scan(&terminated).Error)
	require.True(t, terminated)
	require.Eventually(t, func() bool {
		return db.Exec("DELETE FROM role_permissions WHERE role_id = -1").Error == nil
	}, 10*time.Second, 50*time.Millisecond)
	srv.waitLog(t, "single_writer: confirming: holder lock lost", 5*time.Second)

	// 6. Server stopped: the posture report shows the mode and the runbook.
	_ = srv.cmd.Process.Kill()
	_, _ = srv.cmd.Process.Wait()
	out, _ = runAdmin(t, bin, dir, env, "validate", "--posture", "--config", "./keyorix.yaml")
	require.Contains(t, out, "single_writer: on (storage.database.single_writer)", out)
	require.Contains(t, out, "pg_terminate_backend(holder_pid)", out)

	// 7. A later boot without the setting removes the fence.
	swWriteConfig(t, dir, dsn, false)
	srv2 := swStartServer(t, bin, dir)
	srv2.waitLog(t, "removed the write fence left by an earlier single_writer boot", 60*time.Second)
	var n int
	require.NoError(t, db.Raw("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'trg\\_ksw\\_%'").Scan(&n).Error)
	require.Zero(t, n)
}
