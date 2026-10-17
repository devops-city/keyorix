package admin

import (
	"fmt"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

// Ported near-verbatim from internal/cli/system/audit.go per ADR-108 §B1 and
// docs/cli-split-inventory.md §7 PR 11 -- securefiles.FixFilePerms in
// audit-only mode over the config file and every key-material path
// (internal/keyfiles.Registry). Never starts a listener.
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit critical files for permissions and ownership",
	Long: `Checks the config file and every encryption key-material path
(internal/keyfiles.Registry) for correct permissions and ownership, without
modifying anything (see 'admin encryption fix-perms' to auto-correct).

Exit codes: 0 if every file passes, 1 if any file fails (see the printed
warnings/errors).`,
	RunE: runAdminAudit,
}

func runAdminAudit(cmd *cobra.Command, args []string) error {
	// Resolve the same way config.Load will, so the path checked below is the
	// file actually loaded -- not a hardcoded "keyorix.yaml" that silently
	// diverges from --config / KEYORIX_CONFIG_PATH on any non-default deployment.
	configPath := filepath.Clean(config.ResolvedPath(configPathFlag))
	fmt.Printf("Auditing config file: %s\n", configPath)

	cfg, err := config.Load(configPathFlag)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	if _, err := cfg.EnforceSecretFilePermissions(); err != nil {
		return fmt.Errorf("secret file security: %w", err)
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	// Every key-material path below is config-driven and about to be
	// Lstat'd/opened -- sanitized the same way validateFilePermissions and
	// fixfileperm.go's autofix path do, so a config-driven '..' can't probe an
	// unintended file's permissions even in audit-only mode.
	files := []securefiles.FilePermSpec{{Path: configPath, Mode: 0600}}
	specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
	if err != nil {
		return fmt.Errorf("failed to build key-file registry: %w", err)
	}
	files = append(files, specs...)

	if err := securefiles.FixFilePerms(files, false); err != nil { // false = audit only
		fmt.Println("\nAudit finished with warnings/errors. Please fix the issues.")
		// Returning an error here (not os.Exit(1) directly) matters: os.Exit
		// terminates the process immediately, WITHOUT unwinding the call
		// stack -- it would skip this function's own `defer lock.Release()`
		// above, leaving the exclusive database lock to release only via
		// Postgres's slower, asynchronous connection-close detection (or,
		// for SQLite, the kernel's fd cleanup) instead of the fast,
		// synchronous, explicit unlock every other exit path gets. Returning
		// an error lets Execute() (admin.go) set the same exit code AFTER
		// this function's defers -- including the lock release -- have run.
		return fmt.Errorf("audit found permission/ownership issues")
	}

	fmt.Println("Audit passed: all critical files have correct permissions and ownership.")
	return nil
}
