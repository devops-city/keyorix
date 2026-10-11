package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/configs"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

// Ported near-verbatim from internal/cli/system/init.go's LOCAL-mode path
// (generateConfigFile/initializeEncryption/initializeDatabase) per ADR-108 §B1
// and docs/cli-split-inventory.md §7 PR 11 -- the remote-bootstrap branch
// (`system init --server ...`, POST /system/init) stays a CLI/API command; it
// talks to a server over the network and has no place in a host-side admin
// subcommand. This command never starts a listener.
var (
	initAll            bool
	initEncryptionOnly bool
	initDatabaseOnly   bool
	initLoggingOnly    bool
	initOverwrite      bool
	initDev            bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create config, encryption keys, and the database on this host",
	Long: `Initialize the files a Keyorix server needs to start: the config file,
encryption key directories, and an empty database file. Never starts a
listener; run 'keyorix-server' (no subcommand) or 'keyorix-server admin
migrate' afterward.

The config is the secure baseline: 'admin validate --posture' reports zero
deviations on it. When init writes it, init also generates the files it
references, without printing their contents: a self-signed TLS certificate
and key (certs/server.crt, certs/server.key) and a random /metrics token
(secrets/metrics_token), all 0600. Files that already exist are kept. An
existing config is never changed and nothing is generated for it.

--dev writes a relaxed config instead, labelled DEV-ONLY: no TLS, no rate
limit, unauthenticated /metrics. For a throwaway local demo only; the
posture check reports it.

Exit codes: 0 on success, 1 on any failure (see the printed error message).`,
	RunE: runAdminInit,
}

func init() {
	initCmd.Flags().BoolVar(&initAll, "all", true, "Initialize all components")
	initCmd.Flags().BoolVar(&initEncryptionOnly, "encryption", false, "Initialize encryption key directories only")
	initCmd.Flags().BoolVar(&initDatabaseOnly, "database", false, "Initialize the database only")
	initCmd.Flags().BoolVar(&initLoggingOnly, "logging", false, "Initialize logging only")
	initCmd.Flags().BoolVar(&initOverwrite, "overwrite-existing", false, "Overwrite an existing config file (dangerous)")
	initCmd.Flags().BoolVar(&initDev, "dev", false, "Write the relaxed DEV-ONLY config (no TLS, no rate limit, unauthenticated /metrics) for a local demo; never for production")
}

func runAdminInit(cmd *cobra.Command, args []string) error { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	configPath := configPathFlag
	if configPath == "" {
		configPath = "./keyorix.yaml"
	}

	fmt.Println("Keyorix Server Admin: init")
	fmt.Println("==========================")

	setupAll := initAll
	if initEncryptionOnly || initDatabaseOnly || initLoggingOnly {
		setupAll = false
	}

	wroteConfig, err := generateAdminConfigFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to generate config file: %w", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	// Only for the config this run wrote: an existing install is never changed.
	if wroteConfig && !initDev {
		if err := generateSecureBaselineFiles(cfg); err != nil {
			return fmt.Errorf("failed to generate TLS certificate / metrics token: %w", err)
		}
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	if setupAll || initEncryptionOnly {
		if err := initializeAdminEncryption(cfg); err != nil {
			return fmt.Errorf("failed to initialize encryption: %w", err)
		}
	}

	if setupAll || initDatabaseOnly {
		if err := initializeAdminDatabase(cfg); err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
	}

	if setupAll || initLoggingOnly {
		if err := initializeAdminLogging(); err != nil {
			return fmt.Errorf("failed to initialize logging: %w", err)
		}
	}

	fmt.Println("\nKeyorix system initialization completed successfully.")
	fmt.Printf("Config file: %s\n", configPath)
	if cfg.Storage.Type == "local" || cfg.Storage.Type == "sqlite" {
		fmt.Println("Using PostgreSQL instead? Set storage.type: postgres (and storage.database.dsn) in the config BEFORE the steps below; the SQLite file created here is then unused and can be deleted.")
	}
	fmt.Println("Run 'keyorix-server admin encryption init' to generate encryption keys (required before the server can start)")
	fmt.Println("Run 'keyorix-server admin validate' to check the setup")
	fmt.Println("Run 'keyorix-server admin migrate' to create the database schema")
	fmt.Println("Run 'keyorix-server admin audit' to check file permissions")

	recordAdminAction(cfg, "admin.init", fmt.Sprintf("ran `keyorix-server admin init` (config=%s)", configPath), true)

	return nil
}

// generateAdminConfigFile writes the config template (the DEV-ONLY variant
// with --dev) unless a config already exists, and reports whether it wrote one.
func generateAdminConfigFile(configPath string) (bool, error) {
	fmt.Printf("Generating config file: %s\n", configPath)

	if _, err := os.Stat(configPath); err == nil && !initOverwrite {
		fmt.Printf("Config file already exists: %s\n", configPath)
		fmt.Println("   Use --overwrite-existing to overwrite")
		return false, nil
	}

	tpl := configs.DefaultConfigTemplate
	if initDev {
		dev, err := configs.DevConfigTemplate()
		if err != nil {
			return false, err
		}
		tpl = dev
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		return false, fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := securefiles.SecureWriteFileSync(".", configPath, tpl, 0600); err != nil {
		return false, fmt.Errorf("failed to write config file: %w", err)
	}

	if initDev {
		fmt.Printf("Config file created: %s (DEV-ONLY: no TLS, no rate limit, unauthenticated /metrics -- never use it for production)\n", configPath)
	} else {
		fmt.Printf("Config file created: %s (secure baseline)\n", configPath)
	}
	return true, nil
}

func initializeAdminDatabase(cfg *config.Config) error {
	// #2980: the SQLite file is only this deployment's database when the backend
	// is SQLite. For PostgreSQL (or remote) there is nothing to pre-create on
	// disk, and creating one leaves a stray, unused keyorix.db behind.
	switch cfg.Storage.Type {
	case "postgres", "postgresql", "remote":
		fmt.Printf("Database: storage.type is %q, no local database file to create (run 'keyorix-server admin migrate' to create the schema)\n", cfg.Storage.Type)
		return nil
	}
	dbPath := filepath.Clean(cfg.Storage.Database.Path)
	if strings.Contains(dbPath, "..") {
		return fmt.Errorf("invalid path for database: %s", dbPath)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}
	// O_EXCL makes the create atomic: no TOCTOU window between stat and open.
	// If the file already exists, OpenFile returns an error we treat as "ok".
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if cerr := file.Close(); cerr != nil {
			return fmt.Errorf("failed to close database file: %w", cerr)
		}
	} else if !os.IsExist(err) {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	return nil
}

func initializeAdminEncryption(cfg *config.Config) error {
	// The KEK is passphrase-derived and never on disk (ADR-004); only the salt
	// and the wrapped DEK need directories.
	dekDir := filepath.Dir(cfg.Storage.Encryption.DEKPath)
	saltDir := filepath.Dir(cfg.Storage.Encryption.SaltPath)
	if err := os.MkdirAll(dekDir, 0750); err != nil {
		return fmt.Errorf("failed to create DEK directory: %w", err)
	}
	if err := os.MkdirAll(saltDir, 0750); err != nil {
		return fmt.Errorf("failed to create salt directory: %w", err)
	}
	return nil
}

func initializeAdminLogging() error {
	logPath := filepath.Clean("keyorix.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0750); err != nil {
		return fmt.Errorf("failed to create logging directory: %w", err)
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if cerr := file.Close(); cerr != nil {
			return fmt.Errorf("failed to close log file: %w", cerr)
		}
	} else if !os.IsExist(err) {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	return nil
}
