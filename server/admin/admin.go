// Package admin implements `keyorix-server admin <cmd>` (ADR-108 §B, PR 11):
// offline, host-side operations that need direct access to the database and
// key files on the server host, run as subcommands of the server binary
// rather than a third binary (the server binary already links core and
// storage). No admin command ever starts an HTTP or gRPC listener.
package admin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/version"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// adminActorType tags every audit event an admin command writes, so a reader
// can tell a host-side `keyorix-server admin` action apart from an ordinary
// "system" (scheduler/startup) event or a "user"/"machine_identity" one.
const adminActorType = "admin_cli"

var rootCmd = &cobra.Command{
	Use:   "admin",
	Short: "Host-side operations that need direct database and key-file access",
	Long: `keyorix-server admin -- operations that must not, or cannot, go through the
network API (ADR-108 §B): the server can't start, everyone is locked out, or
the operation needs the database to itself. These need shell access on the
server host, plus the database and key files -- owning the host is the
authority. No admin command starts an HTTP or gRPC listener.

'keyorix-server admin version' prints the build version, commit, build date and
Go version.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var (
	configPathFlag string
	forceFlag      bool
)

func init() {
	rootCmd.PersistentFlags().StringVar(&configPathFlag, "config", "", "Path to config file (defaults to $KEYORIX_CONFIG_PATH or keyorix.yaml)")
	rootCmd.PersistentFlags().BoolVar(&forceFlag, "force", false, "Run even if a live server appears to be attached to this database")
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(diagnoseCmd)
	rootCmd.AddCommand(migrateCmd)
}

// Execute runs the admin command tree against args (os.Args[2:] -- the
// portion after "admin") and returns a process exit code.
//
// An error implementing exitCodeError (see audit_verify.go) carries its own
// specific code instead of the default 1 -- verify-audit's exit code is a
// documented, three-way verdict (0/1/2/3, design §6), not merely a
// success/failure bit.
func Execute(args []string) int {
	// `admin version` / `admin --version`: build info only. Answered before cobra and
	// before any config or database lock, so it works on a host with no config and
	// beside a running server. Not a cobra subcommand on purpose: the state-map
	// entrypoint key drops "admin", so a `version` subcommand here would collide with
	// the CLI's own `keyorix version` row.
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Print(version.Info())
		return 0
	}
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		var ece *exitCodeError
		if errors.As(err, &ece) {
			return ece.code
		}
		return 1
	}
	return 0
}

// loadConfig resolves and loads the config file the same way every other
// admin command does: --config (persistent flag), else
// config.ResolvedPath's own KEYORIX_CONFIG_PATH/keyorix.yaml resolution.
//
// Unlike internal/cli/common's CLI-side loaders, a blank storage.type IS
// defaulted to "local" here -- mirroring server/main.go's own
// #G-blank-storage-default boot behavior, not the CLI's. This package is
// part of the SERVER binary and operates on the same on-prem, no-`storage:`-
// block deployment shape the plain server boots against; a CLI command
// reached through a *different* binary is not this caller.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(configPathFlag)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	// server/main.go's boot path always calls this before touching storage;
	// admin commands never went through that path, so any storage call that
	// happens to localize an error message (e.g. GetUserByEmail's not-found
	// path) panics with "i18n not initialized" -- found via recover-admin's
	// own manual testing, the first admin command to reach such a call.
	// i18n.Initialize is sync.Once-guarded, so calling it here on every
	// admin command is a safe, idempotent no-op once it has succeeded.
	if err := i18n.Initialize(cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize i18n: %w", err)
	}
	return cfg, nil
}

// stoppedServerHint is appended to the held-lock refusal: the Docker Compose
// sequence docs/SELF_HOSTING.md documents for running an admin command with the
// server stopped (#2540). `exec` runs inside the live backend, so it can never work.
const stoppedServerHint = "With Docker Compose, run admin commands in a throwaway container while the server is stopped:\n" +
	"  docker compose stop backend\n" +
	"  docker compose run --rm backend ./keyorix-server admin <command>\n" +
	"  docker compose start backend"

// acquireDatabaseLock is the shared guard every admin command runs before
// doing anything, and HOLDS for its entire operation -- not merely a check
// released before the real work starts. A probe-then-release design leaves
// a window between the check and the work in which a server (or another
// admin command) could attach, which is exactly the race this guard exists
// to close: found in review before this package's first use ever merged.
//
// Callers MUST defer Release() on the returned lock (nil-safe) for every
// return path of their RunE, for as long as they touch the database.
//
// --force does not skip the acquisition attempt: it still tries to take the
// lock (so two well-behaved commands, one of them --forced, still serialize
// correctly against each other), and only proceeds unprotected -- with a
// printed warning -- if that attempt itself fails. Skipping the attempt
// entirely under --force would reopen the same race for the ONE case
// (another concurrent admin command, not a stuck lock) where taking it is
// still possible and still worth doing.
//
// See internal/serverguard's package doc for the underlying detection
// mechanism and its limits.
func acquireDatabaseLock(cfg *config.Config) (*serverguard.Exclusive, error) {
	lock, err := serverguard.AcquireExclusive(cfg)
	if err != nil {
		if forceFlag {
			fmt.Printf("WARNING: could not acquire this database's exclusive lock (%v) — proceeding anyway because --force was given. A live server or another admin command may be concurrently using this database; this command is not protected against that race.\n", err)
			return nil, nil
		}
		// #2362: AcquireExclusive fails the same way whether a server genuinely holds the
		// lock OR the attempt couldn't even connect (e.g. a Postgres auth failure,
		// SQLSTATE 28P01) -- the latter was being misreported as "a server is using this
		// database", which is simply untrue: presence was never actually determined. Both
		// cases still fail closed (no lock acquired, command refuses to proceed without
		// --force); only the displayed reason differs.
		if serverguard.IsLockHeld(err) {
			// #2540: say HOW to stop it on the documented Docker Compose path. Operators
			// who copy an old `docker compose exec backend ... admin ...` line land here,
			// and the refusal itself is correct (the command needs the database to itself).
			return nil, fmt.Errorf("a Keyorix server (or another admin command) appears to be using this database (%v) — admin commands must not run concurrently with either; stop it first, or pass --force if you are certain this is safe.\n%s", err, stoppedServerHint)
		}
		return nil, fmt.Errorf("cannot connect to the database to check for a running server: %v — admin commands must not run concurrently with a server, but this could not be verified; pass --force if you are certain this is safe", err)
	}
	return lock, nil
}

// withUsableStorage opens cfg's database via the same storage factory the
// server itself uses (which also applies any pending migration as a normal
// side effect of opening -- see internal/storage/factory.go's
// migrateDatabase, idempotent on an already-migrated database) and runs fn
// against it. Used by state-changing admin commands to write their audit
// event "where the DB is usable" (task requirement): a database that cannot
// even be opened is, by definition, not usable, and callers report that
// distinctly from the admin action's own success/failure rather than fail
// the whole command over it.
func withUsableStorage(cfg *config.Config, fn func(store corestorage.Storage) error) error {
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		return fmt.Errorf("database not usable: %w", err)
	}
	return fn(st)
}

// recordAdminAction writes an audit-chain event for a state-changing admin
// command and prints what it did (both parts of the task-2 requirement).
// Best-effort on the audit write: if the database isn't usable yet (e.g.
// `admin init` running against a brand-new, not-yet-migrated database on a
// backend the factory then fails to open for some unrelated reason), the
// command's own outcome is not affected -- this only ever downgrades to a
// printed note, never a hard failure, since the primary action already
// happened (or didn't) on its own terms before this is called.
func recordAdminAction(cfg *config.Config, eventType, description string, success bool) {
	fmt.Println(description)
	err := withUsableStorage(cfg, func(st corestorage.Storage) error {
		ok := success
		return st.LogAuditEvent(context.Background(), &models.AuditEvent{
			EventType:   eventType,
			Description: description,
			Success:     &ok,
			ActorType:   adminActorType,
			EventTime:   time.Now(),
		})
	})
	if err != nil {
		fmt.Printf("note: could not record this action to the audit chain (%v)\n", err)
	}
}

// closeGormDB closes a raw *gorm.DB opened via storage.OpenGormDB. Best
// effort: a close failure on a short-lived CLI-style process is not worth
// failing an otherwise-successful command over.
func closeGormDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
