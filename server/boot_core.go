package main

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
)

func initializeCoreService(cfg *config.Config) (*core.KeyorixCore, *encryption.Service, error) {
	// #G-blank-storage-default: mirrors main()'s own default-application above —
	// a test or any other caller that builds a *config.Config by hand and skips
	// straight to this function bypassed that default too. This is the server's
	// own boot path (the one caller allowed to treat a blank storage.type as
	// "local"; see internal/storage/factory.go's CreateStorage), so apply the
	// same default here, before the Validate() call immediately below rejects a
	// blank type. This does NOT set a default for the CLI: this function lives
	// in server/main.go's package main and is never called from CLI code.
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}

	// #1475: mirrors main()'s own cfg.Validate() call above — a test or any other
	// caller that builds a *config.Config by hand and skips straight to this
	// function bypassed schema/sanity validation entirely, letting fixtures encode
	// configs production boot would refuse (e.g. autocert enabled with no domains).
	// Enforcing it here means "this function accepted the config" is only ever true
	// for a config production would actually boot with.
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid configuration: %w", err)
	}
	// Use storage factory to support SQLite, PostgreSQL, and remote storage
	factory := appstorage.NewStorageFactory()
	store, err := factory.CreateStorage(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// key_dir_lock: database — record it in the database so `admin --force` and a
	// live backup decide from what the replicas declare, not from the admin
	// command's own config. Here, right after the migrations CreateStorage ran and
	// before key initialisation (which can hold the key-init lock for up to
	// keyInitLockWait): main() took the presence lock before this function, so the
	// marker must not trail it by the rest of the boot.
	if cfg.Storage.Encryption.KeyDirLockIsDatabase() {
		if err := recordKeyDirLockMode(cfg); err != nil {
			return nil, nil, err
		}
	}

	encSvc, err := initializeEncryption(cfg, store.LogAuditEvent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	coreService := core.NewKeyorixCore(store)
	cw := &coreWiring{cfg: cfg, core: coreService, store: store, encSvc: encSvc}
	for _, step := range coreWiringSteps {
		if err := step(cw); err != nil {
			return nil, nil, err
		}
	}
	return coreService, encSvc, nil
}

// coreWiring is what every core wiring step receives: the loaded config, the core
// service being wired, its storage, and the encryption service (nil when
// storage.encryption is disabled).
type coreWiring struct {
	cfg    *config.Config
	core   *core.KeyorixCore
	store  corestorage.Storage
	encSvc *encryption.Service
}

// coreWiringStep applies one part of the config to the core service. A non-nil
// error stops the boot (initializeCoreService returns it unchanged).
type coreWiringStep func(cw *coreWiring) error
