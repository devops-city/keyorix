package handlers

import (
	"net/http"
	"runtime"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/version"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// permSystemWrite mirrors router.go's own constant of the same name/value —
// the admin-tier permission (held by admin/system_admin, NOT the universal
// system_viewer baseline system.read) used to gate the recovery-key status
// field below to global admins only.
const permSystemWrite = "system.write"

// SystemInfo represents system information
type SystemInfo struct {
	Version     string          `json:"version"`
	BuildTime   string          `json:"build_time"`
	GitCommit   string          `json:"git_commit"`
	GoVersion   string          `json:"go_version"`
	OS          string          `json:"os"`
	Arch        string          `json:"arch"`
	Uptime      string          `json:"uptime"`
	Environment string          `json:"environment"`
	Features    map[string]bool `json:"features"`
	Database    DatabaseInfo    `json:"database"`
	Security    SecurityInfo    `json:"security"`
}

// DatabaseInfo represents database connection information
type DatabaseInfo struct {
	Type      string   `json:"type"`
	Connected bool     `json:"connected"`
	Version   string   `json:"version"`
	Pool      PoolInfo `json:"pool"`
}

// PoolInfo represents database connection pool information
type PoolInfo struct {
	MaxConnections    int `json:"max_connections"`
	ActiveConnections int `json:"active_connections"`
	IdleConnections   int `json:"idle_connections"`
}

// SecurityInfo represents security configuration information
type SecurityInfo struct {
	TLSEnabled       bool   `json:"tls_enabled"`
	AuthEnabled      bool   `json:"auth_enabled"`
	EncryptionMethod string `json:"encryption_method"`
	AuditEnabled     bool   `json:"audit_enabled"`
	// KeylessRecoveryMode surfaces security.recover_admin.keyless_mode
	// (docs/design-b2-recover-admin.md §5) so a customer's own compliance
	// scanning can catch a misconfigured install running the labs/demo
	// escape hatch -- one of the three places design §5 requires this to be
	// flagged (alongside the startup warning and the startup audit event).
	KeylessRecoveryMode bool `json:"keyless_recovery_mode"`
	// AuditDurableSyncSkipped surfaces
	// storage.database.insecure_audit_skip_durable_sync (ADR-112 Amendment 1,
	// docs/specs/fast-audit-mode.md) -- one of the four places that amendment
	// requires the setting to be flagged, and specifically the one a buyer's
	// auditor can reach WITHOUT host access, so "is this install still
	// committing audit durably before disclosing a secret?" is answerable over
	// the API.
	//
	// true means it is NOT: the audit record is still written and committed
	// before the secret is returned, and a failed audit write still fails the
	// request, but the commit no longer waits for a disk sync.
	//
	// This reports IN EFFECT, not merely "configured" -- so it is false on a
	// backend where the setting does nothing. Deliberately that way round: the
	// question this field answers is "is my audit durability weakened right
	// now", and on a remote backend the truthful answer is no. A configured
	// setting that is being ignored shows up in
	// AuditDurableSyncSkipNotInEffectReason below, so the two states stay
	// distinguishable from this response alone.
	AuditDurableSyncSkipped bool `json:"audit_durable_sync_skipped"`
	// AccessLogOnSinkStall is the effective server.access_log.on_sink_stall:
	// "block" (default; no access-log line is ever lost, requests wait for a
	// stalled sink) or "drop" (keeps serving; lines past the 1 MiB queue are
	// dropped and counted). The audit trail is unaffected either way.
	AccessLogOnSinkStall string `json:"access_log_on_sink_stall"`
	// AccessLogDropped is how many access-log lines this process has dropped
	// since start because the sink stalled. Always 0 in block mode.
	AccessLogDropped uint64 `json:"access_log_dropped"`
	// AuditDurableSyncSkipNotInEffectReason is non-empty ONLY when
	// insecure_audit_skip_durable_sync is present in the config but is not in
	// effect on this backend -- so a non-empty value always means "the
	// operator wrote this and it is doing nothing", and never anything else
	// (Andrei's decision, 2026-10-05: show it as off, WITH the reason, as a
	// field rather than only as log text). Omitted when empty, so a default
	// install's response is unchanged.
	AuditDurableSyncSkipNotInEffectReason string `json:"audit_durable_sync_skip_not_in_effect_reason,omitempty"`
	// RecoveryKey is a read-only recovery-key configuration status (F6,
	// recovery-key visibility) -- nil for any caller who does not hold
	// system.write (global-admin tier). Never carries the key or its hash,
	// only whether one exists and its generation; see
	// core.KeyorixCore.GetRecoveryKeyStatus.
	RecoveryKey *core.RecoveryKeyStatus `json:"recovery_key,omitempty"`
}

// SystemMetrics represents system performance metrics
type SystemMetrics struct {
	Memory     MemoryMetrics   `json:"memory"`
	Goroutines int             `json:"goroutines"`
	GC         GCMetrics       `json:"gc"`
	HTTP       HTTPMetrics     `json:"http"`
	Database   DatabaseMetrics `json:"database"`
	Secrets    SecretsMetrics  `json:"secrets"`
	Uptime     string          `json:"uptime"`
	Timestamp  time.Time       `json:"timestamp"`
}

// MemoryMetrics represents memory usage metrics
type MemoryMetrics struct {
	Alloc        uint64 `json:"alloc"`
	TotalAlloc   uint64 `json:"total_alloc"`
	Sys          uint64 `json:"sys"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    uint64 `json:"heap_alloc"`
	HeapSys      uint64 `json:"heap_sys"`
	HeapIdle     uint64 `json:"heap_idle"`
	HeapInuse    uint64 `json:"heap_inuse"`
	HeapReleased uint64 `json:"heap_released"`
	HeapObjects  uint64 `json:"heap_objects"`
	StackInuse   uint64 `json:"stack_inuse"`
	StackSys     uint64 `json:"stack_sys"`
}

// GCMetrics represents garbage collection metrics
type GCMetrics struct {
	NumGC         uint32   `json:"num_gc"`
	PauseTotal    uint64   `json:"pause_total"`
	PauseNs       []uint64 `json:"pause_ns"`
	NextGC        uint64   `json:"next_gc"`
	LastGC        uint64   `json:"last_gc"`
	GCCPUFraction float64  `json:"gc_cpu_fraction"`
}

// HTTPMetrics represents HTTP server metrics
type HTTPMetrics struct {
	RequestsTotal     int64   `json:"requests_total"`
	RequestsPerSec    float64 `json:"requests_per_sec"`
	AvgResponseTime   float64 `json:"avg_response_time"`
	ErrorRate         float64 `json:"error_rate"`
	ActiveConnections int     `json:"active_connections"`
}

// DatabaseMetrics represents database performance metrics
type DatabaseMetrics struct {
	QueriesTotal      int64   `json:"queries_total"`
	QueriesPerSec     float64 `json:"queries_per_sec"`
	AvgQueryTime      float64 `json:"avg_query_time"`
	SlowQueries       int64   `json:"slow_queries"`
	ConnectionsActive int     `json:"connections_active"`
	ConnectionsIdle   int     `json:"connections_idle"`
}

// SecretsMetrics represents secrets-related metrics
type SecretsMetrics struct {
	TotalSecrets       int64 `json:"total_secrets"`
	ActiveSecrets      int64 `json:"active_secrets"`
	ExpiredSecrets     int64 `json:"expired_secrets"`
	SecretsCreated24h  int64 `json:"secrets_created_24h"`
	SecretsAccessed24h int64 `json:"secrets_accessed_24h"`
	EncryptionOps24h   int64 `json:"encryption_ops_24h"`
	DecryptionOps24h   int64 `json:"decryption_ops_24h"`
}

var startTime = time.Now()

// Note: HealthCheck is implemented in health.go

// poolInfo reports the live connection pool of the running server: the cap the storage
// factory actually applied (config value, or the dialect default when unset), and the
// connections in use / idle right now. It used to echo the raw config values (0 when unset,
// which is the common case on compose and Helm installs) and a hard-coded "2 active".
// When the backend keeps no local pool the numbers are not available and stay 0, which the
// clients render as "not reported" (a max of 0 is never a real pool).
func poolInfo(coreService *core.KeyorixCore) PoolInfo {
	stats, ok := coreService.DBPoolStats()
	if !ok {
		return PoolInfo{}
	}
	return PoolInfo{
		MaxConnections:    stats.MaxOpenConnections,
		ActiveConnections: stats.InUse,
		IdleConnections:   stats.Idle,
	}
}

// MakeSystemInfoHandler returns a handler that serves real system info from config.
func MakeSystemInfoHandler(cfg *config.Config, coreService *core.KeyorixCore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx := middleware.GetUserFromContext(r.Context())
		if userCtx == nil {
			sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
			return
		}

		// Recovery-key status (F6): global-admin-only, per Andrei's decision
		// this must not be visible to non-admins even though the rest of
		// this endpoint is system.read-gated (the universal baseline).
		var recoveryKeyStatus *core.RecoveryKeyStatus
		if middleware.AuthorizedAtGlobalScope(r.Context(), coreService, userCtx, permSystemWrite) {
			if status, err := coreService.GetRecoveryKeyStatus(r.Context()); err == nil {
				recoveryKeyStatus = status
			}
		}

		// One computation, read twice below, so "in effect" and "why not"
		// cannot disagree within a single response.
		fastAuditStatus := cfg.Storage.Database.AuditDurableSyncStatus(cfg.Storage.Type)

		tlsEnabled := cfg.Server.HTTP.TLS.Enabled
		encryptionEnabled := cfg.Storage.Encryption.Enabled
		grpcEnabled := cfg.Server.GRPC.Enabled

		systemInfo := SystemInfo{
			Version:     version.Version,
			BuildTime:   version.BuildDate, // the commit date, not wall clock, so release builds stay reproducible
			GitCommit:   version.Commit,
			GoVersion:   runtime.Version(),
			OS:          runtime.GOOS,
			Arch:        runtime.GOARCH,
			Uptime:      time.Since(startTime).String(),
			Environment: cfg.Environment,
			Features: map[string]bool{
				"tls_enabled":        tlsEnabled,
				"auth_enabled":       true, // always on
				"audit_enabled":      true, // always on
				"metrics_enabled":    true,
				"grpc_enabled":       grpcEnabled,
				"encryption_enabled": encryptionEnabled,
				"rbac_enabled":       true, // always on
			},
			Database: DatabaseInfo{
				Type:      cfg.Storage.Type,
				Connected: true,
				Version:   "",
				Pool:      poolInfo(coreService),
			},
			Security: SecurityInfo{
				TLSEnabled:          tlsEnabled,
				AuthEnabled:         true,
				EncryptionMethod:    "AES-256-GCM",
				AuditEnabled:        true,
				KeylessRecoveryMode: cfg.Security.RecoverAdmin.KeylessMode,
				// Read from the already-loaded *config.Config, exactly like
				// KeylessRecoveryMode above -- no request body ever reaches
				// these values, which is what keeps the setting
				// config-file-only (ADR-112 Amendment 1; the guard is
				// TestInsecureAuditSkipDurableSync_NoWriteAssignment).
				AuditDurableSyncSkipped:               fastAuditStatus.InEffect,
				AccessLogOnSinkStall:                  cfg.Server.AccessLog.EffectiveOnSinkStall(),
				AccessLogDropped:                      middleware.AccessLogDropped(),
				AuditDurableSyncSkipNotInEffectReason: fastAuditStatus.NotInEffectReason,
				RecoveryKey:                           recoveryKeyStatus,
			},
		}

		sendSuccess(w, systemInfo, "")
	}
}

// GetMetrics handles GET /api/v1/system/metrics
func GetMetrics(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Get runtime memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get GC pause history (last 10 pauses)
	pauseNs := make([]uint64, 0, 10)
	for i := 0; i < len(memStats.PauseNs) && i < 10; i++ {
		if memStats.PauseNs[i] > 0 {
			pauseNs = append(pauseNs, memStats.PauseNs[i])
		}
	}

	metrics := SystemMetrics{
		Memory: MemoryMetrics{
			Alloc:        memStats.Alloc,
			TotalAlloc:   memStats.TotalAlloc,
			Sys:          memStats.Sys,
			Lookups:      memStats.Lookups,
			Mallocs:      memStats.Mallocs,
			Frees:        memStats.Frees,
			HeapAlloc:    memStats.HeapAlloc,
			HeapSys:      memStats.HeapSys,
			HeapIdle:     memStats.HeapIdle,
			HeapInuse:    memStats.HeapInuse,
			HeapReleased: memStats.HeapReleased,
			HeapObjects:  memStats.HeapObjects,
			StackInuse:   memStats.StackInuse,
			StackSys:     memStats.StackSys,
		},
		Goroutines: runtime.NumGoroutine(),
		GC: GCMetrics{
			NumGC:         memStats.NumGC,
			PauseTotal:    memStats.PauseTotalNs,
			PauseNs:       pauseNs,
			NextGC:        memStats.NextGC,
			LastGC:        memStats.LastGC,
			GCCPUFraction: memStats.GCCPUFraction,
		},
		// HTTP, Database, and Secrets counters are not instrumented in the HTTP
		// handler path. Use the Prometheus /metrics endpoint for real HTTP counters
		// and the gRPC GetMetrics call for domain-level counts. Returning zeros
		// here rather than fabricated values; previously these were hardcoded
		// constants that misled capacity-planning and incident-response consumers.
		HTTP:      HTTPMetrics{},
		Database:  DatabaseMetrics{},
		Secrets:   SecretsMetrics{},
		Uptime:    time.Since(startTime).String(),
		Timestamp: time.Now().UTC(),
	}

	sendSuccess(w, metrics, "")
}

// Helper functions are now in helpers.go
