package main

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

// flushLastUsedOnShutdown writes the last-used stamps the core has recorded
// but not yet flushed (internal/core/last_used_coalescer.go). It is bounded by
// its own 10 s context, including the wait for a background flush that is
// stuck in a slow write.
func flushLastUsedOnShutdown(coreService *core.KeyorixCore) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	coreService.FlushLastUsed(ctx)
}

// closeAuditForwarder flushes/closes the wired SIEM audit forwarder (if any) on
// shutdown. core.AuditForwarder only declares Forward (core has no dependency
// on the concrete siem package), so the Close method is reached via a local
// interface rather than a direct type assertion to *siem.Forwarder.
func closeAuditForwarder(coreService *core.KeyorixCore) {
	type closer interface{ Close() }
	if cl, ok := coreService.AuditForwarder().(closer); ok {
		cl.Close()
	}
}
