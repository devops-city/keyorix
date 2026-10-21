package main

import (
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/startup"
)

// wireAccessLogStallNotice is a core wiring step (coreWiringSteps in main.go).
func wireAccessLogStallNotice(cw *coreWiring) error {
	cfg := cw.cfg
	// Access-log stall mode (server.access_log.on_sink_stall): always reported at
	// startup so the effective mode is visible; "drop" is a WARNING.
	if mode := cfg.Server.AccessLog.EffectiveOnSinkStall(); mode == config.AccessLogOnSinkStallDrop {
		log.Printf("WARNING: %s", startup.AccessLogDropModeWarning)
	} else {
		log.Printf("access log: server.access_log.on_sink_stall=%s (no line is dropped; requests wait for a stalled sink)", mode)
	}
	return nil
}

// wireSCIMJITNotice is a core wiring step (coreWiringSteps in main.go).
func wireSCIMJITNotice(cw *coreWiring) error {
	cfg := cw.cfg
	// SCIM + SSO JIT on one install: JIT-created accounts are not SCIM-managed.
	if w := config.SCIMJITUnmanagedWarning(cfg.SCIMJITUnmanagedProviders()); w != "" {
		log.Print(w)
	}
	return nil
}
