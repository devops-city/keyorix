package main

import (
	"log"

	"github.com/keyorixhq/keyorix/internal/core"
)

// wireAuthRateLimitFallback is a core wiring step (coreWiringSteps in main.go).
func wireAuthRateLimitFallback(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// The auth rate limits' in-memory fallback is per process; divide its limits
	// by the replicas sharing the budgets (ADR-040 amendment, AUTH-AUDIT-1).
	coreService.SetAuthRateLimitFallbackReplicas(cfg.Security.AuthRateLimitFallback.GetReplicas())
	log.Printf("Auth rate-limit storage fallback: limits divided by %d replica(s)", cfg.Security.AuthRateLimitFallback.GetReplicas())
	return nil
}

// wireOneTimePasswordExpiry is a core wiring step (coreWiringSteps in main.go).
func wireOneTimePasswordExpiry(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Admin-created one-time passwords expire (OTP-EXPIRY-1); the recover-admin
	// password's lifetime is read by that command itself, from the same section.
	coreService.SetOneTimePasswordExpiry(cfg.Security.GetOneTimePasswordExpiry())
	return nil
}

// wireLoginLockout is a core wiring step (coreWiringSteps in main.go).
func wireLoginLockout(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Apply per-account login lockout (brute-force protection, distinct from and
	// complementary to the per-IP rate limiter, which distributed guessing can evade).
	// Enabled BY DEFAULT — a secrets-manager login must resist online guessing out of
	// the box; set login_lockout.insecure_disable_login_lockout to opt out.
	if ll := cfg.Security.LoginLockout; !ll.Disabled {
		coreService.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
			Enabled:      true,
			MaxAttempts:  ll.GetMaxAttempts(),
			Window:       ll.GetWindow(),
			BaseCooldown: ll.GetBaseCooldown(),
			MaxCooldown:  ll.GetMaxCooldown(),
		})
		log.Printf("Per-account login lockout enabled (max_attempts=%d, window=%s, base_cooldown=%s, max_cooldown=%s)",
			ll.GetMaxAttempts(), ll.GetWindow(), ll.GetBaseCooldown(), ll.GetMaxCooldown())
	} else {
		log.Printf("WARNING: per-account login lockout is DISABLED — only the per-IP rate limiter throttles password guessing, which distributed/botnet guessing against a single account can evade")
	}
	return nil
}
