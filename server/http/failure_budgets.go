package http

import "time"

// Failure budgets for the two public routes that check a static secret and have no
// per-account lockout behind them (customMiddleware.FailureBudget). Only a rejected
// secret spends the budget, so a caller that holds the secret is never throttled.
const (
	// POST /system/init checks the bootstrap token (403 on a wrong one) until the
	// system is initialised. An operator-pinned KEYORIX_BOOTSTRAP_TOKEN can be a
	// guessable phrase, and every attempt takes the cluster-wide bootstrap lock.
	bootstrapFailureBurst  = 5
	bootstrapFailureRefill = 30 * time.Second
	// GET /metrics checks server.http.metrics_token (401 on a wrong one).
	metricsFailureBurst  = 10
	metricsFailureRefill = 6 * time.Second
)
