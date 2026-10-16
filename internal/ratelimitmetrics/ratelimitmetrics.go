// Package ratelimitmetrics holds the one Prometheus counter for requests refused by
// a rate limiter, shared by the HTTP middleware and the gRPC interceptors (neither
// imports the other).
//
// A 429 already lands in keyorix_http_requests_total{status="429"}, but that cannot
// tell the per-principal API limiter (a client hammering the API) from the
// failed-token limiter (credential stuffing) and does not cover gRPC at all. The
// limiter label is a closed set (Limiter), never a caller-supplied value.
package ratelimitmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Limiter identifies which limiter refused a request. The set is closed.
type Limiter string

const (
	Principal            Limiter = "principal"               // HTTP per-user/machine/IP request budget
	TokenAuthFailure     Limiter = "token_auth_failure"      // HTTP per-IP failed-token budget
	GRPCPrincipal        Limiter = "grpc_principal"          // gRPC per-principal request budget
	GRPCTokenAuthFailure Limiter = "grpc_token_auth_failure" // gRPC per-IP failed-token budget
)

var rejectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_rate_limit_rejections_total",
	Help: "Requests refused by a rate limiter (HTTP 429 / gRPC ResourceExhausted), by limiter (principal|token_auth_failure|grpc_principal|grpc_token_auth_failure).",
}, []string{"limiter"})

func init() {
	// Pre-register every series so rate() and absent() see an explicit 0.
	for _, l := range []Limiter{Principal, TokenAuthFailure, GRPCPrincipal, GRPCTokenAuthFailure} {
		rejectionsTotal.WithLabelValues(string(l))
	}
}

// Reject counts one refused request.
func Reject(l Limiter) {
	rejectionsTotal.WithLabelValues(string(l)).Inc()
}
