package core

import (
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"gorm.io/gorm"
)

// ErrAuthStorageUnavailable is returned by ValidateSessionToken, ValidatePATToken,
// ValidateMachineToken and ValidateOIDCToken when a lookup they need (the
// credential row, the owning account, the machine identity) FAILED, as opposed to
// positively not existing. Like ErrRoleResolutionUnavailable it says nothing about
// the credential: the HTTP middleware answers 503 and the gRPC interceptors
// codes.Unavailable, without negative-caching the token and without charging the
// caller's source IP's brute-force budget.
//
// Before this, only the roles read had that treatment; every earlier lookup
// collapsed any storage error into the same opaque message as a bad credential, so
// a database outage (PostgreSQL restart, network cut) answered every valid machine
// token and session with 401, negative-cached each for invalidTokenTTL (so the 401s
// outlived the outage) and counted them as brute-force strikes against the callers'
// IPs. Found by scripts/drills/disaster.sh (pgdown), PROD-OPS-1.
//
// The underlying error is deliberately not wrapped in: its detail must not reach an
// unauthenticated caller.
var ErrAuthStorageUnavailable = errors.New("authentication storage temporarily unavailable")

// IsAuthTransient reports whether a Validate*Token failure was a storage fault the
// caller should retry (ErrAuthStorageUnavailable or ErrRoleResolutionUnavailable)
// rather than a verdict on the credential.
func IsAuthTransient(err error) bool {
	return errors.Is(err, ErrAuthStorageUnavailable) || errors.Is(err, ErrRoleResolutionUnavailable)
}

// credentialLookupError classifies a failed credential/account/identity lookup made
// by a Validate*Token function. A positive "no such row" keeps the caller-visible
// verdict message (the credential is bad); anything else (connection refused or
// reset, timeout, closed pool, ...) is a storage fault and becomes
// ErrAuthStorageUnavailable. Unknown errors are classified as faults on purpose:
// the request is denied either way, and a fault must never be cached as proof the
// token is invalid.
func credentialLookupError(err error, verdict string) error {
	if errors.Is(err, gorm.ErrRecordNotFound) || storage.IsSessionNotFound(err) || storage.IsUserNotFound(err) {
		return fmt.Errorf("%s", verdict)
	}
	return ErrAuthStorageUnavailable
}
