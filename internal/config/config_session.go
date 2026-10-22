package config

import (
	"time"
)

// SessionConfig tunes session-token lifetimes for short-lived tokens with silent
// auto-refresh. Absent (zero value) keeps the backward-compatible behaviour: a 24h
// access window and no absolute ceiling (refreshable indefinitely). An install that
// wants short-lived tokens sets a short access_ttl plus an absolute_ttl ceiling and
// relies on the client to refresh silently before each access window lapses.
type SessionConfig struct {
	// AccessTTL is how long an issued access token is valid before it must be
	// refreshed (e.g. "30m"). Empty = DefaultAccessTTLString (24h).
	AccessTTL string `yaml:"access_ttl"`
	// AbsoluteTTL caps total session lifetime from login: refreshing the access
	// window can never extend a session past it (e.g. "12h"). Empty or "0" = no
	// ceiling, so a session can be refreshed indefinitely (legacy behaviour).
	AbsoluteTTL string `yaml:"absolute_ttl"`
}

// DefaultAccessTTLString is the fallback access-token lifetime. It matches the
// historic hard-coded 24h so an install that does not configure a session block
// keeps exactly the old behaviour (no un-refreshing client is logged out).
const DefaultAccessTTLString = "24h"

// GetAccessTTL parses AccessTTL, falling back to 24h when empty or invalid.
func (c *SessionConfig) GetAccessTTL() time.Duration {
	raw := c.AccessTTL
	if raw == "" {
		raw = DefaultAccessTTLString
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(DefaultAccessTTLString)
	}
	return d
}

// GetAbsoluteTTL parses AbsoluteTTL. Empty, "0", or an unparseable/non-positive
// value means "no ceiling" and returns 0 — sessions are then refreshable forever.
func (c *SessionConfig) GetAbsoluteTTL() time.Duration {
	if c.AbsoluteTTL == "" {
		return 0
	}
	d, err := time.ParseDuration(c.AbsoluteTTL)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}
