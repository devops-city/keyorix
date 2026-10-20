package handlers

import (
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SessionSummary mirrors config.SessionConfig, using the effective
// (defaulted) TTLs rather than the possibly-empty raw YAML strings.
type SessionSummary struct {
	AccessTTL   string `json:"access_ttl"`
	AbsoluteTTL string `json:"absolute_ttl"`
}

// PasswordPolicySummary mirrors config.PasswordPolicyConfig verbatim — none
// of its fields are sensitive.
type PasswordPolicySummary struct {
	MinLength             int  `json:"min_length"`
	RequireUppercase      bool `json:"require_uppercase"`
	RequireLowercase      bool `json:"require_lowercase"`
	RequireDigit          bool `json:"require_digit"`
	RequireSpecial        bool `json:"require_special"`
	RejectPersonalInfo    bool `json:"reject_personal_info"`
	RejectCommonPasswords bool `json:"reject_common_passwords"`
	HistoryCount          int  `json:"history_count"`
	MaxAgeDays            int  `json:"max_age_days"`
}

// LoginLockoutSummary reports the EFFECTIVE lockout state, not the raw
// config.LoginLockoutConfig.Enabled field — lockout is on by default and
// Disabled is the actual opt-out (see config.go's own comment on
// LoginLockoutConfig), so Enabled here is computed as !cfg.Disabled.
type LoginLockoutSummary struct {
	Enabled      bool   `json:"enabled"`
	MaxAttempts  int    `json:"max_attempts"`
	Window       string `json:"window"`
	BaseCooldown string `json:"base_cooldown"`
	MaxCooldown  string `json:"max_cooldown"`
}

// WebAuthnSummary mirrors config.WebAuthnConfig verbatim — public
// relying-party metadata, nothing sensitive.
type WebAuthnSummary struct {
	Enabled       bool     `json:"enabled"`
	RPID          string   `json:"rp_id"`
	RPDisplayName string   `json:"rp_display_name"`
	RPOrigins     []string `json:"rp_origins"`
}

// SSOProviderSummary is a deliberately narrow view of config.SSOProviderConfig:
// it excludes Issuer, ClientID, ClientSecret, RedirectURL, Scopes,
// DefaultRole, GroupsClaim, GroupRoleMap, and the entire SAML block (which
// embeds the IdP's signing certificate) — none of that belongs in an HTTP
// response. Mirrors the redaction precedent in sso.go's ListSSOProviders,
// which never marshals SSOProviderConfig directly for the same reason.
type SSOProviderSummary struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	AutoProvision bool   `json:"auto_provision"`
	GroupSync     bool   `json:"group_sync"`
}

type SSOSummary struct {
	Enabled   bool                 `json:"enabled"`
	Providers []SSOProviderSummary `json:"providers"`
}

// AuthConfigResponse is the response body for GET /api/v1/system/auth-config.
type AuthConfigResponse struct {
	Session        SessionSummary        `json:"session"`
	PasswordPolicy PasswordPolicySummary `json:"password_policy"`
	LoginLockout   LoginLockoutSummary   `json:"login_lockout"`
	// RequireMFA is whether security.require_mfa is in force right now: false
	// while ADR-112's upgrade grace period runs (RequireMFAGrace says until when).
	RequireMFA bool `json:"require_mfa"`
	// RequireMFAGrace is the running require_mfa upgrade grace period (#2923),
	// omitted when there is none.
	RequireMFAGrace *MFAGraceSummary `json:"require_mfa_grace,omitempty"`
	WebAuthn        WebAuthnSummary  `json:"webauthn"`
	SSO             SSOSummary       `json:"sso"`
}

// MakeAuthConfigHandler returns a handler serving a read-only, redacted
// summary of the server's authentication configuration (session TTLs,
// password policy, login lockout, MFA/WebAuthn/SSO settings). No secrets —
// SSO client secrets, SAML metadata, and per-provider OIDC details are
// deliberately excluded.
func MakeAuthConfigHandler(cfg *config.Config) http.HandlerFunc {
	return MakeAuthConfigHandlerLive(cfg, nil)
}

// MakeAuthConfigHandlerLive is MakeAuthConfigHandler reporting require_mfa as
// coreService enforces it at request time (ADR-112's upgrade grace period,
// #2923, ends while the server runs). A nil coreService reports the config.
func MakeAuthConfigHandlerLive(cfg *config.Config, coreService *core.KeyorixCore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx := middleware.GetUserFromContext(r.Context())
		if userCtx == nil {
			sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
			return
		}

		// #G37: report the EFFECTIVE (defaults-merged) password policy, matching
		// server/main.go's resolvePasswordPolicy — a partial password_policy block
		// must not be summarized as if it zeroed out every rule it didn't mention.
		d := core.DefaultPasswordPolicy()
		resolvedPP := cfg.PasswordPolicy.Resolve(config.PasswordPolicyValues{
			MinLength:             d.MinLength,
			RequireUppercase:      d.RequireUppercase,
			RequireLowercase:      d.RequireLowercase,
			RequireDigit:          d.RequireDigit,
			RequireSpecial:        d.RequireSpecial,
			RejectPersonalInfo:    d.RejectPersonalInfo,
			RejectCommonPasswords: d.RejectCommonPasswords,
			HistoryCount:          d.HistoryCount,
			MaxAgeDays:            d.MaxAgeDays,
		})

		ll := cfg.Security.LoginLockout
		providers := make([]SSOProviderSummary, 0, len(cfg.SSO.Providers))
		for _, p := range cfg.SSO.Providers {
			providers = append(providers, SSOProviderSummary{
				Name:          p.Name,
				Type:          p.Type,
				AutoProvision: p.AutoProvision,
				GroupSync:     p.GroupSync,
			})
		}

		resp := AuthConfigResponse{
			Session: SessionSummary{
				AccessTTL:   cfg.Session.GetAccessTTL().String(),
				AbsoluteTTL: cfg.Session.GetAbsoluteTTL().String(),
			},
			PasswordPolicy: PasswordPolicySummary{
				MinLength:             resolvedPP.MinLength,
				RequireUppercase:      resolvedPP.RequireUppercase,
				RequireLowercase:      resolvedPP.RequireLowercase,
				RequireDigit:          resolvedPP.RequireDigit,
				RequireSpecial:        resolvedPP.RequireSpecial,
				RejectPersonalInfo:    resolvedPP.RejectPersonalInfo,
				RejectCommonPasswords: resolvedPP.RejectCommonPasswords,
				HistoryCount:          resolvedPP.HistoryCount,
				MaxAgeDays:            resolvedPP.MaxAgeDays,
			},
			LoginLockout: LoginLockoutSummary{
				Enabled:      !ll.Disabled,
				MaxAttempts:  ll.GetMaxAttempts(),
				Window:       ll.GetWindow().String(),
				BaseCooldown: ll.GetBaseCooldown().String(),
				MaxCooldown:  ll.GetMaxCooldown().String(),
			},
			RequireMFA: cfg.Security.RequireMFA,
			WebAuthn: WebAuthnSummary{
				Enabled:       cfg.WebAuthn.Enabled,
				RPID:          cfg.WebAuthn.RPID,
				RPDisplayName: cfg.WebAuthn.RPDisplayName,
				RPOrigins:     cfg.WebAuthn.RPOrigins,
			},
			SSO: SSOSummary{
				Enabled:   cfg.SSO.Enabled,
				Providers: providers,
			},
		}
		if coreService != nil {
			resp.RequireMFA = coreService.MFARequired()
			resp.RequireMFAGrace = mfaGraceSummary(coreService)
		}

		sendSuccess(w, resp, "")
	}
}

// MFAGraceSummary is a running ADR-112 require_mfa upgrade grace period
// (#2923): MFA is not enforced until EndsAt (RFC 3339), or until the first
// administrator enrols a second factor if that comes first. DaysLeft is the
// whole days left, rounded up. Clients show it as a persistent banner to users
// without a second factor: when it ends they are sent to MFA enrolment.
type MFAGraceSummary struct {
	EndsAt   string `json:"ends_at"`
	DaysLeft int    `json:"days_left"`
}

// mfaGraceSummary is coreService's running grace period, nil when none.
func mfaGraceSummary(coreService *core.KeyorixCore) *MFAGraceSummary {
	st, ok := coreService.MFAUpgradeGraceStatus()
	if !ok {
		return nil
	}
	return &MFAGraceSummary{EndsAt: st.EndsAt.UTC().Format(time.RFC3339), DaysLeft: st.DaysLeft}
}

// KeyProviderSummary is a deliberately narrow view of config.KeyProviderConfig:
// it excludes FilePath, WrappedKeyPath, ExecCommand, ShamirShareFiles,
// ShamirShareEnv, TPMDevice (all disclose exact filesystem/command locations
// of key material), EnvVar (names the env var holding raw key material), and
// KMSKeyID/KMSEncryptionContext (cloud resource identifiers with no
// legitimate need to be exposed here). ShamirCommitment is safe to expose —
// it's a one-way HMAC commitment that reveals nothing about the KEK itself
// (see the field's own doc comment in config.go).
type KeyProviderSummary struct {
	Type             string `json:"type"`
	ShamirCommitment string `json:"shamir_commitment,omitempty"`
	FallbackCount    int    `json:"fallback_count"`
}

// EncryptionConfigResponse is the response body for GET /api/v1/system/encryption-config.
type EncryptionConfigResponse struct {
	Enabled     bool               `json:"enabled"`
	KeyProvider KeyProviderSummary `json:"key_provider"`
}

// MakeEncryptionConfigHandler returns a handler serving a read-only,
// redacted summary of the server's encryption configuration: whether
// envelope encryption is enabled and the KEK provider type. Key material
// locations (file paths, exec commands, env var names, KMS key IDs) are
// deliberately excluded.
func MakeEncryptionConfigHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx := middleware.GetUserFromContext(r.Context())
		if userCtx == nil {
			sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
			return
		}

		kp := cfg.Storage.Encryption.KeyProvider
		resp := EncryptionConfigResponse{
			Enabled: cfg.Storage.Encryption.Enabled,
			KeyProvider: KeyProviderSummary{
				Type:             kp.Type,
				ShamirCommitment: kp.ShamirCommitment,
				FallbackCount:    len(kp.Fallbacks),
			},
		}

		sendSuccess(w, resp, "")
	}
}
