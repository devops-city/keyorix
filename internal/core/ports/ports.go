// Package ports defines the interfaces ADR-109
// (docs/adr-109-core-depends-on-interfaces.md) puts between internal/core and
// the integration packages it currently imports directly: internal/connect,
// internal/rotation, internal/dynamic, internal/encryption, internal/notary,
// internal/saml. Each interface here is modeled on the exact subset of
// methods internal/core already calls on today's concrete type — see the
// doc comment on each one for which type it mirrors and which core files
// call it.
//
// Each ADR-109 "Order of work" step swaps one integration from its concrete
// package type to the interface here, and wires the real implementation from
// server/main.go's DefaultIntegrations instead — see internal/core's own
// dependency_guard_test.go, whose allowlist shrinks by one entry per
// completed step. notary and saml are wired as of step 1, rotation as of
// step 2, dynamic as of step 3, connect as of step 4, encryption as of step
// 5 — coreIntegrationDeps is empty from step 5 onward, machine-checked by
// TestCoreIntegrationDepsAllowlistIsEmpty.
//
// This package must never import an integration package itself, or any of
// their cloud SDKs — that would silently defeat the whole point. See
// ports_deps_test.go.
package ports

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Connector reads a secret value from one external store. A type alias of
// internal/connect.Connector (ADR-109 step 4) — the alias lives on the
// internal/connect side (see that package's doc comment) so every existing
// connector implementation (AWS Secrets Manager, Azure Key Vault, GCP Secret
// Manager, Vault) satisfies this directly, with no adapter.
// internal/core.ReadFederatedSecret (connect.go) calls only these three
// methods on the value internal/connect.Manager.Get returns.
type Connector interface {
	Name() string
	Type() string
	GetSecret(ctx context.Context, ref string) (string, error)
}

// ConnectorResolver resolves a configured Keyorix Connect connector by name.
// Mirrors internal/connect.Manager (a concrete type, not aliased — only the
// element type it returns is, same shape as RotationExecutorResolver/
// internal/rotation.Manager), the only methods internal/core calls on it
// (connect.go, service.go).
type ConnectorResolver interface {
	Get(name string) (Connector, bool)
	Names() []string
}

// RefHasDotSegment reports whether ref contains a "." or ".." path segment.
// A type alias target of internal/connect.RefHasDotSegment (ADR-109 step 4)
// — the implementation lives here so internal/core.refMatches (connect.go)
// can apply the same traversal guard internal/connect's own per-reference
// allowlist (prefixAllowed) uses, without importing internal/connect. See
// internal/connect/connect.go's own doc comment on RefHasDotSegment for the
// full rationale.
func RefHasDotSegment(ref string) bool {
	for seg := range strings.SplitSeq(ref, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// RefWithinPrefix reports whether ref is scoped by prefix p on a
// path-segment boundary rather than a bare substring match: ref must equal p
// exactly, or extend it starting with '/'. A type alias target of
// internal/connect.RefWithinPrefix (ADR-109 step 4) — see that function's
// doc comment for the full rationale. An empty prefix p matches nothing (use
// a separate empty-prefix guard to mean "allow all").
func RefWithinPrefix(p, ref string) bool {
	if ref == p {
		return true
	}
	if !strings.HasPrefix(ref, p) {
		return false
	}
	if strings.HasSuffix(p, "/") {
		return true
	}
	return ref[len(p)] == '/'
}

// RotationExecutor applies a new credential to an upstream system during
// rotation. A type alias of internal/rotation.Executor (ADR-109 step 2) — the
// alias lives on the internal/rotation side (see that package's doc comment)
// so every existing rotation.Executor implementation satisfies this directly,
// with no adapter.
type RotationExecutor interface {
	Name() string
	Type() string
	Rotate(ctx context.Context, ref, newValue string) error
}

// GeneratingRotationExecutor is a RotationExecutor whose upstream mints the
// new value itself (e.g. a cloud key API). Mirrors (and, as of ADR-109 step 2,
// aliased by) internal/rotation.GeneratingExecutor — rotation_executor.go
// type-asserts a resolved RotationExecutor against this to prefer
// GenerateUpstream over Rotate when the backend supports it.
type GeneratingRotationExecutor interface {
	RotationExecutor
	GenerateUpstream(ctx context.Context, ref string) (string, error)
}

// RotationExecutorResolver resolves a configured rotation backend by name.
// Mirrors internal/rotation.Manager (a concrete type, not aliased — only the
// element types it returns are), the only methods internal/core calls on it
// (rotation_executor.go, rotation_dryrun.go, service.go).
type RotationExecutorResolver interface {
	Get(name string) (RotationExecutor, bool)
	Names() []string
}

// RotationPartialError reports that a RotationExecutor's upstream minted a new
// credential (Value is the value to store in Keyorix) but a follow-up step
// failed — typically a prior, possibly compromised credential that could not
// be deleted. A type alias of internal/rotation.PartialRotationError (ADR-109
// step 2); its Error()/Unwrap() methods are declared here, alongside the
// canonical type, since a type alias cannot carry methods of its own —
// internal/rotation's own doc comment on PartialRotationError has the full
// rationale for why Value must still be stored.
type RotationPartialError struct {
	Value string
	Err   error
}

func (e *RotationPartialError) Error() string { return e.Err.Error() }
func (e *RotationPartialError) Unwrap() error { return e.Err }

// DynamicCredential is an issued, short-lived credential returned to the
// caller once. A type alias of internal/dynamic.Credential (ADR-109 step 3) —
// the alias lives on the internal/dynamic side (see that package's doc
// comment) so every backend engine's existing Issue implementation satisfies
// DynamicBackendEngine directly, with no adapter. JSON tags are preserved
// (rather than dropped, as a fresh struct here would) since dynamic_secrets.go's
// IssueLease marshals a DynamicCredential to encrypt it at rest — the shape of
// that JSON must not silently change underneath an existing encrypted blob.
type DynamicCredential struct {
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// DynamicBackendEngine mints and revokes credentials on a target backend. A
// type alias of internal/dynamic.CredentialEngine (ADR-109 step 3) — every
// method here is one internal/core actually calls (dynamic_secrets.go).
type DynamicBackendEngine interface {
	Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (cred DynamicCredential, roleName string, err error)
	Revoke(ctx context.Context, adminDSN, roleName string) error
	Renew(ctx context.Context, adminDSN, roleName string, expiresAt time.Time) error
	SupportsNativeExpiry() bool
	BackendType() string
	IsEphemeralBackend() bool
	// RevokeInvalidatesCredential reports whether Revoke for this adminDSN
	// actually invalidates the credential at the provider (vs. only local
	// Keyorix bookkeeping) — RevokeLease uses it to render an accurate audit
	// message. See internal/dynamic.CredentialEngine's doc comment on this
	// method for the full per-backend breakdown.
	RevokeInvalidatesCredential(adminDSN string) bool
}

// DynamicBackendFactory resolves a DynamicBackendEngine for the named backend
// type. A plain function type — not an interface with an Engine method — since
// that's the exact shape internal/core.dynamicEngineFactory already holds
// (service.go, SetDynamicEngineFactory): a closure, not an object with a
// method, backed by internal/dynamic.New in production. Mirrors
// ports.VerifyReceiptFunc's reasoning (ADR-109 step 1): wire the shape core
// actually uses, not a heavier abstraction it doesn't need.
type DynamicBackendFactory func(backendType string) (DynamicBackendEngine, error)

// dsnUserinfoPattern matches the userinfo component of a URL-style connection
// string -- scheme://user:password@host... -- as produced by postgres://,
// mysql://, mongodb://, redis://, rediss:// DSNs. It matches greedily up to
// the LAST '@' before the next whitespace so a password containing an
// unescaped '@' -- or, critically, an unescaped '/' -- doesn't leave a
// residual fragment or bypass the match entirely.
var dsnUserinfoPattern = regexp.MustCompile(`://[^\s]*@`)

// bareUserinfoPattern matches a "user:password@" credential fragment with NO
// scheme prefix -- go-sql-driver/mysql's native DSN format
// ("user:pass@tcp(host:3306)/db") never has a "://" scheme at all, so
// dsnUserinfoPattern alone never matches it; the same bare shape also appears
// in generic dial/DNS error text ("dial tcp: lookup admin:hunter2@db.internal").
// Runs after dsnUserinfoPattern, which has already consumed and replaced every
// scheme-prefixed occurrence.
var bareUserinfoPattern = regexp.MustCompile(`[^\s:@/]+:[^\s@]+@`)

// kvCredentialPattern matches key=value pairs whose key names a credential
// field, case-insensitively, in the ODBC/connection-string style
// ("Server=...;Uid=admin;Pwd=hunter2;") or a URL query string
// ("...&password=hunter2"). The value is everything up to the next
// delimiter (';', '&', whitespace) or end of string.
var kvCredentialPattern = regexp.MustCompile(`(?i)\b(password|pwd|passwd|secret|token|access_key_id|access_key|secret_access_key|session_token|api_key|apikey|auth)\s*=\s*[^;&\s]+`)

// redactedPlaceholder replaces any credential fragment the patterns above
// recognize.
const redactedPlaceholder = "***REDACTED***"

// RedactSensitive strips connection-string/DSN credential fragments (URL
// userinfo, ODBC/query-string key=value credential fields) from s. It is a
// defense-in-depth text filter, not a parser or a guarantee. A type alias
// target of internal/dynamic.RedactSensitive (ADR-109 step 3) — the
// implementation lives here so internal/core can sanitize a dynamic-secrets
// backend error before logging it (dynamic_secrets.go) without importing
// internal/dynamic; see that package's redact.go for the full rationale and
// its own re-export.
func RedactSensitive(s string) string {
	s = dsnUserinfoPattern.ReplaceAllString(s, "://"+redactedPlaceholder+"@")
	s = bareUserinfoPattern.ReplaceAllString(s, redactedPlaceholder+"@")
	s = kvCredentialPattern.ReplaceAllStringFunc(s, func(m string) string {
		if idx := strings.IndexByte(m, '='); idx >= 0 {
			return m[:idx+1] + redactedPlaceholder
		}
		return m
	})
	return s
}

// SanitizeErrorMessage returns err's Error() text with RedactSensitive
// applied, safe to pass to log.Printf/log.Println. See RedactSensitive's doc
// comment and internal/dynamic/redact.go for the full rationale.
func SanitizeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return RedactSensitive(err.Error())
}

// EncryptionProvider performs authenticated encryption/decryption for secret
// values and auth-flow secrets (MFA, dynamic-secret admin DSNs and leases).
// Mirrors internal/encryption.Service — the ONLY four methods internal/core
// calls on it, across secret_value_crypto.go, mfa.go, dynamic_secrets.go,
// secret_render.go and service.go's authEncryptor/secretValueEncryptor
// helpers. AAD is built by the caller (SecretAAD and siblings below) and
// passed through opaquely — this interface has no opinion on how AAD is
// constructed. Unlike every other ADR-109 integration, *internal/encryption.
// Service (ADR-109 step 5) needs no type alias to satisfy this: its four
// methods already have this exact signature, so it satisfies
// EncryptionProvider structurally, with no change to internal/encryption
// itself.
type EncryptionProvider interface {
	IsEnabled() bool
	IsInitialized() bool
	EncryptSecretWithAAD(plaintext, aad []byte) (ciphertext, meta []byte, err error)
	DecryptSecretWithAAD(ciphertext, aad []byte) (plaintext []byte, err error)
}

// SecretAAD returns the canonical Additional Authenticated Data for a secret
// version. Format: "keyorix:v2:<secretID>:<projectID>:<versionNumber>". This
// binds the ciphertext to a specific secret + project + version, preventing
// ciphertext transplant attacks (copying an encrypted value between rows). A
// type alias target of internal/encryption.SecretAAD (ADR-109 step 5, small,
// pure, stdlib-only) so internal/core.encryptVersionValue/decryptVersionValue
// (secret_value_crypto.go) can build it without importing internal/encryption;
// see that package's own re-export for the same two-line-re-export rationale
// steps 1–4 already established for their own AAD/redaction helpers.
func SecretAAD(secretID, projectID uint, versionNumber int) []byte {
	return []byte(fmt.Sprintf("keyorix:v2:%d:%d:%d", secretID, projectID, versionNumber))
}

// MFASecretAAD returns the AAD for a user's encrypted TOTP shared secret
// (#94), binding the ciphertext to the owning user so a DB-write attacker
// cannot transplant one user's encrypted TOTP seed onto another user's row.
// A type alias target of internal/encryption.MFASecretAAD (ADR-109 step 5) —
// see mfa.go's BeginMFAEnrollment/VerifyMFALogin for the call sites.
func MFASecretAAD(userID uint) []byte {
	return []byte(fmt.Sprintf("keyorix:mfa:v1:%d", userID))
}

// DynamicSecretConfigAAD returns the AAD for a dynamic-secret config's
// encrypted admin DSN (#94), binding the ciphertext to the config's identity
// and project/environment scope. A type alias target of
// internal/encryption.DynamicSecretConfigAAD (ADR-109 step 5) — see
// dynamic_secrets.go's call sites.
func DynamicSecretConfigAAD(configID, projectID, environmentID uint) []byte {
	return []byte(fmt.Sprintf("keyorix:dynsecret-config:v1:%d:%d:%d", configID, projectID, environmentID))
}

// DynamicSecretLeaseAAD returns the AAD for an issued dynamic-secret lease's
// encrypted credential (#94), binding the ciphertext to the lease's identity
// and owning config. A type alias target of
// internal/encryption.DynamicSecretLeaseAAD (ADR-109 step 5) — see
// dynamic_secrets.go's IssueLease.
func DynamicSecretLeaseAAD(leaseID string, configID uint) []byte {
	return []byte(fmt.Sprintf("keyorix:dynsecret-lease:v1:%s:%d", leaseID, configID))
}

// NotificationChannelURLAAD returns the AAD for a notification channel's
// encrypted webhook/Slack/Teams URL (#2433), binding the ciphertext to the
// channel's identity so a DB-write attacker cannot transplant one channel's
// encrypted URL onto another's row.
func NotificationChannelURLAAD(channelID uint) []byte {
	return []byte(fmt.Sprintf("keyorix:notifchan-url:v1:%d", channelID))
}

// NotaryReceipt is proof an external timestamping authority anchored a
// message. Mirrors internal/notary.Receipt.
type NotaryReceipt struct {
	Token    []byte
	Time     time.Time
	Provider string
}

// TimestampNotary anchors a message with an external timestamping authority.
// Mirrors internal/notary.Notary — audit_checkpoint.go's checkpointNotary
// field. Receipt verification (internal/notary.VerifyReceipt) is a separate
// free function, not a TimestampNotary method — see VerifyReceiptFunc below.
type TimestampNotary interface {
	Anchor(ctx context.Context, message []byte) (*NotaryReceipt, error)
	Provider() string
}

// VerifyReceiptFunc re-checks a TimestampNotary receipt token against a trusted
// root pool and the original anchored message, returning the authority-asserted
// time. Mirrors internal/notary.VerifyReceipt exactly — it stays a free function,
// not a TimestampNotary method, since verifying a receipt depends only on the
// configured trust roots, not on which Notary produced it (see
// audit_checkpoint.go's VerifyCheckpointAnchor). Wired alongside TimestampNotary
// at startup (SetCheckpointAnchorRoots); nil means stored anchors cannot be
// locally re-verified — fails closed rather than asserting an unverifiable proof.
type VerifyReceiptFunc func(roots *x509.CertPool, message, token []byte) (time.Time, error)

// SAMLAssertion is the parsed content of a SAML response Keyorix has
// verified. Mirrors internal/saml.AssertionInfo, the fields sso.go reads off
// it.
type SAMLAssertion struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// GroupsPresent reports that the assertion carried the configured groups
	// attribute at all, even with no (non-blank) values. It is what tells "the
	// IdP asserts this user is in NO groups" (reconcile to zero, removing stale
	// memberships) apart from "the IdP did not send a groups attribute" (leave
	// memberships untouched) -- the SAML counterpart of the OIDC path's
	// `present` bool from extractTokenStringList. A non-empty Groups implies
	// presence whatever this field says, so a producer that predates it can
	// never make a non-empty assertion look absent.
	GroupsPresent bool
}

// SAMLServiceProvider is a SAML Service Provider. Mirrors the shape
// internal/core/sso.go's own SAMLAuthn used to have (it predates this
// package) — ADR-109 step 1 made SAMLAuthn a type alias of this interface,
// and internal/saml.AssertionInfo a type alias of SAMLAssertion, so
// *internal/saml.Provider satisfies this interface directly with no adapter.
type SAMLServiceProvider interface {
	AuthnRequest(relayState string) (redirectURL, requestID string, err error)
	ParseResponse(r *http.Request, possibleRequestIDs []string) (*SAMLAssertion, error)
	Metadata() ([]byte, error)
}
