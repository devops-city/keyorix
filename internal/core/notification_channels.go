// notification_channels.go — runtime CRUD for outbound notification channels.
// Channels are DB-backed destinations (webhook/slack/teams/email) that can be
// managed at runtime without editing config files.
package core

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/netutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// validChannelTypes is the set of accepted channel type values.
var validChannelTypes = map[string]struct{}{
	"webhook": {},
	"slack":   {},
	"teams":   {},
	"email":   {},
}

// Notification channel audit event types -- see config_change_audit.go for the
// shared writer. An admin repointing/disabling where alerts are delivered is
// the same threat shape as disabling anomaly detection (anomaly_config.go):
// silently remove the alarm, then act.
const (
	EventNotificationChannelCreated = "notification_channel.created"
	EventNotificationChannelUpdated = "notification_channel.updated"
	EventNotificationChannelDeleted = "notification_channel.deleted"
)

// ListNotificationChannels returns all configured notification channels, with
// each channel's URL decrypted (#2433) so every existing caller (the HTTP
// handler, alert dispatch in alert_escalation.go/recover_admin_alert.go) keeps
// reading ch.URL as a plain string, unaware encryption is involved. Fails
// closed: if even one row's URL cannot be decrypted, the whole call errors
// rather than returning a partial list with ciphertext masquerading as a URL.
func (c *KeyorixCore) ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error) {
	rows, err := c.storage.ListNotificationChannels(ctx)
	if err != nil {
		return nil, err
	}
	for _, ch := range rows {
		if err := c.decryptNotificationChannelURL(ch); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// GetNotificationChannel returns the channel with the given id, with its URL
// decrypted (#2433) — see ListNotificationChannels' doc comment.
func (c *KeyorixCore) GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error) {
	ch, err := c.storage.GetNotificationChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.decryptNotificationChannelURL(ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// decryptNotificationChannelURL populates ch.URL from ch.URLEnc/ch.URLMeta,
// fail-closed: an undecryptable row is returned as an error, never as if
// ch.URLEnc's raw bytes were themselves a usable URL.
//
// url_enc is self-describing (ports.UnwrapNotificationChannelURL), so this
// never has to guess which form the stored bytes are in — the three cases are
// the three defects #2468's coordinator review found, each now explicit:
//
//   - Absent (empty/NULL column): the row has NO URL. Legitimate for an
//     `email` channel, and for any row an upgrading install's backfill has not
//     reached yet. Reads back as the empty string. Feeding those zero bytes to
//     the decryptor is what used to fail the entire fail-closed list over one
//     URL-less email channel.
//   - Plaintext: written while encryption was off, or still awaiting the
//     backfill that enables it. Returned as-is, no decrypt attempted — but ONLY
//     while encryption is off. See the tag-downgrade refusal below.
//   - Encrypted: a real envelope. Refused outright when no encryptor is wired,
//     rather than letting decryptAuthSecret's passthrough branch hand the
//     caller the envelope JSON AS the URL for alert dispatch to then dial.
//     Also refused when the envelope declares no AAD version — see the
//     decryption-oracle refusal below.
//
// Round 2 of #2468's review found that the format tag, on its own, still let a
// DB-WRITE attacker (a compromised replica, a restored backup, SQL injection
// elsewhere, a DBA — someone who can write the row but does NOT hold the DEK)
// steer this column two ways. Both are closed here:
//
//   - TAG DOWNGRADE. A plaintext tag was accepted unconditionally, so an
//     attacker could overwrite a channel's envelope with a plaintext URL of
//     their choosing and redirect every alert for that channel. Plaintext
//     carries no AAD, so nothing bound it to the channel at all — and the next
//     startup backfill would then ENCRYPT the planted URL, laundering it into
//     a properly-bound envelope and destroying the evidence. Refused whenever
//     encryption is active, which costs nothing legitimate: the CRUD paths only
//     ever write an envelope in that state, and the startup backfill refuses to
//     complete (hence refuses to start the server) while any plaintext row
//     remains — see MigrateNotificationChannelURLsToEncrypted's own
//     no-plaintext-left verification. A URL-less channel is tag Absent, not
//     tag Plaintext, so the email-channel case this PR already fixed is
//     untouched.
//
//   - NO-AAD DECRYPTION ORACLE. Service.DecryptSecretWithAAD falls back to a
//     no-AAD decrypt when the envelope's aad_version is empty, for rows
//     predating #94. url_enc is new in this PR, so it has NO legitimate
//     pre-AAD rows — and the attacker writes the metadata that decides whether
//     AAD is checked, so they could paste ANY old non-AAD ciphertext from
//     elsewhere in the database into url_enc and read its plaintext back out of
//     GET /notification-channels. The AAD binding was sound but bypassable;
//     requiring aad_version makes it load-bearing.
func (c *KeyorixCore) decryptNotificationChannelURL(ch *models.NotificationChannel) error {
	tag, payload, err := ports.UnwrapNotificationChannelURL(ch.URLEnc)
	if err != nil {
		return fmt.Errorf("notification channel %d: %w", ch.ID, err)
	}
	switch tag {
	case ports.NotificationChannelURLTagAbsent:
		ch.URL = ""
		return nil
	case ports.NotificationChannelURLTagPlaintext:
		if c.AuthEncryptionActive() {
			return fmt.Errorf("notification channel %d URL is stored unencrypted while encryption is active: refusing it (no legitimate write path produces this, and an unencrypted URL carries no binding to the channel)", ch.ID)
		}
		ch.URL = string(payload)
		return nil
	default: // ports.NotificationChannelURLTagEncrypted -- Unwrap admits no other value
		if !c.AuthEncryptionActive() {
			return fmt.Errorf("notification channel %d URL is encrypted at rest but encryption is disabled: refusing to return the stored envelope as a URL", ch.ID)
		}
		aadBound, aerr := ports.NotificationChannelURLEnvelopeIsAADBound(payload)
		if aerr != nil {
			return fmt.Errorf("notification channel %d: %w", ch.ID, aerr)
		}
		if !aadBound {
			return fmt.Errorf("notification channel %d URL envelope declares no AAD version: refusing it (this column has no legitimate pre-AAD rows, so a no-AAD decrypt here would be a decryption oracle for ciphertext copied in from elsewhere)", ch.ID)
		}
		plain, derr := c.decryptAuthSecret(payload, ch.URLMeta, ports.NotificationChannelURLAAD(ch.ID))
		if derr != nil {
			return fmt.Errorf("failed to decrypt notification channel %d URL: %w", ch.ID, derr)
		}
		ch.URL = plain
		return nil
	}
}

// encryptNotificationChannelURL produces the url_enc/url_meta pair to store
// for plain, tagged with the format it is actually in (see
// ports.UnwrapNotificationChannelURL): a real envelope when an encryptor is
// wired and enabled, an explicitly-labelled plaintext passthrough otherwise.
// Always returns a non-empty url_enc, even for an empty URL — so "this row's
// format is known and its URL is empty" stays distinguishable from "this row
// has never been written" (which only an upgrading install produces).
func (c *KeyorixCore) encryptNotificationChannelURL(plain string, channelID uint) (urlEnc, urlMeta []byte, err error) {
	if !c.AuthEncryptionActive() {
		return ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagPlaintext, []byte(plain)), nil, nil
	}
	envelope, meta, err := c.encryptAuthSecret(plain, ports.NotificationChannelURLAAD(channelID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt notification channel URL: %w", err)
	}
	return ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagEncrypted, envelope), meta, nil
}

// redactedNotificationChannelForAudit returns a copy of ch with the URL (the
// webhook bearer credential) and its encrypted form scrubbed, for use ONLY as
// the before/after payload passed to writeConfigChangeAuditEvent (#2432): the
// raw struct is json.Marshal'd into audit_events.Diff, which URL (and
// URLEnc/URLMeta, defensively, though their json:"-" tag already excludes
// them) must never reach — audit.read is a different, narrower authorization
// boundary than notification-channel management, and must not become a path
// to recover a live webhook credential.
func redactedNotificationChannelForAudit(ch *models.NotificationChannel) *models.NotificationChannel {
	if ch == nil {
		return nil
	}
	redacted := *ch
	if redacted.URL != "" {
		redacted.URL = "[redacted]"
	}
	redacted.URLEnc = nil
	redacted.URLMeta = nil
	return &redacted
}

// CreateNotificationChannel validates and persists a new notification channel.
// Validation:
//   - Name must be non-empty.
//   - Type must be one of: webhook, slack, teams, email.
//   - URL is required for webhook/slack/teams types.
//   - Email is required for email type.
//
// actorID is the acting user's numeric ID for audit attribution (0 when
// unknown, e.g. a local CLI invocation) -- see writeConfigChangeAuditEvent.
func (c *KeyorixCore) CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel, createdBy string, actorID uint) (*models.NotificationChannel, error) {
	if err := c.validateNotificationChannel(ch); err != nil {
		return nil, err
	}
	plainURL := ch.URL
	ch.CreatedBy = createdBy
	ch.CreatedAt = time.Now().UTC()
	ch.UpdatedAt = ch.CreatedAt
	// #2433: the URL's AAD binds to ch.ID, an auto-increment PK not known before
	// insert -- so this genuinely needs two writes: insert with URLEnc/URLMeta
	// empty (ch.URL is gorm:"-", so the insert never writes plaintext into a
	// column either), then encrypt bound to the now-known ID and persist.
	//
	// #2468: both writes share ONE transaction. They did not originally, and a
	// failure between them left a durable row with an empty url_enc -- which,
	// with encryption on, is the exact shape that then failed EVERY subsequent
	// ListNotificationChannels, because that list is deliberately fail-closed.
	// The window was not theoretical: encryptAuthSecret reaches a KMS-backed
	// encryptor, and UpdateNotificationChannel is an ordinary DB write. One
	// transaction also means this function no longer needs the
	// insertNotificationChannelRow indirection that hid its second write from
	// TestAtomicityGuard_UnclassifiedMultiWriteFunction (INV-CORE-35): the
	// guard is satisfied for the real reason now, not by splitting the count
	// across two function bodies.
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if terr := tx.CreateNotificationChannel(ctx, ch); terr != nil {
			return terr
		}
		urlEnc, urlMeta, terr := c.encryptNotificationChannelURL(plainURL, ch.ID)
		if terr != nil {
			return terr
		}
		ch.URLEnc = urlEnc
		ch.URLMeta = urlMeta
		if terr := tx.UpdateNotificationChannel(ctx, ch); terr != nil {
			return fmt.Errorf("failed to persist encrypted notification channel URL: %w", terr)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	ch.URL = plainURL
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelCreated, actorID,
		fmt.Sprintf("notification channel %d (%q, type=%s) created by %s", ch.ID, ch.Name, ch.Type, createdBy),
		nil, redactedNotificationChannelForAudit(ch))
	return ch, nil
}

// UpdateNotificationChannel applies the given map of field updates to the channel
// identified by id and returns the updated channel.
// actorID is the acting user's numeric ID for audit attribution (0 when
// unknown, e.g. a local CLI invocation) -- see writeConfigChangeAuditEvent.
func (c *KeyorixCore) UpdateNotificationChannel(ctx context.Context, id uint, updates map[string]any, actorID uint) (*models.NotificationChannel, error) {
	ch, err := c.storage.GetNotificationChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	// Decrypt the EXISTING URL first (#2433): storage.GetNotificationChannel
	// never populates ch.URL on its own (not a persisted column any more), so
	// both the audit "before" snapshot and the no-url-change case below need
	// the real plaintext, not a zero-value empty string.
	if err := c.decryptNotificationChannelURL(ch); err != nil {
		return nil, err
	}
	before := *ch
	urlChanged := false
	if v, ok := updates["name"].(string); ok && v != "" {
		ch.Name = v
	}
	if v, ok := updates["type"].(string); ok && v != "" {
		ch.Type = v
	}
	if v, ok := updates["url"].(string); ok {
		ch.URL = v
		urlChanged = true
	}
	if v, ok := updates["email"].(string); ok {
		ch.Email = v
	}
	if v, ok := updates["events"].(string); ok {
		ch.Events = v
	}
	if v, ok := updates["enabled"].(bool); ok {
		ch.Enabled = v
	}
	if err := c.validateNotificationChannel(ch); err != nil {
		return nil, err
	}
	if urlChanged {
		// Re-encrypt bound to the SAME channel ID -- unlike create, an update
		// has no chicken-egg problem (the ID already exists). When the URL
		// wasn't part of this update, ch.URLEnc/ch.URLMeta (fetched by
		// storage.GetNotificationChannel above, untouched since) are left
		// exactly as they were -- re-encrypting unconditionally here would
		// otherwise overwrite valid ciphertext with an encryption of the
		// decrypted plaintext, harmless in effect but needless churn, and
		// outright wrong if decryptNotificationChannelURL ever returned a
		// placeholder instead of the real plaintext on some future error path.
		urlEnc, urlMeta, err := c.encryptNotificationChannelURL(ch.URL, ch.ID)
		if err != nil {
			return nil, err
		}
		ch.URLEnc = urlEnc
		ch.URLMeta = urlMeta
	}
	ch.UpdatedAt = time.Now().UTC()
	if err := c.storage.UpdateNotificationChannel(ctx, ch); err != nil {
		return nil, err
	}
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelUpdated, actorID,
		fmt.Sprintf("notification channel %d (%q) updated", id, ch.Name),
		redactedNotificationChannelForAudit(&before), redactedNotificationChannelForAudit(ch))
	return ch, nil
}

// DeleteNotificationChannel permanently removes the channel with the given id.
// actorID is the acting user's numeric ID for audit attribution (0 when
// unknown, e.g. a local CLI invocation) -- see writeConfigChangeAuditEvent.
func (c *KeyorixCore) DeleteNotificationChannel(ctx context.Context, id uint, actorID uint) error {
	ch, err := c.storage.GetNotificationChannel(ctx, id)
	if err != nil {
		return err
	}
	if err := c.storage.DeleteNotificationChannel(ctx, id); err != nil {
		return err
	}
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelDeleted, actorID,
		fmt.Sprintf("notification channel %d (%q, type=%s) deleted", id, ch.Name, ch.Type),
		redactedNotificationChannelForAudit(ch), nil)
	return nil
}

// validateNotificationChannel enforces invariants for create and update paths.
func (c *KeyorixCore) validateNotificationChannel(ch *models.NotificationChannel) error {
	if strings.TrimSpace(ch.Name) == "" {
		return fmt.Errorf("notification channel name is required")
	}
	if _, ok := validChannelTypes[ch.Type]; !ok {
		return fmt.Errorf("invalid notification channel type %q: must be one of webhook, slack, teams, email", ch.Type)
	}
	urlValidator := c.webhookURLValidator
	if urlValidator == nil {
		urlValidator = validateWebhookURL
	}
	switch ch.Type {
	case "webhook", "slack", "teams":
		if strings.TrimSpace(ch.URL) == "" {
			return fmt.Errorf("notification channel URL is required for type %q", ch.Type)
		}
		if err := urlValidator(ch.URL); err != nil {
			return err
		}
	case "email":
		if strings.TrimSpace(ch.Email) == "" {
			return fmt.Errorf("notification channel email is required for type \"email\"")
		}
	}
	return nil
}

// validateWebhookURL enforces SSRF-prevention rules on outbound webhook/slack/teams URLs.
// It requires an https scheme and rejects destinations that resolve to RFC 1918,
// loopback, link-local, or IMDS (169.254.0.0/16) addresses.
func validateWebhookURL(raw string) error {
	u, err := parseWebhookURLLiteral(raw)
	if err != nil {
		return err
	}
	if net.ParseIP(u.Hostname()) != nil {
		return nil // literal already vetted by parseWebhookURLLiteral
	}
	addrs, err := channelLookupIPAddr(context.Background(), u.Hostname())
	if err != nil {
		return fmt.Errorf("notification channel: could not resolve URL hostname to verify it is not private/internal: %w", err)
	}
	for _, a := range addrs {
		if isChannelDisallowedIP(a.IP) {
			return fmt.Errorf("notification channel: URL resolves to a private/link-local address (%s); refusing internal destination", a.IP)
		}
	}
	return nil
}

// validateWebhookSendTimeURL is the send-time half of validateWebhookURL
// (postJSONToURL): scheme and IP-literal checks only. Hostnames are NOT
// resolved here -- escalationTransport resolves and re-validates them at dial
// time and connects to the checked IP, so a second lookup here would only
// add a TOCTOU window. It exists so a stored URL that is (or was edited into)
// a literal 169.254.169.254 / 127.0.0.1 is refused even when a caller
// supplied its own *http.Client (c.httpClient) that bypasses the dial guard.
func validateWebhookSendTimeURL(raw string) error {
	_, err := parseWebhookURLLiteral(raw)
	return err
}

// parseWebhookURLLiteral parses raw and enforces the https scheme and the
// private/link-local/loopback policy for an IP-literal host.
func parseWebhookURLLiteral(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("notification channel: invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("notification channel: URL must use https (got %q)", u.Scheme)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isChannelDisallowedIP(ip) {
		return nil, fmt.Errorf("notification channel: URL targets a private/link-local address; refusing internal destination")
	}
	return u, nil
}

// channelLookupIPAddr resolves a hostname to its IP addresses — a var (like
// evidencesink/notifychan's identically-shaped lookupIPAddr) so tests can
// substitute a fake resolver without a real DNS query, and so
// escalationTransport (alert_escalation.go) can share the EXACT same
// resolution seam this construction-time check uses, making a DNS-rebinding
// scenario (a public answer here, a private one at actual escalation-dial
// time) directly testable end-to-end.
var channelLookupIPAddr netutil.Resolver = netutil.DefaultResolver

// isChannelDisallowedIP reports whether ip is a private, link-local, or loopback
// address — all of which are forbidden as outbound webhook destinations (SSRF guard).
//
// Checked both directly AND against ip's embedded IPv4 (netutil.EmbeddedIPv4),
// mirroring netutil's own matchesCIDRsWithEmbedded "direct match OR embedded
// match" shape — checking ONLY the decoded form would wrongly clear a genuine
// IPv6 loopback/link-local literal (e.g. ::1 itself decodes, as deprecated
// IPv4-compatible, to embedded 0.0.0.1, which is neither loopback nor private
// in isolation). A NAT64 (64:ff9b::/96) or IPv4-compatible (::x) encoding of a
// private/loopback/link-local IPv4 (e.g. 64:ff9b::a9fe:a9fe = cloud IMDS
// 169.254.169.254) needs the embedded check: Go's own net.IP.IsPrivate/
// IsLoopback/IsLinkLocalUnicast fold IPv4-MAPPED (::ffff:x) via To4, but NOT
// these two encodings, so a bare stdlib check here disagreed with
// netutil.IsPrivateOrLinkLocal (the guard every backend-infrastructure dial
// site in this codebase shares) for exactly those two forms -- reachable both
// from validateWebhookURL's construction-time check and, more importantly,
// from escalationTransport's dial-time re-validation (alert_escalation.go),
// which wires this exact function in as its netutil.Dialer.Disallow policy.
func isChannelDisallowedIP(ip net.IP) bool {
	if isChannelDisallowedIPDirect(ip) {
		return true
	}
	if v4 := netutil.EmbeddedIPv4(ip); v4 != nil {
		return isChannelDisallowedIPDirect(v4)
	}
	return false
}

func isChannelDisallowedIPDirect(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
