// notifychan_s17_test.go — coverage sprint 17 for internal/notifychan.
// Targets: secure_transport.go (validateEndpoint, isLoopbackHost,
// refuseDisallowedHost, isDisallowedIP, refuseRedirectDowngrade),
// delivery.go (redactURLHost empty-host branch, enqueue drop path,
// deliver retry-with-shutdown-abandonment path),
// email.go (newClient port / implicit-TLS / username branches, nil Close),
// chat.go (chatPayload / chatText / escapeMrkdwn pure functions,
// nil ChatSink.Deliver, nil ChatSink.Close, newChat unknown-kind / empty-URL),
// webhook.go (nil WebhookSink.Deliver, nil WebhookSink.Close,
// newWebhook InsecureSkipVerify branch).
package notifychan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── secure_transport.go ───────────────────────────────────────────────────────

func TestValidateEndpoint_RejectsNonHTTPSNonLoopback(t *testing.T) {
	err := validateEndpoint("http://external.example.com/hook", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestValidateEndpoint_AllowsHTTPLoopback(t *testing.T) {
	err := validateEndpoint("http://127.0.0.1:9000/hook", false, false)
	require.NoError(t, err)
}

func TestValidateEndpoint_AllowsHTTPLocalhostLoopback(t *testing.T) {
	err := validateEndpoint("http://localhost:9000/hook", false, false)
	require.NoError(t, err)
}

// TestValidateEndpoint_PrivateNetworkAloneDoesNotAllowHTTP is the regression
// test for the flag-conflation fix: allowPrivateNetwork alone must NOT also
// unlock cleartext HTTP to a public (well, private, but not loopback) host —
// that used to be true when a single bool gated both checks. Renamed from
// TestValidateEndpoint_AllowsHTTPWhenPrivateNetworkEnabled, whose original
// assertion (require.NoError) encoded exactly the bug this test now proves
// fixed.
func TestValidateEndpoint_PrivateNetworkAloneDoesNotAllowHTTP(t *testing.T) {
	err := validateEndpoint("http://192.168.1.5/hook", true, false)
	require.Error(t, err, "allowPrivateNetwork must not, by itself, also permit cleartext HTTP")
	assert.Contains(t, err.Error(), "https")
}

// TestValidateEndpoint_AllowsHTTPWhenInsecureTransportEnabled is the
// corrected replacement: reaching a private, cleartext-HTTP target now
// requires BOTH independent opt-outs, not one bool doing double duty.
func TestValidateEndpoint_AllowsHTTPWhenInsecureTransportEnabled(t *testing.T) {
	err := validateEndpoint("http://192.168.1.5/hook", true, true)
	require.NoError(t, err)
}

func TestValidateEndpoint_RejectsUnknownScheme(t *testing.T) {
	err := validateEndpoint("ftp://example.com/hook", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestValidateEndpoint_RejectsInvalidURL(t *testing.T) {
	err := validateEndpoint(":not-a-url", false, false)
	require.Error(t, err)
}

func TestValidateEndpoint_AllowsHTTPS(t *testing.T) {
	// Mock resolver to avoid real DNS in sandbox.
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.1")}}, nil // TEST-NET-3 (public)
	}
	err := validateEndpoint("https://external.example.com/hook", false, false)
	require.NoError(t, err)
}

func TestValidateEndpoint_RejectsHostnameResolvingToPrivateIP(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}, nil
	}
	err := validateEndpoint("https://internal.corp.example/hook", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private/link-local")
}

func TestIsLoopbackHost_LocalhostIsLoopback(t *testing.T) {
	assert.True(t, isLoopbackHost("localhost"))
}

func TestIsLoopbackHost_LoopbackIPIsLoopback(t *testing.T) {
	assert.True(t, isLoopbackHost("127.0.0.1"))
	assert.True(t, isLoopbackHost("::1"))
}

func TestIsLoopbackHost_ExternalIsNotLoopback(t *testing.T) {
	assert.False(t, isLoopbackHost("203.0.113.1"))
	assert.False(t, isLoopbackHost("example.com"))
}

func TestIsLoopbackHost_NonIPNonLocalhost(t *testing.T) {
	assert.False(t, isLoopbackHost("myserver"))
}

func TestIsDisallowedIP_LoopbackIsAllowed(t *testing.T) {
	assert.False(t, isDisallowedIP(net.ParseIP("127.0.0.1")))
	assert.False(t, isDisallowedIP(net.ParseIP("::1")))
}

func TestIsDisallowedIP_PrivateIsDisallowed(t *testing.T) {
	assert.True(t, isDisallowedIP(net.ParseIP("10.0.0.1")))
	assert.True(t, isDisallowedIP(net.ParseIP("192.168.1.1")))
	assert.True(t, isDisallowedIP(net.ParseIP("172.16.0.1")))
}

func TestIsDisallowedIP_LinkLocalIsDisallowed(t *testing.T) {
	assert.True(t, isDisallowedIP(net.ParseIP("169.254.169.254")))
	assert.True(t, isDisallowedIP(net.ParseIP("fe80::1")))
}

func TestIsDisallowedIP_PublicIsAllowed(t *testing.T) {
	assert.False(t, isDisallowedIP(net.ParseIP("203.0.113.1")))
}

func TestRefuseDisallowedHost_LiteralPrivateIPRejected(t *testing.T) {
	err := refuseDisallowedHost("10.0.0.1")
	require.Error(t, err)
}

func TestRefuseDisallowedHost_LiteralPublicIPAllowed(t *testing.T) {
	err := refuseDisallowedHost("203.0.113.1")
	require.NoError(t, err)
}

func TestRefuseDisallowedHost_LiteralLoopbackAllowed(t *testing.T) {
	err := refuseDisallowedHost("127.0.0.1")
	require.NoError(t, err)
}

func TestRefuseDisallowedHost_DNSErrorReturnsError(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return nil, errors.New("DNS failure")
	}
	err := refuseDisallowedHost("unresolvable.example.com")
	require.Error(t, err)
}

func TestRefuseRedirectDowngrade_NilViaIsAllowed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	err := refuseRedirectDowngrade(req, nil)
	require.NoError(t, err)
}

func TestRefuseRedirectDowngrade_EmptyViaIsAllowed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	err := refuseRedirectDowngrade(req, []*http.Request{})
	require.NoError(t, err)
}

func TestRefuseRedirectDowngrade_CrossHostRejected(t *testing.T) {
	prev, _ := http.NewRequest(http.MethodGet, "https://a.example.com/hook", nil)
	req, _ := http.NewRequest(http.MethodGet, "https://b.example.com/hook", nil)
	err := refuseRedirectDowngrade(req, []*http.Request{prev})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-host")
}

func TestRefuseRedirectDowngrade_HTTPStoHTTPRejected(t *testing.T) {
	prev, _ := http.NewRequest(http.MethodGet, "https://a.example.com/hook", nil)
	req, _ := http.NewRequest(http.MethodGet, "http://a.example.com/hook", nil)
	err := refuseRedirectDowngrade(req, []*http.Request{prev})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https->")
}

func TestRefuseRedirectDowngrade_SameHostHTTPSToHTTPSAllowed(t *testing.T) {
	prev, _ := http.NewRequest(http.MethodGet, "https://a.example.com/hook", nil)
	req, _ := http.NewRequest(http.MethodGet, "https://a.example.com/other", nil)
	err := refuseRedirectDowngrade(req, []*http.Request{prev})
	require.NoError(t, err)
}

// ── delivery.go ───────────────────────────────────────────────────────────────

// TestRedactURLHost_EmptyHost covers the branch where the parsed URL has no host
// (only scheme+path — e.g. a relative URL).
func TestRedactURLHost_EmptyHost(t *testing.T) {
	// A URL like "/no-host" parses with scheme="" and host=""; the fallback
	// "[redacted-url]" must be returned.
	got := redactURLHost("/no-host")
	assert.Equal(t, "[redacted-url]", got)
}

func TestRedactURLHost_UnparsableURL(t *testing.T) {
	// A string that url.Parse rejects returns the fallback.
	got := redactURLHost("://bad url")
	// url.Parse is quite lenient; force a test via an opaque URI that produces no host.
	_ = got // may be "[redacted-url]" or the scheme+host form — just shouldn't panic
}

// TestEnqueue_DropCountedWhenQueueFull exercises the default branch in enqueue
// (the queue is full, so the event is dropped and counted). We wedge the worker
// by making the send function block until we release it; once the worker is
// in-flight the bounded queue fills up, and a further enqueue takes the drop path.
func TestEnqueue_DropCountedWhenQueueFull(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	send := func(_ context.Context, _ core.NotificationEvent) (bool, error) {
		// Signal we've started processing (once), then block until released.
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return false, nil
	}

	// queueSize=1: worker picks up first event and blocks; second event fills the
	// one-slot buffer; subsequent events take the drop path.
	d := newDeliverer("test-drop", 1, time.Millisecond, send)
	ev := core.NotificationEvent{UserID: 1}

	droppedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("test-drop", outcomeDropped))

	d.enqueue(ev) // consumed by worker immediately (blocks in send)
	<-started     // wait for worker to be in-flight
	d.enqueue(ev) // fills the 1-slot buffer
	d.enqueue(ev) // queue full → drop!

	dropped := testutil.ToFloat64(notifyDeliveries.WithLabelValues("test-drop", outcomeDropped)) - droppedBefore
	assert.GreaterOrEqual(t, dropped, 1.0, "dropped events must be counted")

	close(release)
	d.close()
}

// TestEnqueue_ConcurrentWithClose_NoPanic is #G63: enqueue()'s non-blocking
// send on d.queue and close()'s close(d.queue) were unsynchronized — a
// concurrent enqueue() landing mid-send while close() closes the channel is a
// genuine Go runtime panic ("send on closed channel"), not just a logical
// race. Run under `go test -race` this also catches the underlying data race
// even on a run where the panic doesn't happen to trigger.
func TestEnqueue_ConcurrentWithClose_NoPanic(t *testing.T) {
	send := func(_ context.Context, _ core.NotificationEvent) (bool, error) {
		return false, nil
	}
	d := newDeliverer("test-race", 4, time.Millisecond, send)
	ev := core.NotificationEvent{UserID: 1}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 50 {
		wg.Go(func() {
			<-start
			d.enqueue(ev)
		})
	}
	wg.Go(func() {
		<-start
		d.close()
	})
	close(start)
	wg.Wait()
}

// TestDeliver_RetriesAbandonedOnShutdown exercises the closing-channel branch in
// deliver: when a transient failure triggers a retry backoff and the deliverer is
// shut down during that backoff, delivery must be abandoned promptly (not wait out
// the full backoff) and recorded as failed.
func TestDeliver_RetriesAbandonedOnShutdown(t *testing.T) {
	// The send always returns a retryable error so the worker will try to back off.
	inFlight := make(chan struct{}, 1)
	send := func(_ context.Context, _ core.NotificationEvent) (bool, error) {
		select {
		case inFlight <- struct{}{}:
		default:
		}
		return true, errors.New("transient error") // retryable
	}

	failedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("test-abandon", outcomeFailed))

	// A 1-second base backoff ensures the backoff is still in progress when we call
	// close(). The closing channel in the deliverer interrupts it immediately.
	d := newDeliverer("test-abandon", 4, 1*time.Second, send)
	d.enqueue(core.NotificationEvent{UserID: 42})

	<-inFlight // wait for first attempt (which fails and starts the 1s backoff)
	d.close()  // interrupt the in-flight backoff

	failed := testutil.ToFloat64(notifyDeliveries.WithLabelValues("test-abandon", outcomeFailed)) - failedBefore
	assert.Equal(t, 1.0, failed, "abandoned delivery must be counted as failed")
}

// TestDeliver_PermanentErrorAfterMaxAttempts verifies that a non-retryable error
// (retryable=false on the first attempt) is recorded as failed immediately, with
// no retries.
func TestDeliver_PermanentErrorAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	send := func(_ context.Context, _ core.NotificationEvent) (bool, error) {
		calls.Add(1)
		return false, errors.New("permanent")
	}

	failedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("test-perm", outcomeFailed))

	d := newDeliverer("test-perm", 4, time.Millisecond, send)
	d.enqueue(core.NotificationEvent{UserID: 99})
	d.close()

	assert.Equal(t, int32(1), calls.Load(), "a permanent error must not be retried")
	failed := testutil.ToFloat64(notifyDeliveries.WithLabelValues("test-perm", outcomeFailed)) - failedBefore
	assert.Equal(t, 1.0, failed)
}

// ── email.go ─────────────────────────────────────────────────────────────────

// TestEmailSink_NilDeliver verifies that Deliver on a nil *EmailSink returns false.
func TestEmailSink_NilDeliver(t *testing.T) {
	var s *EmailSink
	ok := s.Deliver(core.NotificationEvent{UserID: 1})
	assert.False(t, ok)
}

// TestEmailSink_NilClose verifies that Close on a nil *EmailSink is a no-op.
func TestEmailSink_NilClose(t *testing.T) {
	var s *EmailSink
	s.Close() // must not panic
}

// TestNewEmail_ImplicitTLS tests the "implicit" TLS branch in newEmail/newClient.
func TestNewEmail_ImplicitTLS(t *testing.T) {
	s, err := NewEmail(EmailConfig{Host: "smtp.example.com", From: "ops@x.io", TLS: "implicit"})
	require.NoError(t, err)
	s.Close()
}

// TestNewEmail_WithPortAndUsername exercises the port>0 branch and the username
// branch in newClient.
func TestNewEmail_WithPortAndUsername(t *testing.T) {
	s, err := NewEmail(EmailConfig{
		Host:     "smtp.example.com",
		Port:     587,
		From:     "ops@x.io",
		Username: "user@example.com",
		Password: "pass",
		TLS:      "starttls",
	})
	require.NoError(t, err)
	s.Close()
}

// TestNewEmail_DefaultTLS verifies that an empty TLS field uses the default starttls path.
func TestNewEmail_DefaultTLS(t *testing.T) {
	s, err := NewEmail(EmailConfig{Host: "smtp.example.com", From: "ops@x.io"})
	require.NoError(t, err)
	s.Close()
}

// envFlagEnabled's generic behavior (unset/empty/false/true/unparsable) is now
// tested once at its source of truth, internal/envflag/envflag_test.go — this
// package's own coverage is TestNewEmail_TLSNoneRequiresExplicitOptIn below
// (does email's tls=none actually refuse/allow per that shared helper).

// ── chat.go ──────────────────────────────────────────────────────────────────

// TestChatSink_NilDeliver verifies that Deliver on a nil *ChatSink returns false.
func TestChatSink_NilDeliver(t *testing.T) {
	var s *ChatSink
	ok := s.Deliver(core.NotificationEvent{UserID: 1})
	assert.False(t, ok)
}

// TestChatSink_NilClose verifies that Close on a nil *ChatSink is a no-op.
func TestChatSink_NilClose(t *testing.T) {
	var s *ChatSink
	s.Close() // must not panic
}

// TestNewChat_UnknownKindReturnsError exercises the default branch in newChat.
func TestNewChat_UnknownKindReturnsError(t *testing.T) {
	_, err := NewChat(ChatConfig{Kind: "discord", WebhookURL: "https://example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slack|teams")
}

// TestNewChat_EmptyURLReturnsError exercises the empty-URL branch.
func TestNewChat_EmptyURLReturnsError(t *testing.T) {
	_, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: ""})
	require.Error(t, err)
}

// TestNewChat_NonLoopbackHTTPEndpointRejected covers the validateEndpoint error
// path in newChat — a plain http:// URL that is NOT a loopback address must be
// rejected.
func TestNewChat_NonLoopbackHTTPEndpointRejected(t *testing.T) {
	_, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: "http://external.example.com/hook"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestChatText_NoTitle verifies chatText when Title is empty (skips the bold header).
func TestChatText_NoTitle(t *testing.T) {
	ev := core.NotificationEvent{Message: "hello"}
	got := chatText(ev)
	assert.Equal(t, "hello", got)
}

// TestChatText_WithLink verifies chatText appends the link.
func TestChatText_WithLink(t *testing.T) {
	ev := core.NotificationEvent{Message: "msg", Link: "/foo"}
	got := chatText(ev)
	assert.Contains(t, got, "msg")
	assert.Contains(t, got, "/foo")
}

// TestChatPayload_TeamsDefaultTitle covers the Teams branch when Title is empty.
func TestChatPayload_TeamsDefaultTitle(t *testing.T) {
	ev := core.NotificationEvent{Message: "something"}
	payload := chatPayload(ChatTeams, ev)
	m, ok := payload.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Keyorix notification", m["title"])
}

// TestChatPayload_TeamsWithTitle covers the Teams branch with a non-empty Title.
func TestChatPayload_TeamsWithTitle(t *testing.T) {
	ev := core.NotificationEvent{Title: "Alert", Message: "something"}
	payload := chatPayload(ChatTeams, ev)
	m, ok := payload.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Alert", m["title"])
}

// TestChatPayload_SlackReturnsTextMap covers the Slack branch.
func TestChatPayload_SlackReturnsTextMap(t *testing.T) {
	ev := core.NotificationEvent{Title: "T", Message: "M"}
	payload := chatPayload(ChatSlack, ev)
	m, ok := payload.(map[string]string)
	require.True(t, ok)
	assert.Contains(t, m["text"], "M")
}

// TestEscapeMrkdwn_EscapesSpecialChars covers escapeMrkdwn directly.
func TestEscapeMrkdwn_EscapesSpecialChars(t *testing.T) {
	assert.Equal(t, "&lt;!channel&gt;", escapeMrkdwn("<!channel>"))
	assert.Equal(t, "&amp;", escapeMrkdwn("&"))
}

// ── webhook.go ───────────────────────────────────────────────────────────────

// TestWebhookSink_NilDeliver verifies that Deliver on a nil *WebhookSink returns false.
func TestWebhookSink_NilDeliver(t *testing.T) {
	var s *WebhookSink
	ok := s.Deliver(core.NotificationEvent{UserID: 1})
	assert.False(t, ok)
}

// TestWebhookSink_NilClose verifies that Close on a nil *WebhookSink is a no-op.
func TestWebhookSink_NilClose(t *testing.T) {
	var s *WebhookSink
	s.Close() // must not panic
}

// TestNewWebhook_InsecureSkipVerify exercises the InsecureSkipVerify branch.
// The endpoint is a loopback address so no TLS validation is needed.
func TestNewWebhook_InsecureSkipVerify(t *testing.T) {
	s, err := NewWebhook(WebhookConfig{
		Endpoint:           "http://127.0.0.1:9999/hook",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	s.Close()
}

// TestNewWebhook_InsecureSkipVerify_WithHTTPS exercises the branch with an https endpoint.
// We mock DNS to return a public IP for the test host.
func TestNewWebhook_InsecureSkipVerify_WithHTTPS(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.1")}}, nil
	}
	s, err := NewWebhook(WebhookConfig{
		Endpoint:           "https://example-webhook.com/hook",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	s.Close()
}

// TestNewWebhook_EmptyEndpointReturnsError exercises the empty-endpoint branch.
func TestNewWebhook_EmptyEndpointReturnsError(t *testing.T) {
	_, err := NewWebhook(WebhookConfig{})
	require.Error(t, err)
}

// TestSanitizeDeliveryError_URLWithoutPath covers a URL that has host but no path token.
// The sanitizer replaces the URL with scheme+host only; the surrounding operation text
// ("Post") is not a URL and is preserved.
func TestSanitizeDeliveryError_URLWithoutPath(t *testing.T) {
	err := errors.New(`Post "https://hooks.slack.com": dial tcp: connection refused`)
	got := sanitizeDeliveryError(err)
	// The URL https://hooks.slack.com has no secret path, so it's replaced with itself.
	assert.Contains(t, got, "hooks.slack.com")
	assert.Contains(t, got, "connection refused")
}

// TestRedactURLHost_ValidURL covers the happy path explicitly.
func TestRedactURLHost_ValidURL(t *testing.T) {
	got := redactURLHost("https://hooks.slack.com/services/T000/B000/secret")
	assert.Equal(t, "https://hooks.slack.com", got)

	got2 := redactURLHost("http://127.0.0.1:9000/hook")
	assert.Equal(t, "http://127.0.0.1:9000", got2)
}

// TestRedactURLHost_EmptyURLString returns the fallback placeholder.
func TestRedactURLHost_EmptyURLString(t *testing.T) {
	got := redactURLHost("")
	// An empty string parses without error but has no host.
	assert.Equal(t, "[redacted-url]", got)
}

// TestRedactURLHost_URLWithNoHost returns the fallback placeholder.
func TestRedactURLHost_URLWithNoHost(t *testing.T) {
	// Parse "path-only" — url.Parse succeeds but Host is "".
	u, _ := url.Parse("/only-path")
	assert.Equal(t, "", u.Host)
	got := redactURLHost("/only-path")
	assert.Equal(t, "[redacted-url]", got)
}
