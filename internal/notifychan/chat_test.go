package notifychan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureChatServer(t *testing.T) (*httptest.Server, func() []byte) {
	t.Helper()
	var mu sync.Mutex
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return body
	}
}

func TestChatSink_SlackPayload(t *testing.T) {
	srv, get := captureChatServer(t)
	sink, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL})
	require.NoError(t, err)
	pid := uint(3)
	sink.Deliver(core.NotificationEvent{Title: "Secrets due for rotation", Message: "2 overdue in Payments.", ProjectID: &pid, Link: "/rotation-policies"})
	sink.Close()

	var payload map[string]string
	require.NoError(t, json.Unmarshal(get(), &payload))
	assert.Contains(t, payload["text"], "Secrets due for rotation")
	assert.Contains(t, payload["text"], "2 overdue in Payments.")
	assert.Contains(t, payload["text"], "/rotation-policies")
}

func TestChatSink_TeamsPayload(t *testing.T) {
	srv, get := captureChatServer(t)
	sink, err := NewChat(ChatConfig{Kind: ChatTeams, WebhookURL: srv.URL})
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{Title: "Anomaly detected", Message: "off-hours access by ada."})
	sink.Close()

	var card map[string]any
	require.NoError(t, json.Unmarshal(get(), &card))
	assert.Equal(t, "MessageCard", card["@type"])
	assert.Equal(t, "Anomaly detected", card["title"])
	assert.Equal(t, "off-hours access by ada.", card["text"])
}

// TestChatSink_EscapesMrkdwnInjectionFromSecretName proves the #328 exploit trace
// (an ordinary secret owner names a secret with Slack mrkdwn control syntax and
// shares it — no admin privilege required) is neutralized before it reaches either
// platform's JSON payload: no live `<!channel>` mass-ping token, no live
// `<url|label>` spoofed-link token, in the actual bytes posted to the destination.
func TestChatSink_EscapesMrkdwnInjectionFromSecretName(t *testing.T) {
	// Exactly the exploit trace from #328: a secret name crafted to trigger a
	// Slack mass-ping and a spoofed clickable link, delivered via the ordinary
	// "secret shared with you" notification (notifySecretShared in
	// internal/core/notifications.go embeds secret.Name verbatim into ev.Message).
	secretName := `<!channel> Password reset required: <https://evil.example/login|Reset Now>`
	message := `You were granted read access to secret "` + secretName + `".`

	t.Run("slack", func(t *testing.T) {
		srv, get := captureChatServer(t)
		sink, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL})
		require.NoError(t, err)
		sink.Deliver(core.NotificationEvent{Title: "Secret shared with you", Message: message})
		sink.Close()

		var payload map[string]string
		require.NoError(t, json.Unmarshal(get(), &payload))
		text := payload["text"]
		assert.NotContains(t, text, "<!channel>", "must not carry a live @channel mass-ping token")
		assert.NotContains(t, text, "<https://evil.example/login|Reset Now>", "must not carry a live spoofed-link token")
		// The content must still be present, just inert — nothing was silently dropped.
		assert.Contains(t, text, "&lt;!channel&gt;")
		assert.Contains(t, text, "&lt;https://evil.example/login|Reset Now&gt;")
	})

	t.Run("teams", func(t *testing.T) {
		srv, get := captureChatServer(t)
		sink, err := NewChat(ChatConfig{Kind: ChatTeams, WebhookURL: srv.URL})
		require.NoError(t, err)
		sink.Deliver(core.NotificationEvent{Title: "Secret shared with you", Message: message})
		sink.Close()

		var card map[string]any
		require.NoError(t, json.Unmarshal(get(), &card))
		text, _ := card["text"].(string)
		assert.NotContains(t, text, "<!channel>", "must not carry a live @channel mass-ping token")
		assert.NotContains(t, text, "<https://evil.example/login|Reset Now>", "must not carry a live spoofed-link token")
		assert.Contains(t, text, "&lt;!channel&gt;")
		assert.Contains(t, text, "&lt;https://evil.example/login|Reset Now&gt;")
	})
}

// TestChatSink_EscapesMrkdwnInjectionInTitle covers the Title field (used verbatim
// by other admin/system-triggered notification paths, e.g. compliance_digest.go,
// rotation_executor.go) through the same choke point.
func TestChatSink_EscapesMrkdwnInjectionInTitle(t *testing.T) {
	srv, get := captureChatServer(t)
	sink, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL})
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{Title: `<!here> urgent`, Message: "ok"})
	sink.Close()

	var payload map[string]string
	require.NoError(t, json.Unmarshal(get(), &payload))
	assert.NotContains(t, payload["text"], "<!here>")
	assert.Contains(t, payload["text"], "&lt;!here&gt;")
}

// TestChatSink_SendRequestBuildErrorIsPermanent covers send's http.NewRequestWithContext
// error path. The webhook URL is validated once at construction (newChat), so the only
// way to exercise a request-build failure at send time is to bypass the constructor and
// hand send() a URL that url.Parse itself rejects (a raw control character) — proving
// the documented contract (a request-construction failure is a permanent, non-retryable
// error, same as a marshalling failure) actually holds, not just that some error occurs.
func TestChatSink_SendRequestBuildErrorIsPermanent(t *testing.T) {
	s := &ChatSink{
		cfg:    ChatConfig{Kind: ChatSlack, WebhookURL: "https://example.com/\x7fbad"},
		client: &http.Client{},
	}
	retryable, err := s.send(context.Background(), core.NotificationEvent{Title: "x"})
	require.Error(t, err)
	assert.False(t, retryable, "a malformed request must be treated as permanent, not retried")
}

func TestNewChat_Validation(t *testing.T) {
	_, err := NewChat(ChatConfig{Kind: "irc", WebhookURL: "https://x"})
	require.Error(t, err)
	_, err = NewChat(ChatConfig{Kind: ChatSlack})
	require.Error(t, err)
}

func TestChatSink_RetriesTransientThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // transient — retried by the shared engine
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	delivBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("slack", outcomeDelivered))
	retryBefore := testutil.ToFloat64(notifyRetries.WithLabelValues("slack"))

	sink, err := newChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	defer sink.Close()
	sink.Deliver(core.NotificationEvent{Title: "x"})

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(notifyDeliveries.WithLabelValues("slack", outcomeDelivered))-delivBefore == 1
	}, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(3), hits.Load(), "should retry the two 503s then succeed")
	assert.Equal(t, 2.0, testutil.ToFloat64(notifyRetries.WithLabelValues("slack"))-retryBefore)
}

// TestChatSink_DialTimeRefusesDNSRebind is the G48 regression: a hostname
// that resolves to a PUBLIC address at construction (so NewChat succeeds) but
// to a PRIVATE/link-local address by the time the sink actually delivers
// (simulating a DNS-rebinding attacker) must have its delivery refused — the
// dial-time re-check, not just the one-time construction check, must catch
// it. chat.go has no AllowPrivateNetworkTarget opt-out, so this guard always
// applies.
func TestChatSink_DialTimeRefusesDNSRebind(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()

	const rebindHost = "rebind.chat.example"
	callCount := 0
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		require.Equal(t, rebindHost, host)
		callCount++
		if callCount == 1 {
			// Construction-time validateEndpoint lookup: a public address.
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
		}
		// Every subsequent (dial-time) lookup: cloud-metadata address.
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}

	failedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("slack", outcomeFailed))

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	sink, err := newChat(ChatConfig{Kind: ChatSlack, WebhookURL: "https://" + rebindHost + "/hook"}, time.Millisecond)
	require.NoError(t, err, "construction sees a public address and must succeed")
	require.GreaterOrEqual(t, callCount, 1)

	sink.Deliver(core.NotificationEvent{Title: "x"})
	sink.Close()

	assert.Equal(t, 1.0, testutil.ToFloat64(notifyDeliveries.WithLabelValues("slack", outcomeFailed))-failedBefore,
		"delivery must be refused once dial-time resolution returns a private address, even though construction saw a public one")
	// Assert on the SPECIFIC failure reason — "rebind.chat.example" isn't a
	// real, resolvable domain, so a weaker assertion (mere failure) would
	// pass even without the dial-time guard, for the wrong reason (a plain
	// DNS lookup error).
	assert.Contains(t, buf.String(), "disallowed address", "the failure must come from the dial-time SSRF guard, not an unrelated DNS error")
}
