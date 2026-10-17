package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----

func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func makePolicy(id uint, name, minSev string, afterMin int) models.AlertEscalationPolicy {
	return models.AlertEscalationPolicy{
		ID:                   id,
		Name:                 name,
		MinSeverity:          minSev,
		EscalateAfterMinutes: afterMin,
		ChannelIDs:           "",
		Enabled:              true,
	}
}

func makeAlert(id uint, sev string, ageMinutes int) models.AnomalyAlert {
	return models.AnomalyAlert{
		ID:           id,
		AlertType:    "off_hours",
		Severity:     sev,
		Description:  "test anomaly",
		SecretName:   "my-secret",
		AccessedBy:   "alice",
		IPAddress:    "1.2.3.4",
		DetectedAt:   time.Now().UTC().Add(-time.Duration(ageMinutes) * time.Minute),
		Acknowledged: false,
	}
}

// fakeWebhookTransport is a sandbox-safe http.RoundTripper that intercepts
// outbound webhook POSTs without binding a TCP port.
type fakeWebhookTransport struct {
	statusCode int               // returned status; 0 → 200
	err        error             // if non-nil, returned instead of a response
	called     chan struct{}     // signalled on each call when non-nil
	capture    func(body []byte) // called with the raw request body when non-nil
}

func (t *fakeWebhookTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.err != nil {
		return nil, t.err
	}
	if t.capture != nil && req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		t.capture(b)
	}
	if t.called != nil {
		select {
		case t.called <- struct{}{}:
		default:
		}
	}
	code := t.statusCode
	if code == 0 {
		code = http.StatusOK
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}, nil
}

// ---- RunAlertEscalation ----

func TestRunAlertEscalation_NoPolicies(t *testing.T) {
	store := new(MockStorage)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{}, nil)
	c := NewKeyorixCore(store)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_NoEnabledPolicies(t *testing.T) {
	store := new(MockStorage)
	disabled := makePolicy(1, "p1", "medium", 30)
	disabled.Enabled = false
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{disabled}, nil)
	c := NewKeyorixCore(store)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.Evaluated)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_ZeroDelayPolicySkipped(t *testing.T) {
	store := new(MockStorage)
	p := makePolicy(1, "p1", "medium", 0) // zero delay — skipped
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	c := NewKeyorixCore(store)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.Evaluated)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_NoUnackedAlerts(t *testing.T) {
	store := new(MockStorage)
	p := makePolicy(1, "p1", "medium", 30)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{}, nil)
	c := NewKeyorixCore(store)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_AlertBelowMinSeverity_Skipped(t *testing.T) {
	store := new(MockStorage)
	p := makePolicy(1, "p1", "high", 30)
	p.ChannelIDs = ""

	now := time.Now().UTC()
	alert := makeAlert(1, "low", 60) // age 60 min > 30 min threshold, but severity too low

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	assert.Equal(t, 1, result.Skipped)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_AlertTooRecent_Skipped(t *testing.T) {
	store := new(MockStorage)
	// Policy threshold is 60 min; alert is only 30 min old — store returns nothing
	// because the query uses the minimum policy delay as the threshold.
	// Simulate: store returns the alert, but it's 10 min old and policy needs 30 min.
	p := makePolicy(1, "p1", "medium", 30)
	p.ChannelIDs = ""

	now := time.Now().UTC()
	alert := makeAlert(1, "high", 10) // 10 min old — too recent for the 30-min policy
	alert.DetectedAt = now.Add(-10 * time.Minute)

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	assert.Equal(t, 1, result.Skipped)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_MatchingAlert_Escalated(t *testing.T) {
	received := make(chan struct{}, 1)
	tr := &fakeWebhookTransport{called: received}

	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "medium", 30)
	p.ChannelIDs = "7"

	alert := makeAlert(1, "high", 60)
	alert.DetectedAt = now.Add(-60 * time.Minute)

	ch := &models.NotificationChannel{
		ID:      7,
		Name:    "test-webhook",
		Type:    "webhook",
		URLEnc:  plaintextURLEnc("https://fake-webhook.test/hook"),
		Enabled: true,
	}

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(ch, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)
	c.httpClient = &http.Client{Transport: tr}

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 1, result.Escalated)
	assert.Equal(t, 0, result.Skipped)

	select {
	case <-received:
	default:
		t.Error("webhook was not called")
	}
	store.AssertExpectations(t)
}

// TestRunAlertEscalation_DialTimeRefusesDNSRebind is the G48 regression: a
// channel URL hostname that resolves to a PUBLIC address when the channel is
// created/validated (validateWebhookURL, notification_channels.go) but to a
// PRIVATE/link-local address by the time an alert actually escalates
// (simulating a DNS-rebinding attacker) must have the escalation POST
// refused — the dial-time re-check in escalationTransport, not just the
// one-time create/update-time check, must catch it. c.httpClient is left nil
// so postJSONToURL uses the real production escalationTransport, and
// channelLookupIPAddr (the SAME resolver seam validateWebhookURL itself
// uses) is overridden to simulate the rebind end-to-end.
func TestRunAlertEscalation_DialTimeRefusesDNSRebind(t *testing.T) {
	origResolve := channelLookupIPAddr
	defer func() { channelLookupIPAddr = origResolve }()

	const rebindHost = "rebind.escalation.example"
	callCount := 0
	channelLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		require.Equal(t, rebindHost, host)
		callCount++
		if callCount == 1 {
			// The channel-creation-time validateWebhookURL lookup: a public address.
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
		}
		// Every subsequent (escalation dial-time) lookup: an RFC-1918 address.
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}

	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "medium", 30)
	p.ChannelIDs = "7"

	alert := makeAlert(1, "high", 60)
	alert.DetectedAt = now.Add(-60 * time.Minute)

	// CreateNotificationChannel runs validateWebhookURL — this is the
	// construction-time check the rebind must bypass to matter.
	c := NewKeyorixCore(store)
	c.now = fixedNow(now)
	store.On("CreateNotificationChannel", mock.Anything, mock.Anything).Return(nil)
	// #2433: CreateNotificationChannel inserts, then encrypts the URL (bound to
	// the now-known ID) and persists URLEnc/URLMeta via a second
	// UpdateNotificationChannel call.
	store.On("UpdateNotificationChannel", mock.Anything, mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	created, err := c.CreateNotificationChannel(context.Background(), &models.NotificationChannel{
		Name: "rebind-channel", Type: "webhook", URL: "https://" + rebindHost + "/hook", Enabled: true,
	}, "tester", 1)
	require.NoError(t, err, "channel creation sees a public address and must succeed")
	require.GreaterOrEqual(t, callCount, 1)

	// URLEnc (#2433), not URL: GetNotificationChannel (the core-layer wrapper
	// dispatchPolicyChannels now calls) decrypts ch.URLEnc into ch.URL -- a
	// fixture that only set the latter would read back empty.
	ch := &models.NotificationChannel{ID: 7, Name: created.Name, Type: created.Type, URLEnc: plaintextURLEnc(created.URL), Enabled: true}
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(ch, nil)

	// c.httpClient is intentionally left nil so postJSONToURL uses the real
	// production escalationTransport (not a test double), exercising the
	// actual dial-time guard.
	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated, "the escalation POST must be refused once dial-time resolution returns a private address")
	assert.Equal(t, 1, result.Skipped)
	// Assert on the SPECIFIC failure reason — "rebind.escalation.example"
	// isn't a real, resolvable domain, so a weaker assertion (mere
	// Escalated==0) would pass even without the dial-time guard, for the
	// wrong reason (a plain DNS lookup error rather than the SSRF refusal).
	assert.Contains(t, buf.String(), "disallowed address", "the failure must come from the dial-time SSRF guard, not an unrelated DNS error")
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_DisabledChannel_Skipped(t *testing.T) {
	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "medium", 30)
	p.ChannelIDs = "7"

	alert := makeAlert(1, "high", 60)
	alert.DetectedAt = now.Add(-60 * time.Minute)

	ch := &models.NotificationChannel{
		ID:      7,
		Name:    "disabled-channel",
		Type:    "webhook",
		URL:     "https://example.com/hook",
		Enabled: false,
	}

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(ch, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	assert.Equal(t, 1, result.Skipped)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_MultiplePolicies_OneMatches(t *testing.T) {
	tr := &fakeWebhookTransport{}

	store := new(MockStorage)
	now := time.Now().UTC()

	p1 := makePolicy(1, "p1", "critical", 30) // severity too high — won't match "high" alert
	p1.ChannelIDs = "7"
	p2 := makePolicy(2, "p2", "medium", 60) // matches
	p2.ChannelIDs = "7"

	alert := makeAlert(1, "high", 90) // 90 min old, severity=high
	alert.DetectedAt = now.Add(-90 * time.Minute)

	ch := &models.NotificationChannel{ID: 7, Name: "wh", Type: "webhook", URLEnc: plaintextURLEnc("https://fake-webhook.test/hook"), Enabled: true}

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p1, p2}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	// p1 fails on severity (critical > high) so no channel fetch for p1.
	// p2 matches: age 90 >= 60, severity high >= medium; fetches channel 7.
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(ch, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)
	c.httpClient = &http.Client{Transport: tr}

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 1, result.Escalated)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_InvalidChannelID_Skipped(t *testing.T) {
	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "low", 30)
	p.ChannelIDs = "not-a-number"

	alert := makeAlert(1, "low", 60)
	alert.DetectedAt = now.Add(-60 * time.Minute)

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	assert.Equal(t, 1, result.Skipped)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_ChannelFetchError_ContinuesOtherChannels(t *testing.T) {
	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "low", 30)
	p.ChannelIDs = "99" // doesn't exist

	alert := makeAlert(1, "low", 60)
	alert.DetectedAt = now.Add(-60 * time.Minute)

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(99)).Return((*models.NotificationChannel)(nil), fmt.Errorf("not found"))

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	// Channel fetch failed — dispatch didn't happen, alert counted as skipped.
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_SlackChannel_Escalated(t *testing.T) {
	received := make(chan struct{}, 1)
	tr := &fakeWebhookTransport{called: received}

	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "low", 5)
	p.ChannelIDs = "3"

	alert := makeAlert(1, "low", 10)
	alert.DetectedAt = now.Add(-10 * time.Minute)

	ch := &models.NotificationChannel{ID: 3, Name: "slack-ops", Type: "slack", URLEnc: plaintextURLEnc("https://fake-slack.test/hook"), Enabled: true}

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(3)).Return(ch, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)
	c.httpClient = &http.Client{Transport: tr}

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Escalated)
	select {
	case <-received:
	default:
		t.Error("slack webhook was not called")
	}
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_EmailChannel_NoHTTPCall(t *testing.T) {
	// Email channels don't POST — they log. Verify no panic and escalated=1.
	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "low", 5)
	p.ChannelIDs = "5"

	alert := makeAlert(1, "low", 10)
	alert.DetectedAt = now.Add(-10 * time.Minute)

	ch := &models.NotificationChannel{ID: 5, Name: "ops-email", Type: "email", Email: "ops@example.com", Enabled: true}

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(5)).Return(ch, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Escalated)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_EmptyChannelIDs_Skipped(t *testing.T) {
	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "low", 5)
	p.ChannelIDs = "" // no channels configured

	alert := makeAlert(1, "low", 10)
	alert.DetectedAt = now.Add(-10 * time.Minute)

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	assert.Equal(t, 1, result.Skipped)
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_ListPoliciesError(t *testing.T) {
	store := new(MockStorage)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return(([]models.AlertEscalationPolicy)(nil), fmt.Errorf("db error"))
	c := NewKeyorixCore(store)

	_, err := c.RunAlertEscalation(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list policies")
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_ListAlertsError(t *testing.T) {
	store := new(MockStorage)
	p := makePolicy(1, "p1", "medium", 30)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return(([]models.AnomalyAlert)(nil), fmt.Errorf("db error"))
	c := NewKeyorixCore(store)

	_, err := c.RunAlertEscalation(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list alerts")
	store.AssertExpectations(t)
}

func TestRunAlertEscalation_WebhookError_CountsSkipped(t *testing.T) {
	// Webhook returns 500; dispatch fails and alert is counted as skipped.
	tr := &fakeWebhookTransport{statusCode: http.StatusInternalServerError}

	store := new(MockStorage)
	now := time.Now().UTC()

	p := makePolicy(1, "p1", "low", 5)
	p.ChannelIDs = "8"

	alert := makeAlert(1, "low", 30)
	alert.DetectedAt = now.Add(-30 * time.Minute)

	ch := &models.NotificationChannel{ID: 8, Name: "bad-hook", Type: "webhook", URL: "https://fake-webhook.test/hook", Enabled: true}

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(8)).Return(ch, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)
	c.httpClient = &http.Client{Transport: tr}

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated)
	assert.Equal(t, 1, result.Skipped)
	store.AssertExpectations(t)
}

// ---- CRUD tests ----

func TestCreateAlertEscalationPolicy_EmptyName_Error(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	_, err := c.CreateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{
		Name:                 "",
		MinSeverity:          "medium",
		EscalateAfterMinutes: 30,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestCreateAlertEscalationPolicy_InvalidSeverity_Error(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	_, err := c.CreateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{
		Name:                 "p1",
		MinSeverity:          "extreme",
		EscalateAfterMinutes: 30,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid min_severity")
}

func TestCreateAlertEscalationPolicy_ZeroDelay_Error(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	_, err := c.CreateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{
		Name:                 "p1",
		MinSeverity:          "medium",
		EscalateAfterMinutes: 0,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escalate_after_minutes must be a positive integer")
}

func TestCreateAlertEscalationPolicy_Success(t *testing.T) {
	store := new(MockStorage)
	store.On("CreateAlertEscalationPolicy", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(store)

	p, err := c.CreateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{
		Name:                 "my-policy",
		MinSeverity:          "high",
		EscalateAfterMinutes: 60,
		ChannelIDs:           "1,2",
	})
	require.NoError(t, err)
	assert.Equal(t, "my-policy", p.Name)
	assert.False(t, p.CreatedAt.IsZero())
	store.AssertExpectations(t)
}

func TestGetAlertEscalationPolicy(t *testing.T) {
	store := new(MockStorage)
	expected := &models.AlertEscalationPolicy{ID: 5, Name: "p5"}
	store.On("GetAlertEscalationPolicy", mock.Anything, uint(5)).Return(expected, nil)
	c := NewKeyorixCore(store)

	got, err := c.GetAlertEscalationPolicy(context.Background(), 5)
	require.NoError(t, err)
	assert.Equal(t, uint(5), got.ID)
	store.AssertExpectations(t)
}

func TestListAlertEscalationPolicies(t *testing.T) {
	store := new(MockStorage)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{
		{ID: 1, Name: "a"},
		{ID: 2, Name: "b"},
	}, nil)
	c := NewKeyorixCore(store)

	list, err := c.ListAlertEscalationPolicies(context.Background())
	require.NoError(t, err)
	assert.Len(t, list, 2)
	store.AssertExpectations(t)
}

func TestUpdateAlertEscalationPolicy_Success(t *testing.T) {
	store := new(MockStorage)
	existing := &models.AlertEscalationPolicy{
		ID:                   3,
		Name:                 "old-name",
		MinSeverity:          "low",
		EscalateAfterMinutes: 15,
		ChannelIDs:           "1",
		Enabled:              true,
	}
	store.On("GetAlertEscalationPolicy", mock.Anything, uint(3)).Return(existing, nil)
	store.On("UpdateAlertEscalationPolicy", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(store)

	updated, err := c.UpdateAlertEscalationPolicy(context.Background(), 3, map[string]any{
		"name":                   "new-name",
		"min_severity":           "high",
		"escalate_after_minutes": float64(45),
		"channel_ids":            "2,3",
		"enabled":                false,
	})
	require.NoError(t, err)
	assert.Equal(t, "new-name", updated.Name)
	assert.Equal(t, "high", updated.MinSeverity)
	assert.Equal(t, 45, updated.EscalateAfterMinutes)
	assert.Equal(t, "2,3", updated.ChannelIDs)
	assert.False(t, updated.Enabled)
	store.AssertExpectations(t)
}

func TestUpdateAlertEscalationPolicy_ValidationError(t *testing.T) {
	store := new(MockStorage)
	existing := &models.AlertEscalationPolicy{
		ID:                   3,
		Name:                 "p",
		MinSeverity:          "low",
		EscalateAfterMinutes: 15,
	}
	store.On("GetAlertEscalationPolicy", mock.Anything, uint(3)).Return(existing, nil)
	c := NewKeyorixCore(store)

	_, err := c.UpdateAlertEscalationPolicy(context.Background(), 3, map[string]any{
		"min_severity": "bogus",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid min_severity")
}

func TestDeleteAlertEscalationPolicy(t *testing.T) {
	store := new(MockStorage)
	store.On("DeleteAlertEscalationPolicy", mock.Anything, uint(9)).Return(nil)
	c := NewKeyorixCore(store)

	err := c.DeleteAlertEscalationPolicy(context.Background(), 9)
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// ---- severity ordering ----

func TestSeverityOrdering(t *testing.T) {
	// low < medium < high < critical
	assert.True(t, severityAtLeast("low", "low"))
	assert.False(t, severityAtLeast("low", "medium"))
	assert.False(t, severityAtLeast("low", "high"))
	assert.False(t, severityAtLeast("low", "critical"))

	assert.True(t, severityAtLeast("medium", "low"))
	assert.True(t, severityAtLeast("medium", "medium"))
	assert.False(t, severityAtLeast("medium", "high"))
	assert.False(t, severityAtLeast("medium", "critical"))

	assert.True(t, severityAtLeast("high", "low"))
	assert.True(t, severityAtLeast("high", "medium"))
	assert.True(t, severityAtLeast("high", "high"))
	assert.False(t, severityAtLeast("high", "critical"))

	assert.True(t, severityAtLeast("critical", "low"))
	assert.True(t, severityAtLeast("critical", "medium"))
	assert.True(t, severityAtLeast("critical", "high"))
	assert.True(t, severityAtLeast("critical", "critical"))
}

func TestSeverityOrdering_UnknownValues(t *testing.T) {
	assert.False(t, severityAtLeast("unknown", "medium"))
	assert.False(t, severityAtLeast("high", "unknown"))
}

// ---- splitChannelIDs ----

func TestSplitChannelIDs(t *testing.T) {
	assert.Equal(t, []string{"1", "2", "3"}, splitChannelIDs("1,2,3"))
	assert.Equal(t, []string{"1", "2"}, splitChannelIDs(" 1 , 2 "))
	assert.Nil(t, splitChannelIDs(""))
	assert.Nil(t, splitChannelIDs(",,,"))
}

// TestDispatchToChannel_WebhookRedactsPIIEmbeddedInDescription is #G30: several
// alert types (new_ip, new_user, ml_outlier, principal_breadth) embed the
// alert's own AccessedBy/IPAddress as free text inside Description — which
// used to bypass the accessed_by/ip_address structured-field redaction this
// path already applies. The outbound JSON payload must not contain either
// value anywhere, including inside "description".
func TestDispatchToChannel_WebhookRedactsPIIEmbeddedInDescription(t *testing.T) {
	var body []byte
	tr := &fakeWebhookTransport{capture: func(b []byte) { body = b }}

	c := NewKeyorixCore(new(MockStorage))
	c.httpClient = &http.Client{Transport: tr}

	alert := makeAlert(1, "high", 60)
	alert.AccessedBy = "alice"
	alert.IPAddress = "203.0.113.7"
	alert.Description = fmt.Sprintf("ML detected an anomalous access pattern (score 0.92): %s from %s at 14:00 UTC differs from this secret's learned baseline",
		alert.AccessedBy, alert.IPAddress)

	ch := &models.NotificationChannel{ID: 7, Name: "test-webhook", Type: "webhook", URL: "https://fake-webhook.test/hook", Enabled: true}
	policy := makePolicy(1, "p1", "medium", 30)

	require.NoError(t, c.dispatchToChannel(context.Background(), ch, &alert, &policy))
	require.NotNil(t, body)
	assert.NotContains(t, string(body), "alice", "accessed_by embedded in Description must be redacted")
	assert.NotContains(t, string(body), "203.0.113.7", "ip_address embedded in Description must be redacted")
	assert.Contains(t, string(body), "[redacted]")
	assert.Contains(t, string(body), "ML detected an anomalous access pattern", "the rest of the description must survive")
}

// ---- dispatchToChannel (teams type) ----

func TestDispatchToChannel_TeamsType_LogOnly(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	ch := &models.NotificationChannel{ID: 1, Name: "teams-ch", Type: "teams", URL: "https://teams.example.com/hook", Enabled: true}
	alert := &models.AnomalyAlert{ID: 1, Severity: "high", AlertType: "off_hours", Description: "x"}
	policy := &models.AlertEscalationPolicy{ID: 1, Name: "p"}

	err := c.dispatchToChannel(context.Background(), ch, alert, policy)
	require.NoError(t, err) // teams = log only, no error
}

// ---- postJSONToURL error path ----

func TestPostJSONToURL_NetworkError(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	// Point to a non-existent URL to trigger a network error.
	err := c.postJSONToURL(context.Background(), "http://127.0.0.1:1", map[string]string{"key": "val"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "POST")
}

// ---- validateEscalationPolicy ----

func TestValidateEscalationPolicy_AllSeverities(t *testing.T) {
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		p := &models.AlertEscalationPolicy{Name: "p", MinSeverity: sev, EscalateAfterMinutes: 1}
		assert.NoError(t, validateEscalationPolicy(p), "severity %s should be valid", sev)
	}
}

// ---- CreateAlertEscalationPolicy storage error ----

func TestCreateAlertEscalationPolicy_StorageError(t *testing.T) {
	store := new(MockStorage)
	store.On("CreateAlertEscalationPolicy", mock.Anything, mock.Anything).Return(fmt.Errorf("db error"))
	c := NewKeyorixCore(store)

	_, err := c.CreateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{
		Name:                 "p",
		MinSeverity:          "medium",
		EscalateAfterMinutes: 30,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
	store.AssertExpectations(t)
}

// ---- UpdateAlertEscalationPolicy storage error path ----

func TestUpdateAlertEscalationPolicy_StorageError(t *testing.T) {
	store := new(MockStorage)
	existing := &models.AlertEscalationPolicy{
		ID:                   1,
		Name:                 "p",
		MinSeverity:          "medium",
		EscalateAfterMinutes: 30,
	}
	store.On("GetAlertEscalationPolicy", mock.Anything, uint(1)).Return(existing, nil)
	store.On("UpdateAlertEscalationPolicy", mock.Anything, mock.Anything).Return(fmt.Errorf("storage failure"))
	c := NewKeyorixCore(store)

	_, err := c.UpdateAlertEscalationPolicy(context.Background(), 1, map[string]any{
		"name": "new-name",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage failure")
	store.AssertExpectations(t)
}

// ---- UpdateAlertEscalationPolicy get error path ----

func TestUpdateAlertEscalationPolicy_GetError(t *testing.T) {
	store := new(MockStorage)
	store.On("GetAlertEscalationPolicy", mock.Anything, uint(99)).Return((*models.AlertEscalationPolicy)(nil), fmt.Errorf("not found"))
	c := NewKeyorixCore(store)

	_, err := c.UpdateAlertEscalationPolicy(context.Background(), 99, map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertExpectations(t)
}

// ---- postJSONToURL marshal error ----

// unmarshalableValue is an un-serialisable type (channel) to trigger json.Marshal error.
type unmarshalableValue struct {
	Ch chan int
}

func TestPostJSONToURL_MarshalError(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	// channels are not serializable by encoding/json
	err := c.postJSONToURL(context.Background(), "http://localhost:9", unmarshalableValue{Ch: make(chan int)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal payload")
}

// ---- RunAlertEscalation with two+ active policies (covers minDelay update branch) ----

func TestRunAlertEscalation_MultiPolicyMinDelayUpdate(t *testing.T) {
	tr := &fakeWebhookTransport{}

	store := new(MockStorage)
	now := time.Now().UTC()

	// Two policies with different delays; p2 has a shorter delay (10 min < 60 min).
	// This exercises the minDelay update branch.
	p1 := makePolicy(1, "slow-policy", "low", 60)
	p1.ChannelIDs = ""
	p2 := makePolicy(2, "fast-policy", "low", 10)
	p2.ChannelIDs = "2"

	// Alert 15 min old — old enough for p2 (10 min) but not p1 (60 min).
	alert := makeAlert(1, "low", 15)
	alert.DetectedAt = now.Add(-15 * time.Minute)

	ch := &models.NotificationChannel{ID: 2, Name: "wh", Type: "webhook", URLEnc: plaintextURLEnc("https://fake-webhook.test/hook"), Enabled: true}

	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p1, p2}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(2)).Return(ch, nil)

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)
	c.httpClient = &http.Client{Transport: tr}

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 1, result.Escalated)
	store.AssertExpectations(t)
}

// ---- coordinator review, PR #2249: real actor on admin-job "ran" events ----

// TestRunAlertEscalation_AttributesRealActorFromContext proves the
// run-alert-escalation "job ran" summary event carries the REAL triggering
// caller's ID when one exists (WithAuditActor, set by the admin-jobs HTTP
// handler before invoking this shared core function) -- before this fix,
// every one of these summary events hardcoded a nil actor regardless of
// caller, so a manual admin trigger of this security-relevant job was
// indistinguishable from an unattributed scheduler run.
func TestRunAlertEscalation_AttributesRealActorFromContext(t *testing.T) {
	store := new(MockStorage)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{}, nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)
	c := NewKeyorixCore(store)

	const actorID = uint(4242)
	_, err := c.RunAlertEscalation(WithAuditActor(context.Background(), actorID))
	require.NoError(t, err)

	require.NotNil(t, captured, "a zero-policy run must still leave an audit trail")
	require.NotNil(t, captured.UserID, "an admin-triggered run must attribute the real actor, not nil")
	assert.Equal(t, actorID, *captured.UserID)
}

// TestRunAlertEscalation_NoActorTag_NilActor proves the scheduler's own
// untagged-context runs still correctly report no actor -- the fix above
// must not force attribution onto a run that genuinely has no human caller.
func TestRunAlertEscalation_NoActorTag_NilActor(t *testing.T) {
	store := new(MockStorage)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{}, nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)
	c := NewKeyorixCore(store)

	_, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)

	require.NotNil(t, captured)
	assert.Nil(t, captured.UserID, "an untagged (scheduler) run must not fabricate an actor")
}

// ---- coordinator review, PR #2249: escalation-policy audit redaction ----

// TestLogAlertEscalationPolicyCreated_RedactsChannelIDs proves the audit
// event for a policy CREATE never carries the raw ChannelIDs -- a policy's
// wiring reveals which NotificationChannels (webhook/Slack/Teams targets,
// potentially secret-bearing URLs) it dispatches to, so the audit view
// reports only a channel COUNT.
func TestLogAlertEscalationPolicyCreated_RedactsChannelIDs(t *testing.T) {
	store := new(MockStorage)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)
	c := NewKeyorixCore(store)

	p := &models.AlertEscalationPolicy{
		ID: 7, Name: "sev1-page", MinSeverity: "critical", EscalateAfterMinutes: 5,
		ChannelIDs: "3,4,5", Enabled: true,
	}
	c.LogAlertEscalationPolicyCreated(context.Background(), 100, p)

	require.NotNil(t, captured)
	assert.Contains(t, captured.Diff, "sev1-page", "non-secret fields must still be audited")
	assert.Contains(t, captured.Diff, `"channel_count":3`, "channel wiring must be reported as a count")
	assert.NotContains(t, captured.Diff, "3,4,5", "the raw channel_ids must never appear in the audit trail")
	assert.NotContains(t, captured.Diff, "channel_ids", "the channel_ids field name itself must not appear -- confirms the allowlisted view, not a redacted-value substitution")
}

// TestLogAlertEscalationPolicyUpdated_CarriesBeforeDiff proves before is a
// real prior snapshot, not the hardcoded nil the original implementation
// passed -- an incident investigation needs to see what a policy's severity
// threshold or delay changed FROM, not just what it changed to.
func TestLogAlertEscalationPolicyUpdated_CarriesBeforeDiff(t *testing.T) {
	store := new(MockStorage)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)
	c := NewKeyorixCore(store)

	before := &models.AlertEscalationPolicy{ID: 8, Name: "sev1-page", MinSeverity: "high", EscalateAfterMinutes: 30, ChannelIDs: "1", Enabled: true}
	after := &models.AlertEscalationPolicy{ID: 8, Name: "sev1-page", MinSeverity: "critical", EscalateAfterMinutes: 5, ChannelIDs: "1,2", Enabled: true}
	c.LogAlertEscalationPolicyUpdated(context.Background(), 100, before, after)

	require.NotNil(t, captured)
	assert.Contains(t, captured.Diff, `"min_severity":"high"`, "the diff must carry the PRIOR min_severity")
	assert.Contains(t, captured.Diff, `"min_severity":"critical"`, "the diff must carry the NEW min_severity")
	assert.Contains(t, captured.Diff, `"escalate_after_minutes":30`, "the diff must carry the PRIOR delay")
	assert.Contains(t, captured.Diff, `"escalate_after_minutes":5`, "the diff must carry the NEW delay")
}

// TestLogAlertEscalationPolicyUpdated_NilBefore_OmitsBeforeSide proves a nil
// before (the handler's best-effort pre-fetch failed) degrades to an
// after-only diff rather than panicking on a nil dereference.
func TestLogAlertEscalationPolicyUpdated_NilBefore_OmitsBeforeSide(t *testing.T) {
	store := new(MockStorage)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)
	c := NewKeyorixCore(store)

	after := &models.AlertEscalationPolicy{ID: 9, Name: "sev1-page", MinSeverity: "critical", EscalateAfterMinutes: 5, Enabled: true}
	require.NotPanics(t, func() {
		c.LogAlertEscalationPolicyUpdated(context.Background(), 100, nil, after)
	})

	require.NotNil(t, captured)
	assert.NotContains(t, captured.Diff, `"before"`, "a nil before must be omitted (omitempty), not serialized as an empty/zero-value struct")
	assert.Contains(t, captured.Diff, `"min_severity":"critical"`)
}
