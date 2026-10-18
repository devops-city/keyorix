package core

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3426: a channel URL is a bearer credential (Slack-style tokens live in the
// path). url.URL.Redacted() masks only userinfo, so postJSONToURL's error --
// and every log line built from it -- used to carry the full path token.
const (
	secretToken      = "SUPERSECRETTOKEN"
	secretChannelURL = "https://hooks.slack.test/services/T000/B000/" + secretToken
)

// captureSecretLog redirects the std logger for the test and returns a reader of
// everything logged.
func captureSecretLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPostJSONToURL_ReceiverErrorDoesNotLeakPathToken(t *testing.T) {
	logs := captureSecretLog(t)
	c := NewKeyorixCore(new(MockStorage))
	c.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: http.NoBody, Request: r}, nil
	})}

	err := c.postJSONToURL(context.Background(), secretChannelURL, map[string]string{"k": "v"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretToken)
	assert.Contains(t, err.Error(), "hooks.slack.test", "the failing destination host must stay diagnosable")
	assert.Contains(t, err.Error(), "500")

	// The log line the broadcast path builds from the error.
	log.Printf("recover-admin alert: channel %q: dispatch failed: %v", "c", err)
	assert.NotContains(t, logs.String(), secretToken)
}

func TestPostJSONToURL_TransportErrorDoesNotLeakPathToken(t *testing.T) {
	logs := captureSecretLog(t)
	c := NewKeyorixCore(new(MockStorage))
	boom := errors.New("dial tcp 203.0.113.9:443: connect: connection refused")
	// A real http.Client wraps whatever the transport returns in a *url.Error
	// carrying the full request URL.
	c.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, boom })}

	err := c.postJSONToURL(context.Background(), secretChannelURL, map[string]string{"k": "v"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretToken)
	assert.Contains(t, err.Error(), "hooks.slack.test")
	assert.Contains(t, err.Error(), "connection refused", "the cause must stay in the message")
	assert.ErrorIs(t, err, boom, "stripping the URL must not break errors.Is on the cause")
	for e := error(err); e != nil; {
		assert.NotContains(t, e.Error(), secretToken, "no layer of the chain may render the token")
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}

	log.Printf("alert escalation: policy %d: channel %d: dispatch failed: %v", 1, 2, err)
	assert.NotContains(t, logs.String(), secretToken)
}

// The send-time refusal path embeds the validator's error; the stored URL must
// not ride along (a stored URL that no longer parses is the case that used to
// print itself via %q and the wrapped url.Parse error).
func TestPostJSONToURL_RefusedStoredURLDoesNotLeakPathToken(t *testing.T) {
	for name, target := range map[string]string{
		"plaintext scheme":  "http://hooks.slack.test/services/T000/B000/" + secretToken,
		"unparseable":       "https://hooks.slack.test/services/T000/B000/" + secretToken + "\x7f",
		"internal literal":  "https://10.0.0.5/services/T000/B000/" + secretToken,
		"unparseable port":  "https://hooks.slack.test:notaport/services/T000/B000/" + secretToken,
		"opaque control ch": "https://hooks.slack.test/services/T000/B000/" + secretToken + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			logs := captureSecretLog(t)
			c := NewKeyorixCore(new(MockStorage))
			c.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("refused URL must never reach the transport")
				return nil, nil
			})}
			err := c.postJSONToURL(context.Background(), target, map[string]string{"k": "v"})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), secretToken)
			log.Printf("%v", err)
			assert.NotContains(t, logs.String(), secretToken)
		})
	}
}

// Every other place the channel URL can reach an error string or log line:
// create/update validation (its error is returned verbatim to the HTTP client
// and may be logged), the audit diff, and the recover-admin broadcast.
func TestValidateNotificationChannel_ErrorDoesNotEchoPathToken(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	for name, u := range map[string]string{
		"http scheme":  "http://hooks.slack.test/services/T000/B000/" + secretToken,
		"unparseable":  "https://hooks.slack.test/services/T000/B000/" + secretToken + "\x7f",
		"private host": "https://10.0.0.5/services/T000/B000/" + secretToken,
	} {
		t.Run(name, func(t *testing.T) {
			err := c.validateNotificationChannel(&models.NotificationChannel{Name: "n", Type: "slack", URL: u})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), secretToken)
		})
	}
}

func TestBroadcastRecoverAdminAlert_DispatchFailureLogDoesNotLeakPathToken(t *testing.T) {
	logs := captureSecretLog(t)
	c := NewKeyorixCore(new(MockStorage))
	c.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection reset by peer")
	})}
	c.broadcastRecoverAdminAlert(context.Background(), &models.AuditEvent{ID: 1},
		[]*models.NotificationChannel{{Name: "ops", Type: "slack", URL: secretChannelURL, Enabled: true}})
	assert.Contains(t, logs.String(), "dispatch failed")
	assert.NotContains(t, logs.String(), secretToken)
}

func TestDispatchPolicyChannels_DispatchFailureLogDoesNotLeakPathToken(t *testing.T) {
	logs := captureSecretLog(t)
	store := new(MockStorage)
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(&models.NotificationChannel{
		ID: 7, Name: "ops", Type: "slack", URLEnc: plaintextURLEnc(secretChannelURL), Enabled: true,
	}, nil)
	c := NewKeyorixCore(store)
	c.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection reset by peer")
	})}
	sent := c.dispatchPolicyChannels(context.Background(), &models.AnomalyAlert{ID: 1},
		&models.AlertEscalationPolicy{ID: 1, ChannelIDs: "7"})
	assert.False(t, sent)
	assert.Contains(t, logs.String(), "dispatch failed")
	assert.NotContains(t, logs.String(), secretToken)
}

// The audit before/after diff must never carry the URL, on create, update and
// delete. Pin it across the three writers, capturing the real diff JSON.
func TestNotificationChannelAudit_NeverCarriesURL(t *testing.T) {
	store := new(MockStorage)
	var diffs []string
	store.On("CreateNotificationChannel", mock.Anything, mock.Anything).Return(nil)
	store.On("UpdateNotificationChannel", mock.Anything, mock.Anything).Return(nil)
	store.On("DeleteNotificationChannel", mock.Anything, mock.Anything).Return(nil)
	store.On("GetNotificationChannel", mock.Anything, uint(0)).Return(&models.NotificationChannel{
		Name: "ops", Type: "slack", URLEnc: plaintextURLEnc(secretChannelURL), Enabled: true,
	}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if ev, ok := args.Get(1).(*models.AuditEvent); ok {
			diffs = append(diffs, ev.Description+" "+string(ev.Diff))
		}
	}).Return(nil)
	c := NewKeyorixCore(store)
	c.webhookURLValidator = func(string) error { return nil }

	_, err := c.CreateNotificationChannel(context.Background(), &models.NotificationChannel{Name: "ops", Type: "slack", URL: secretChannelURL, Enabled: true}, "tester", 1)
	require.NoError(t, err)
	_, err = c.UpdateNotificationChannel(context.Background(), 0, map[string]any{"url": secretChannelURL + "2", "enabled": false}, 1)
	require.NoError(t, err)
	require.NoError(t, c.DeleteNotificationChannel(context.Background(), 0, 1))

	require.NotEmpty(t, diffs, "the audit writer was never reached; the test proves nothing")
	for _, d := range diffs {
		assert.False(t, strings.Contains(d, secretToken), "audit row leaked the channel URL: %s", d)
	}
}
