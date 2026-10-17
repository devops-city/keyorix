package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostJSONToURL_RefusesInternalLiteralAtSendTime is the #1209 regression:
// postJSONToURL must re-validate the destination on every send, not rely on the
// create/update-time check alone. An injected c.httpClient (no dial guard) is
// used so the only thing that can stop the request is the send-time check; on
// main the fake transport is reached for every URL below.
func TestPostJSONToURL_RefusesInternalLiteralAtSendTime(t *testing.T) {
	for _, target := range []string{
		"https://169.254.169.254/latest/meta-data/",
		"https://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://10.0.0.5/hook",
		"https://[64:ff9b::a9fe:a9fe]/hook", // NAT64-encoded IMDS
		"http://203.0.113.7/hook",           // plaintext scheme
	} {
		t.Run(target, func(t *testing.T) {
			reached := make(chan struct{}, 1)
			c := NewKeyorixCore(new(MockStorage))
			c.httpClient = &http.Client{Transport: &fakeWebhookTransport{called: reached}}

			err := c.postJSONToURL(context.Background(), target, map[string]string{"k": "v"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "refused")
			select {
			case <-reached:
				t.Fatal("request reached the transport despite a disallowed destination")
			default:
			}
		})
	}
}

// Green direction: a public https literal still goes out.
func TestPostJSONToURL_AllowsPublicLiteralAtSendTime(t *testing.T) {
	reached := make(chan struct{}, 1)
	c := NewKeyorixCore(new(MockStorage))
	c.httpClient = &http.Client{Transport: &fakeWebhookTransport{called: reached}}

	require.NoError(t, c.postJSONToURL(context.Background(), "https://203.0.113.7/hook", map[string]string{"k": "v"}))
	select {
	case <-reached:
	default:
		t.Fatal("public destination was not sent")
	}
}
