package k8ssync

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// RESTSink — remaining request-build error branches. These call the sink's
// (mostly unexported) methods directly with a deliberately invalid host or
// an unmarshalable payload, since the exported entry points (Apply/Delete)
// always route through a prior getOwnedMeta call on the same host+path, so a
// bad host fails there first and never reaches these methods' own build step.
// ---------------------------------------------------------------------------

// invalidHostSink returns a RESTSink whose host makes http.NewRequestWithContext
// fail deterministically (a control character in the URL), mirroring
// TestRESTSink_newRequest_InvalidURL in k8ssync_s23_test.go.
func invalidHostSink() *RESTSink {
	return &RESTSink{host: "http://\x00invalid", token: "tok", fieldManager: "keyorix-sync", hc: &http.Client{}}
}

func TestRESTSink_Get_InvalidURL(t *testing.T) {
	_, err := invalidHostSink().Get(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRESTSink_createSecret_InvalidURL(t *testing.T) {
	err := invalidHostSink().createSecret(context.Background(), "ns", "name", map[string]any{"kind": "Secret"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

// TestRESTSink_createSecret_MarshalError exercises the json.Marshal error branch
// directly: a channel value can never be marshaled to JSON, and this is otherwise
// unreachable via Apply since the payloads Apply builds are always plain
// strings/maps.
func TestRESTSink_createSecret_MarshalError(t *testing.T) {
	sink := testSinkHost("http://example.invalid")
	err := sink.createSecret(context.Background(), "ns", "name", map[string]any{"bad": make(chan int)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal secret")
}

func TestRESTSink_applyOwnedSecret_InvalidURL(t *testing.T) {
	err := invalidHostSink().applyOwnedSecret(context.Background(), "ns", "name", map[string]any{"kind": "Secret"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

// TestRESTSink_applyOwnedSecret_MarshalError mirrors
// TestRESTSink_createSecret_MarshalError for the update path.
func TestRESTSink_applyOwnedSecret_MarshalError(t *testing.T) {
	sink := testSinkHost("http://example.invalid")
	err := sink.applyOwnedSecret(context.Background(), "ns", "name", map[string]any{"bad": make(chan int)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal secret")
}

func TestRESTSink_List_InvalidURL(t *testing.T) {
	_, err := invalidHostSink().List(context.Background(), "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRESTSink_getOwnedMeta_InvalidURL(t *testing.T) {
	_, _, exists, owned, err := invalidHostSink().getOwnedMeta(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
	assert.False(t, exists)
	assert.False(t, owned)
}

// testSinkHost builds a RESTSink pointed at host without a live server — used only
// for the marshal-error tests above, where the request is never actually sent.
func testSinkHost(host string) *RESTSink {
	return &RESTSink{host: host, token: "tok", fieldManager: "keyorix-sync", hc: &http.Client{}}
}

// ---------------------------------------------------------------------------
// KeyorixFetcher.getJSON — request-build error branch.
// ---------------------------------------------------------------------------

// TestKeyorixFetcher_getJSON_InvalidURL exercises getJSON's http.NewRequestWithContext
// error branch: baseURL itself passes validateFetcherBaseURL (a loopback http URL),
// but the request path carries a control character that makes the concatenated URL
// unparseable.
func TestKeyorixFetcher_getJSON_InvalidURL(t *testing.T) {
	f := NewKeyorixFetcher("http://127.0.0.1:9", "tok", 1)
	var out struct{}
	err := f.getJSON(context.Background(), "/\x00bad", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}
