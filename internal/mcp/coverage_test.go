package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- Serve: parse error path -------------------------------------------------

// TestServe_ParseError exercises the branch where the incoming stream contains
// unparseable JSON. Serve should write a parse-error response and then return
// the underlying decode error (not nil).
func TestServe_ParseError(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	var out bytes.Buffer
	err := s.Serve(context.Background(), strings.NewReader("{bad json"), &out)
	// Serve must return the decode error, not nil.
	require.Error(t, err)
	// The response written before returning must be a parse-error response.
	dec := json.NewDecoder(&out)
	var resp rpcResponse
	require.NoError(t, dec.Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, codeParseError, resp.Error.Code)
}

// TestServe_EncodeError exercises the branch where writing the response to the
// writer fails. Serve should surface the encoder error.
func TestServe_EncodeError(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	pr, pw := io.Pipe()
	// Close the write-end of the reader immediately so the goroutine's pipe
	// writer (to our errWriter) fails.
	_ = pr.Close()

	// Use an io.Pipe to get a reader+writer pair:
	// feed a valid request to Serve but have the writer reject writes.
	r := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	err := s.Serve(context.Background(), r, pw)
	_ = pw.Close()
	// Serve must return an error when it cannot write the response.
	require.Error(t, err)
}

// -- callTool: empty params --------------------------------------------------

// TestCallTool_EmptyParams covers the len(params)==0 branch in callTool.
func TestCallTool_EmptyParams(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	// tools/call with no params field at all → callTool receives nil/empty JSON.
	resps := run(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	require.Len(t, resps, 1)
	require.NotNil(t, resps[0].Error)
	assert.Equal(t, codeInvalidParams, resps[0].Error.Code)
}

// TestCallTool_InvalidParamsJSON covers the json.Unmarshal failure branch in callTool.
func TestCallTool_InvalidParamsJSON(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	resps := run(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`)
	require.Len(t, resps, 1)
	require.NotNil(t, resps[0].Error)
	assert.Equal(t, codeInvalidParams, resps[0].Error.Code)
}

// -- toolListSecrets: shown==0 branch ----------------------------------------

// TestToolListSecrets_NoVisible covers the "no secrets visible to this token"
// branch when the reader returns an empty list.
func TestToolListSecrets_NoVisible(t *testing.T) {
	fr := &fakeReader{list: []SecretInfo{}}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	assert.Contains(t, text, "no secrets visible")
}

// TestToolListSecrets_AllFilteredByAllowList covers the shown==0 branch when
// allowedRefs filters out every entry returned by the reader.
func TestToolListSecrets_AllFilteredByAllowList(t *testing.T) {
	fr := &fakeReader{list: []SecretInfo{{Ref: "app/prod/db"}, {Ref: "app/prod/api"}}}
	s := NewServer(fr, "")
	s.SetAllowedRefs([]string{"other/env/*"}) // nothing matches
	resps := run(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	assert.Contains(t, text, "no secrets visible")
}

// TestToolListSecrets_Error covers the error return from the reader.
func TestToolListSecrets_Error(t *testing.T) {
	fr := &fakeReader{listErr: errTest}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	assert.Equal(t, true, res["isError"])
	assert.Equal(t, genericListError, res["content"].([]any)[0].(map[string]any)["text"])
}

// errTest is a sentinel error used across these tests.
var errTest = errSentinel("test error")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

// -- validateKeyorixClientURL: uncovered branches -------------------------------------

// TestRequireHTTPSURL_InvalidURL covers the url.Parse error / empty host branch.
func TestRequireHTTPSURL_InvalidURL(t *testing.T) {
	// An empty string produces a URL with no host.
	err := validateKeyorixClientURL("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid KEYORIX_URL")

	// A relative path also has no host.
	err2 := validateKeyorixClientURL("/no-host/path")
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "invalid KEYORIX_URL")
}

// TestRequireHTTPSURL_UnknownScheme covers the default case (not http or https).
func TestRequireHTTPSURL_UnknownScheme(t *testing.T) {
	err := validateKeyorixClientURL("ftp://keyorix.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https")
}

// -- getJSON: empty data branch ----------------------------------------------

// TestGetJSON_EmptyData covers the "empty data in response" branch where the
// server returns a 200 with a non-null envelope but nil/absent "data" field.
func TestGetJSON_EmptyData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"other_field":"value"}`))
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, err := c.GetSecret(context.Background(), "app/prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

// TestGetJSON_MalformedJSON covers the json decode failure in getJSON.
func TestGetJSON_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, err := c.GetSecret(context.Background(), "app/prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode response")
}

// TestGetJSON_RequestBuildError exercises the request-build failure path by
// using a context that is already cancelled — the client.Do call should fail.
func TestGetJSON_RequestFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"value":"v"}}`))
	}))
	srv.Close() // close immediately so the request fails

	c := mustClient(t, srv.URL, "tok")
	_, err := c.GetSecret(context.Background(), "app/prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// -- ListSecrets: getJSON error ----------------------------------------------

// TestListSecrets_HTTPError covers the error-return path in ListSecrets when
// the server returns a non-2xx status.
func TestListSecrets_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, _, err := c.ListSecrets(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

// -- MCP-002: response body size cap -----------------------------------------

// TestGetJSON_LargeBodyCapped verifies that getJSON refuses to decode a response
// body exceeding 10 MiB, preventing memory exhaustion from a hostile or broken
// server sending an enormous payload.
func TestGetJSON_LargeBodyCapped(t *testing.T) {
	// Build a response that exceeds the 10 MiB cap: valid JSON envelope followed
	// by 11 MiB of whitespace inside the "data" object — the decoder will hit the
	// limit before finishing the read and return a decode error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid prefix, then fill well past 10 MiB so LimitReader truncates.
		_, _ = w.Write([]byte(`{"data":{"value":"`))
		pad := make([]byte, 11<<20) // 11 MiB of 'A'
		for i := range pad {
			pad[i] = 'A'
		}
		_, _ = w.Write(pad)
		_, _ = w.Write([]byte(`"}}`))
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, err := c.GetSecret(context.Background(), "app/prod/db")
	// Either a decode error (truncated JSON) or an oversized value — either way, must fail.
	require.Error(t, err)
}

// -- MCP-003: ref format validation ------------------------------------------

// TestToolGetSecret_RefTooLong verifies that a ref exceeding 512 characters is
// rejected before reaching the network.
func TestToolGetSecret_RefTooLong(t *testing.T) {
	long := "a/b/" + strings.Repeat("x", 510) // > 512 total
	resps := run(t, NewServer(&fakeReader{value: "v"}, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"`+long+`"}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	assert.Equal(t, true, res["isError"])
	assert.Contains(t, res["content"].([]any)[0].(map[string]any)["text"], "project/environment/name")
}

// TestToolGetSecret_RefWrongSegments verifies that a ref without exactly three
// slash-separated segments is rejected.
func TestToolGetSecret_RefWrongSegments(t *testing.T) {
	cases := []string{
		"no-slashes",
		"only/two",
		"too/many/slashes/here",
	}
	for _, ref := range cases {
		resps := run(t, NewServer(&fakeReader{value: "v"}, ""),
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"`+ref+`"}}}`)
		require.Len(t, resps, 1)
		res := resultMap(t, resps[0])
		assert.Equal(t, true, res["isError"], "ref %q should be rejected", ref)
	}
}

// TestToolGetSecret_RefEmptySegment verifies that a ref with an empty segment
// (e.g. "/env/name" or "proj//name") is rejected.
func TestToolGetSecret_RefEmptySegment(t *testing.T) {
	cases := []string{"/env/name", "proj//name", "proj/env/"}
	for _, ref := range cases {
		resps := run(t, NewServer(&fakeReader{value: "v"}, ""),
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"`+ref+`"}}}`)
		require.Len(t, resps, 1)
		res := resultMap(t, resps[0])
		assert.Equal(t, true, res["isError"], "ref %q should be rejected", ref)
	}
}

// -- MCP-005: pagination truncation warning ----------------------------------

// TestListSecrets_Truncated verifies that when the upstream returns a full page
// (≥100 secrets), toolListSecrets appends a truncation notice to the result so
// the agent knows to re-query with an environment filter.
func TestListSecrets_Truncated(t *testing.T) {
	// Build exactly 100 secrets so the fakeReader signals truncated=true.
	infos := make([]SecretInfo, 100)
	for i := range infos {
		infos[i] = SecretInfo{Ref: "app/prod/db"}
	}
	fr := &fakeReader{list: infos, listTruncated: true}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	assert.NotEqual(t, true, res["isError"])
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	assert.Contains(t, text, "results may be incomplete")
	assert.Contains(t, text, "environment filter")
}

// TestListSecrets_NotTruncated verifies that when the upstream returns fewer
// than 100 secrets, no truncation notice appears.
func TestListSecrets_NotTruncated(t *testing.T) {
	fr := &fakeReader{list: []SecretInfo{{Ref: "app/prod/db"}}, listTruncated: false}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	assert.NotEqual(t, true, res["isError"])
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	assert.NotContains(t, text, "incomplete")
}

// -- getJSON: request-build failure -------------------------------------------

// TestGetJSON_BuildRequestError covers the http.NewRequestWithContext error
// branch in getJSON. Every public constructor path (NewKeyorixClient) percent-
// encodes user input via url.Values.Encode() before it ever reaches getJSON, so
// this branch is unreachable through the exported API — it's exercised here by
// constructing the client directly (same package) with a path whose invalid
// percent-encoding survives to the request-build call.
func TestGetJSON_BuildRequestError(t *testing.T) {
	c := &KeyorixClient{baseURL: "http://example.com", token: "tok", hc: http.DefaultClient}
	var out struct{}
	err := c.getJSON(context.Background(), "/bad%zz", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

// -- toolListSecrets: maxListCalls cap branch --------------------------------

// TestToolListSecrets_MaxListCallsCapReached covers the maxListCalls>0 &&
// listCallCount>=maxListCalls branch in toolListSecrets (tools.go). As the
// TestServe_SetMaxListCalls doc comment in server_test.go explains, nothing in
// tools.go ever increments s.listCallCount, so this branch is unreachable
// through the public tools/call JSON-RPC surface today (a pre-existing bug,
// out of scope for a test-coverage task to fix). It IS reachable, and worth
// covering, as a white-box call directly against the unexported method with
// listCallCount pre-set to simulate the cap already being exhausted — this
// asserts the real behavior the cap is supposed to have (refuse the call with
// the generic error, and never touch the reader) once/if that increment bug
// is fixed, without touching production code.
func TestToolListSecrets_MaxListCallsCapReached(t *testing.T) {
	fr := &fakeReader{list: []SecretInfo{{Ref: "app/prod/db"}}}
	s := NewServer(fr, "")
	s.SetMaxListCalls(1)
	s.listCallCount.Store(1) // simulate the cap already reached

	res := s.toolListSecrets(context.Background(), json.RawMessage(`{}`))

	assert.Equal(t, true, res["isError"], "the call must be refused once the cap is reached")
	content := res["content"].([]map[string]any)
	assert.Equal(t, genericListError, content[0]["text"], "must return the generic list error, not leak detail")
	assert.False(t, fr.listCalled, "the reader must never be consulted once the cap has refused the call")
}

// TestKeyorixClient_ListSecretsTruncated verifies that the KeyorixClient sets
// the truncated flag when the server returns exactly 100 secrets.
func TestKeyorixClient_ListSecretsTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Build a response with exactly 100 secrets.
		type sec struct {
			Name            string `json:"Name"`
			Type            string `json:"Type"`
			ProjectName     string `json:"project_name"`
			EnvironmentName string `json:"environment_name"`
		}
		type resp struct {
			Secrets []sec `json:"secrets"`
		}
		secrets := make([]sec, 100)
		for i := range secrets {
			secrets[i] = sec{Name: "s", ProjectName: "p", EnvironmentName: "e", Type: "password"}
		}
		b, _ := json.Marshal(map[string]any{"data": resp{Secrets: secrets}})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, truncated, err := c.ListSecrets(context.Background(), "")
	require.NoError(t, err)
	assert.True(t, truncated, "100 secrets returned → truncated must be true")
}
