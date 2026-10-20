package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// A webhook URL is a credential (its path carries the token), so it never travels on
// argv: --url is refused, --url-file <path|-> supplies it, and `channel get` shows only
// what the server returns, which is the elided form.
const (
	canaryChannelURL = "https://hooks.slack.test/services/T000/B000/CANARYtoken1234"
	elidedChannelURL = "https://hooks.slack.test/…"
)

type channelServer struct {
	mu      sync.Mutex
	calls   []string
	bodies  []map[string]any
	getJSON string
}

func newChannelServer(t *testing.T) (*channelServer, *httptest.Server) {
	t.Helper()
	cs := &channelServer{
		getJSON: `{"data":{"channels":[{"id":7,"name":"ops-slack","type":"slack","enabled":true,"url":"` + elidedChannelURL + `","url_set":true,"events":"","created_by":"admin"}]}}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/version" {
			_, _ = io.WriteString(w, `{"api_version":1,"minimum_cli_version":"1.0.0"}`)
			return
		}
		cs.mu.Lock()
		defer cs.mu.Unlock()
		cs.calls = append(cs.calls, r.Method+" "+r.URL.Path)
		if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
			var m map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &m)
			cs.bodies = append(cs.bodies, m)
		}
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"data":{"id":7,"name":"ops-slack","type":"slack","url":"`+canaryChannelURL+`","url_set":true}}`)
		case http.MethodGet:
			_, _ = io.WriteString(w, cs.getJSON)
		default:
			_, _ = io.WriteString(w, `{"data":{"id":7,"name":"ops-slack","type":"slack","url":"`+elidedChannelURL+`","url_set":true}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return cs, srv
}

func (cs *channelServer) writes() []map[string]any {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]map[string]any(nil), cs.bodies...)
}

func feedStdin(t *testing.T, s string) {
	t.Helper()
	old := secretValueStdin
	secretValueStdin = strings.NewReader(s)
	t.Cleanup(func() { secretValueStdin = old })
}

func TestChannelAdd_URLFromStdin(t *testing.T) {
	cs, srv := newChannelServer(t)
	useServer(t, srv.URL, "tok")
	feedStdin(t, canaryChannelURL+"\n")
	if err := executeForTest(t, "notification", "channel", "add", "ops-slack", "--type", "slack", "--url-file", "-"); err != nil {
		t.Fatalf("add with --url-file -: %v", err)
	}
	w := cs.writes()
	if len(w) != 1 || w[0]["url"] != canaryChannelURL {
		t.Fatalf("the server should receive the URL read from stdin, newline trimmed: %v", w)
	}
}

func TestChannelAdd_URLFromRelativeFile(t *testing.T) {
	cs, srv := newChannelServer(t)
	useServer(t, srv.URL, "tok")
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/url.txt", []byte(canaryChannelURL+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := executeForTest(t, "notification", "channel", "add", "ops-slack", "--type", "slack", "--url-file", "./url.txt"); err != nil {
		t.Fatalf("add with --url-file <file>: %v", err)
	}
	if w := cs.writes(); len(w) != 1 || w[0]["url"] != canaryChannelURL {
		t.Fatalf("the server should receive the URL from the file: %v", w)
	}
}

func TestChannelAdd_URLFlagIsRefused(t *testing.T) {
	cs, srv := newChannelServer(t)
	useServer(t, srv.URL, "tok")
	for _, args := range [][]string{
		{"notification", "channel", "add", "ops-slack", "--type", "slack", "--url", canaryChannelURL},
		{"notification", "channel", "update", "ops-slack", "--url", canaryChannelURL},
	} {
		err := executeForTest(t, args...)
		if err == nil {
			t.Fatalf("%v: --url must be refused", args[:3])
		}
		if code, _ := classifyError(err, true); code != exitUsage {
			t.Errorf("%v: refusal exits %d, want %d (usage)", args[:3], code, exitUsage)
		}
		msg := err.Error()
		if !strings.Contains(msg, "--url-file") || !strings.Contains(msg, allowInsecureSecretFlagsEnv) {
			t.Errorf("the refusal should name --url-file and the escape hatch: %s", msg)
		}
		if strings.Contains(msg, canaryChannelURL) || strings.Contains(msg, "CANARYtoken") {
			t.Errorf("the refusal echoed the URL: %s", msg)
		}
	}
	if len(cs.calls) != 0 {
		t.Errorf("a refused flag must send nothing to the server: %v", cs.calls)
	}
}

func TestChannelAdd_URLFlagEscapeHatch(t *testing.T) {
	cs, srv := newChannelServer(t)
	useServer(t, srv.URL, "tok")
	t.Setenv(allowInsecureSecretFlagsEnv, "1")
	if err := executeForTest(t, "notification", "channel", "add", "ops-slack", "--type", "slack", "--url", canaryChannelURL); err != nil {
		t.Fatalf("%s=1 should let --url through: %v", allowInsecureSecretFlagsEnv, err)
	}
	if w := cs.writes(); len(w) != 1 || w[0]["url"] != canaryChannelURL {
		t.Fatalf("escape hatch: %v", w)
	}
}

func TestChannelUpdate_URLFile(t *testing.T) {
	cs, srv := newChannelServer(t)
	useServer(t, srv.URL, "tok")
	feedStdin(t, canaryChannelURL)
	if err := executeForTest(t, "notification", "channel", "update", "ops-slack", "--url-file", "-"); err != nil {
		t.Fatalf("update --url-file -: %v", err)
	}
	if w := cs.writes(); len(w) != 1 || w[0]["url"] != canaryChannelURL {
		t.Fatalf("update should send the replacement URL: %v", w)
	}

	// Without --url-file the stored URL is left alone: no "url" key in the body.
	cs2, srv2 := newChannelServer(t)
	useServer(t, srv2.URL, "tok")
	if err := executeForTest(t, "notification", "channel", "update", "ops-slack", "--events", "secret.rotated"); err != nil {
		t.Fatal(err)
	}
	if w := cs2.writes(); len(w) != 1 {
		t.Fatalf("writes: %v", w)
	} else if _, has := w[0]["url"]; has {
		t.Errorf("an update without --url-file must not send url: %v", w[0])
	}
}

func TestChannelURLFile_Refusals(t *testing.T) {
	_, srv := newChannelServer(t)
	useServer(t, srv.URL, "tok")

	feedStdin(t, "")
	err := executeForTest(t, "notification", "channel", "add", "x", "--type", "slack", "--url-file", "-")
	if err == nil || !strings.Contains(err.Error(), "nothing on stdin") {
		t.Errorf("empty stdin must be an error that says so: %v", err)
	}

	err = executeForTest(t, "notification", "channel", "add", "x", "--type", "slack", "--url", "https://a", "--url-file", "-")
	if err == nil {
		t.Fatal("--url with --url-file must be refused")
	}
	if code, _ := classifyError(err, true); code != exitUsage {
		t.Errorf("both flags: exit %d, want usage", code)
	}

	feedStdin(t, "not a url\n")
	err = executeForTest(t, "notification", "channel", "add", "x", "--type", "slack", "--url-file", "-")
	if err == nil || strings.Contains(err.Error(), "not a url") {
		t.Errorf("a non-URL must be refused without echoing it: %v", err)
	}
}

func TestChannelGet_ShowsOnlyTheElidedURL(t *testing.T) {
	_, srv := newChannelServer(t)
	useServer(t, srv.URL, "tok")
	var err error
	resetAllFlags(rootCmd)
	rootCmd.SetArgs([]string{"notification", "channel", "get", "ops-slack"})
	defer rootCmd.SetArgs(nil)
	out, errOut := captureStdoutAndStderr(t, func() { err = Execute() })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, elidedChannelURL) {
		t.Errorf("channel get should show the masked URL:\n%s", out)
	}
	if !strings.Contains(out, "--url-file") {
		t.Errorf("channel get should say the URL is not retrievable and how to replace it:\n%s", out)
	}
	if strings.Contains(out+errOut, "CANARYtoken") {
		t.Errorf("full URL leaked:\n%s", out)
	}
}
