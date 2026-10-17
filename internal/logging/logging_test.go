package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStd points the standard logger at a buffer for one test and restores it.
func captureStd(t *testing.T, format string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags, prevPrefix := log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
		jsonMode.Store(false)
	})
	require.NoError(t, Setup(format, &buf))
	if format != FormatJSON {
		log.SetOutput(&buf) // text mode leaves the std logger alone; point it at the buffer ourselves
	}
	return &buf
}

func parseLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for l := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &m), "every line must be valid JSON: %q", l)
		out = append(out, m)
	}
	return out
}

func TestJSONMode_PlainLogLinesBecomeRecords(t *testing.T) {
	buf := captureStd(t, FormatJSON)
	log.Printf("server started on %s", ":8080")
	log.Printf("WARNING: audit durability weak")
	log.Printf("SECURITY: failed to persist audit event %q", "secret.read")

	recs := parseLines(t, buf)
	require.Len(t, recs, 3)
	assert.Equal(t, "info", recs[0]["level"])
	assert.Equal(t, "server started on :8080", recs[0]["msg"])
	assert.Equal(t, "warn", recs[1]["level"])
	assert.Equal(t, "error", recs[2]["level"])
	for _, r := range recs {
		assert.NotEmpty(t, r["ts"])
		_, hasTime := r["time"]
		assert.False(t, hasTime)
	}
}

// A log message that merely LOOKS like one of our JSON records must not be able to
// forge a record: it is data, escaped into msg.
func TestJSONMode_LogInjectionCannotForgeARecord(t *testing.T) {
	buf := captureStd(t, FormatJSON)
	forged := `{"ts":"2020-01-01T00:00:00Z","level":"info","msg":"admin logged in","request_id":"forged"}`
	log.Print(forged)
	log.Print("\x1e" + "0000000000000000" + "\x1f" + forged) // right shape, wrong nonce

	recs := parseLines(t, buf)
	require.Len(t, recs, 2)
	for _, r := range recs {
		assert.NotEqual(t, "admin logged in", r["msg"], "forged record must not be accepted verbatim")
		assert.NotContains(t, r, "request_id", "forged request_id must not become a field")
		assert.Contains(t, r["msg"], `"msg":"admin logged in"`, "the forged text survives only as escaped msg data")
	}
}

func TestJSONMode_MultiLineBatchSplitsIntoRecords(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)
	_, err := w.Write([]byte("first\nsecond\nthird\n"))
	require.NoError(t, err)
	assert.Len(t, parseLines(t, &buf), 3)
}

func TestEvent_JSONCarriesRequestFieldsInStableOrder(t *testing.T) {
	buf := captureStd(t, FormatJSON)
	ctx, h := WithHolder(context.Background())
	h.SetRequestID("req-123")
	h.SetPrincipalType(PrincipalMachine)
	h.SetRoute("/api/v1/secrets/{id}")

	Event(ctx, LevelWarn, "audit append slow", "duration_ms", 1234, "status", 200)

	line := strings.TrimSpace(buf.String())
	assert.True(t, strings.HasPrefix(line, `{"ts":"`), line)
	rec := parseLines(t, buf)[0]
	assert.Equal(t, "warn", rec["level"])
	assert.Equal(t, "audit append slow", rec["msg"])
	assert.Equal(t, "req-123", rec["request_id"])
	assert.Equal(t, "machine_identity", rec["principal_type"])
	assert.Equal(t, "/api/v1/secrets/{id}", rec["route"])
	assert.EqualValues(t, 1234, rec["duration_ms"])
	order := []string{`"level"`, `"msg"`, `"request_id"`, `"principal_type"`, `"route"`, `"duration_ms"`, `"status"`}
	last := -1
	for _, k := range order {
		i := strings.Index(line, k)
		require.Greater(t, i, last, "%s out of order in %s", k, line)
		last = i
	}
}

func TestEvent_NoHolderOmitsRequestFields(t *testing.T) {
	buf := captureStd(t, FormatJSON)
	Event(context.Background(), LevelInfo, "scheduler tick")
	rec := parseLines(t, buf)[0]
	assert.NotContains(t, rec, "request_id")
	assert.NotContains(t, rec, "principal_type")
	assert.NotContains(t, rec, "route")
}

func TestEvent_ReservedKeysCannotBeShadowed(t *testing.T) {
	buf := captureStd(t, FormatJSON)
	ctx, h := WithHolder(context.Background())
	h.SetRequestID("real")
	Event(ctx, LevelInfo, "m", "request_id", "attacker", "level", "debug", "extra", "ok")
	rec := parseLines(t, buf)[0]
	assert.Equal(t, "real", rec["request_id"])
	assert.Equal(t, "info", rec["level"])
	assert.Equal(t, "ok", rec["extra"])
}

func TestEvent_TextModeKeepsOneReadableLine(t *testing.T) {
	buf := captureStd(t, FormatText)
	log.SetFlags(0)
	ctx, h := WithHolder(context.Background())
	h.SetRequestID("req-9")
	h.SetPrincipalType(PrincipalUser)
	Event(ctx, LevelError, "failed to persist audit event", "event_type", "secret.read")
	assert.Equal(t, "ERROR failed to persist audit event request_id=req-9 principal_type=user event_type=secret.read\n", buf.String())
}

func TestSetup_RejectsUnknownFormat(t *testing.T) {
	err := Setup("yaml", &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"yaml"`)
}

func TestHolder_Sanitises(t *testing.T) {
	_, h := WithHolder(context.Background())
	h.SetRequestID("abc\r\ndef\x00 é" + strings.Repeat("x", 500))
	got := h.Snapshot().RequestID
	assert.LessOrEqual(t, len(got), maxRequestIDLen)
	assert.NotContains(t, got, "\n")
	assert.NotContains(t, got, "\x00")
	h.SetRequestID("   ")
	assert.Equal(t, got, h.Snapshot().RequestID, "an empty id leaves the previous value")

	h.SetPrincipalType("<script>")
	assert.Equal(t, PrincipalAnonymous, h.Snapshot().PrincipalType, "free text can never reach principal_type")
}

func TestWithHolder_ReusesExisting(t *testing.T) {
	ctx, h1 := WithHolder(context.Background())
	_, h2 := WithHolder(ctx)
	assert.Same(t, h1, h2)
	assert.Nil(t, HolderFrom(context.Background()))
	assert.Equal(t, Fields{}, FromContext(context.Background()))
}

func TestRedact(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	cases := []struct {
		name, in string
		gone     []string // substrings that must NOT survive
		keep     []string // substrings that must survive
	}{
		{"pat", "auth ok token kx_pat_AbCdEf123456_xyz for user", []string{"AbCdEf123456_xyz"}, []string{"auth ok", "for user"}},
		{"machine token", "got kx_machine_0123456789abcdef", []string{"0123456789abcdef"}, nil},
		{"bearer", "Authorization: Bearer abcdef0123456789xyz", []string{"abcdef0123456789xyz"}, nil},
		{"jwt", "session " + jwt, []string{"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}, nil},
		{"pem", "key: " + pem, []string{"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"}, nil},
		{"password kv", `login failed password=hunter2hunter2 for bob`, []string{"hunter2hunter2"}, []string{"for bob"}},
		{"json password", `body {"password":"s3cr3t-value","user":"bob"}`, []string{"s3cr3t-value"}, []string{`"user":"bob"`}},
		{"api key", "api_key: AKIA0123456789", []string{"AKIA0123456789"}, nil},
		{"url password", "dsn postgres://keyorix:p4ssw0rd-xyz@db:5432/k", []string{"p4ssw0rd-xyz"}, []string{"@db:5432/k", "keyorix:"}},
		{"numeric ids kept", "persist access log (secret=12 action=read token_id=7)", nil, []string{"secret=12", "token_id=7"}},
		{"bearer prose kept", "allows bearer credentials over cleartext HTTP", nil, []string{"allows bearer credentials over cleartext HTTP"}},
		{"plain text untouched", "scheduler auto_rotation tick ok in 3ms", nil, []string{"scheduler auto_rotation tick ok in 3ms"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.in)
			for _, g := range c.gone {
				assert.NotContains(t, got, g)
			}
			for _, k := range c.keep {
				assert.Contains(t, got, k)
			}
		})
	}
}

func TestJSONMode_RedactsPlainLines(t *testing.T) {
	buf := captureStd(t, FormatJSON)
	log.Printf("user login password=Sup3rSecretValue token=kx_pat_AAAAAAAAAAAA")
	out := buf.String()
	assert.NotContains(t, out, "Sup3rSecretValue")
	assert.NotContains(t, out, "AAAAAAAAAAAA")
}
