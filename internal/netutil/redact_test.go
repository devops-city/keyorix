package netutil

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactURLHost(t *testing.T) {
	assert.Equal(t, "https://hooks.slack.test", RedactURLHost("https://u:p@hooks.slack.test/services/T/B/TOKEN?x=1"))
	assert.Equal(t, "[redacted-url]", RedactURLHost("/only/a/path/TOKEN"))
	assert.Equal(t, "[redacted-url]", RedactURLHost("https://h/\x7fTOKEN"))
}

func TestRedactErrorURLs_StripsURLErrorLayerKeepsCause(t *testing.T) {
	cause := errors.New("dial tcp: connection refused")
	err := &url.Error{Op: "Post", URL: "https://hooks.slack.test/services/T/B/TOKEN", Err: cause}

	got := RedactErrorURLs(err)
	require.Error(t, got)
	assert.NotContains(t, got.Error(), "TOKEN")
	assert.Contains(t, got.Error(), "connection refused")
	assert.ErrorIs(t, got, cause)
	var ue *url.Error
	assert.False(t, errors.As(got, &ue), "the *url.Error layer holds the full URL and must not stay reachable")
	assert.NoError(t, RedactErrorURLs(nil))
}

func TestSanitizeErrorURLs_SchemeIsCaseInsensitive(t *testing.T) {
	got := SanitizeErrorURLs(errors.New(`Post "HTTPS://hooks.slack.test/services/T/B/TOKEN": dial tcp: refused`))
	assert.NotContains(t, got, "TOKEN")
	assert.Contains(t, got, "hooks.slack.test")
}

func TestRedactErrorURLs_ScrubsURLsLeftInCauseText(t *testing.T) {
	got := RedactErrorURLs(errors.New(`upstream said: see https://hooks.slack.test/services/T/B/TOKEN for details`))
	assert.NotContains(t, got.Error(), "TOKEN")
	assert.Contains(t, got.Error(), "https://hooks.slack.test")
}
