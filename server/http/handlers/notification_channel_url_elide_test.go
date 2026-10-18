package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3425: the elided form must never carry a fragment of the path, query or
// userinfo, whatever shape the stored URL has.
func TestElideChannelURL(t *testing.T) {
	assert.Equal(t, "", elideChannelURL(""))
	assert.Equal(t, "https://hooks.slack.com/…", elideChannelURL("https://hooks.slack.com/services/T0/B0/TOKEN"))
	assert.Equal(t, "https://hooks.slack.com/…", elideChannelURL("https://user:pw@hooks.slack.com/x?token=TOKEN#frag"))
	assert.Equal(t, "https://203.0.113.7:8443/…", elideChannelURL("https://203.0.113.7:8443/hook/TOKEN"))
	assert.Equal(t, "[redacted-url]", elideChannelURL("/services/T0/B0/TOKEN"))
	assert.Equal(t, "[redacted-url]", elideChannelURL("https://h/\x7fTOKEN"))
}

func TestChannelToAPI_RevealOnlyWhenAsked(t *testing.T) {
	ch := &models.NotificationChannel{ID: 1, Name: "n", Type: "slack", URL: "https://hooks.slack.com/services/T0/B0/TOKEN"}

	hidden := channelToAPI(ch, false)
	assert.Equal(t, "https://hooks.slack.com/…", hidden["url"])
	assert.Equal(t, true, hidden["url_set"])

	shown := channelToAPI(ch, true)
	assert.Equal(t, ch.URL, shown["url"])
	assert.Equal(t, true, shown["url_set"])

	none := channelToAPI(&models.NotificationChannel{Type: "email", Email: "a@b.c"}, false)
	assert.Equal(t, "", none["url"])
	assert.Equal(t, false, none["url_set"])
}
