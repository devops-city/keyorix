package netutil

import (
	"errors"
	"net/url"
	"regexp"
)

// embeddedURLPattern matches an absolute http(s) URL appearing anywhere in an
// error's text form. A webhook/chat destination URL IS the bearer credential for
// a Slack/Teams incoming webhook — the token lives in the URL path, not a
// header — and Go's *url.Error.Error() (returned by http.Client on any
// transport-level failure: dial/timeout/TLS) embeds the full request URL
// verbatim, e.g. `Post "https://hooks.slack.com/services/T000/B000/<token>": dial tcp: ...`.
var embeddedURLPattern = regexp.MustCompile(`(?i)https?://[^\s"]+`)

// RedactURLHost renders rawURL as just its scheme and host, dropping the
// path/query/userinfo — and with it any bearer token embedded there — while
// keeping enough context (which destination failed) to be useful for
// diagnosis. Falls back to a fixed placeholder when rawURL doesn't parse into a
// URL with a host.
func RedactURLHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "[redacted-url]"
	}
	return u.Scheme + "://" + u.Host
}

// SanitizeErrorURLs renders err's text with every embedded http(s) URL cut down
// to scheme+host (RedactURLHost). Returns "" for a nil err.
func SanitizeErrorURLs(err error) string {
	if err == nil {
		return ""
	}
	return embeddedURLPattern.ReplaceAllStringFunc(err.Error(), RedactURLHost)
}

// urlRedactedError carries the sanitized text of an error whose original text
// embedded a destination URL. Unwrap exposes the cause with every *url.Error
// layer removed (that layer is what holds the full URL), so errors.Is/As on the
// underlying failure (a context deadline, the redirect-refused sentinel, a
// *net.OpError) keep working while the URL is unreachable through the chain.
type urlRedactedError struct {
	msg string
	err error
}

func (e *urlRedactedError) Error() string { return e.msg }
func (e *urlRedactedError) Unwrap() error { return e.err }

// RedactErrorURLs returns an error with the same cause as err but whose text
// has every embedded http(s) URL reduced to scheme+host and which no longer
// wraps a *url.Error (so neither Error() nor errors.As can recover the URL).
// nil in, nil out.
func RedactErrorURLs(err error) error {
	if err == nil {
		return nil
	}
	inner := err
	for {
		var ue *url.Error
		if !errors.As(inner, &ue) {
			break
		}
		inner = ue.Err
	}
	return &urlRedactedError{msg: SanitizeErrorURLs(inner), err: inner}
}
