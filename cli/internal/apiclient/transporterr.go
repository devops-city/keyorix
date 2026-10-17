package apiclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
)

// DescribeTransportError turns the errors net/http and crypto/tls produce when no
// HTTP answer came back into one sentence with the next step, instead of
// `Get "http://host/api/v1/version": dial tcp ...`. ok is false for any other error.
//
// It lives here, not in cmd, because the clientguard sweep (INV-CLI-06) allows only this
// package to import net and crypto/tls.
func DescribeTransportError(err error) (string, bool) {
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		return "", false
	}
	where := "the Keyorix server"
	if u, perr := url.Parse(uerr.URL); perr == nil && u.Host != "" {
		where = fmt.Sprintf("the Keyorix server at %s://%s", u.Scheme, u.Host)
	}
	inner := uerr.Err

	var (
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		certInvalid x509.CertificateInvalidError
		verifyErr   *tls.CertificateVerificationError
		dnsErr      *net.DNSError
	)
	switch {
	case errors.As(inner, &unknownAuth), errors.As(inner, &hostErr), errors.As(inner, &certInvalid), errors.As(inner, &verifyErr):
		reason := inner.Error()
		if verifyErr != nil {
			reason = verifyErr.Err.Error()
		}
		return fmt.Sprintf("cannot trust the TLS certificate of %s (%s). "+
			"Next step: if the server uses a private CA, point the CLI at it with --ca-file <ca.pem> "+
			"(or `keyorix config set ca_file <ca.pem>`); otherwise check the certificate on the server.", where, reason), true
	case strings.Contains(inner.Error(), "server gave HTTP response to HTTPS client"):
		return fmt.Sprintf("%s answers in plain HTTP, but the URL says https. "+
			"Next step: use an http:// URL (`keyorix login --server http://...`) or enable TLS on the server.", where), true
	case errors.As(inner, &dnsErr):
		return fmt.Sprintf("cannot resolve the host name of %s. Next step: check the URL with `keyorix status`, "+
			"then re-run `keyorix login --server <url>` if it is wrong.", where), true
	case errors.Is(inner, syscall.ECONNREFUSED):
		return fmt.Sprintf("cannot reach %s: connection refused. Next step: check that the server is running and the "+
			"URL is right (`keyorix status` shows the URL in use).", where), true
	case errors.Is(inner, context.DeadlineExceeded) || isTimeout(inner):
		return fmt.Sprintf("cannot reach %s: the request timed out. Next step: check your network and that the server "+
			"is healthy, then retry.", where), true
	case strings.Contains(inner.Error(), "refusing to follow redirect"):
		return fmt.Sprintf("%s redirected the request, and the CLI does not follow redirects (a redirect could "+
			"send your token elsewhere). Next step: log in again with the final URL (`keyorix login --server <url>`).", where), true
	}
	var opErr *net.OpError
	if errors.As(inner, &opErr) || isTimeout(inner) || errors.Is(inner, io.EOF) || errors.Is(inner, io.ErrUnexpectedEOF) {
		return fmt.Sprintf("cannot reach %s: %s. Next step: check your network and the URL (`keyorix status`).",
			where, strings.TrimSpace(inner.Error())), true
	}
	return "", false
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
