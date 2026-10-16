// Package tlsmetrics exposes the expiry time of the certificate each TLS listener
// is serving, so an expiring server certificate is an alert rather than an outage.
//
// The listeners serve their key pair through tlsreload and wrap it with Wrap, so
// the gauge follows the certificate clients are being handed, including after an
// in-place rotation. The cert's
// NotAfter is already public to anyone who connects, so it is safe on /metrics.
// The listener label is one of the two constants below.
package tlsmetrics

import (
	"crypto/tls"
	"crypto/x509"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Listener names. These are the only values the listener label can take.
const (
	HTTP = "http"
	GRPC = "grpc"
)

var notAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "keyorix_tls_certificate_not_after_timestamp_seconds",
	Help: "Unix time at which the TLS certificate served by a listener (http|grpc) expires. Alert on this minus time() before it reaches zero; a renewed file is picked up by new handshakes within about 30 seconds.",
}, []string{"listener"})

// Wrap returns a tls.Config.GetCertificate hook that serves what get serves and
// keeps the gauge on the certificate actually handed to clients: it records the
// current certificate once when wrapped (so the gauge exists before the first
// handshake) and again whenever get returns a different certificate (a rotated
// pair picked up by tlsreload).
func Wrap(listener string, get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var mu sync.Mutex
	var last *tls.Certificate
	observe := func(c *tls.Certificate) {
		mu.Lock()
		defer mu.Unlock()
		if c != nil && c != last {
			last = c
			Observe(listener, *c)
		}
	}
	if c, err := get(nil); err == nil {
		observe(c)
	}
	return func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := get(h)
		if err == nil {
			observe(c)
		}
		return c, err
	}
}

// Observe records the expiry of the leaf certificate cert serves on listener. A
// certificate that cannot be parsed records nothing (the listener would already
// have failed to start with it).
func Observe(listener string, cert tls.Certificate) {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return
		}
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return
		}
	}
	notAfter.WithLabelValues(listener).Set(float64(leaf.NotAfter.Unix()))
}
