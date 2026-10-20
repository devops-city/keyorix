package tlsmetrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "obs1.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key} // Leaf deliberately nil, as tls.LoadX509KeyPair leaves it
}

func TestObserve_RecordsLeafNotAfterPerListener(t *testing.T) {
	httpExp := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	grpcExp := time.Now().Add(3 * 24 * time.Hour).Truncate(time.Second)

	Observe(HTTP, selfSigned(t, httpExp))
	Observe(GRPC, selfSigned(t, grpcExp))

	assert.Equal(t, float64(httpExp.Unix()), testutil.ToFloat64(notAfter.WithLabelValues(HTTP)))
	assert.Equal(t, float64(grpcExp.Unix()), testutil.ToFloat64(notAfter.WithLabelValues(GRPC)))
}

func TestObserve_EmptyCertificateRecordsNothing(t *testing.T) {
	before := testutil.CollectAndCount(notAfter)
	Observe("nope", tls.Certificate{})
	Observe("nope", tls.Certificate{Certificate: [][]byte{[]byte("not der")}})
	assert.Equal(t, before, testutil.CollectAndCount(notAfter), "an unparseable cert must not mint a series")
}

func TestWrap_GaugeFollowsARotatedCertificate(t *testing.T) {
	first := selfSigned(t, time.Now().Add(2*24*time.Hour).Truncate(time.Second))
	second := selfSigned(t, time.Now().Add(90*24*time.Hour).Truncate(time.Second))
	serving := &first
	get := Wrap("rotating", func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serving, nil })

	firstLeaf, err := x509.ParseCertificate(first.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, float64(firstLeaf.NotAfter.Unix()), testutil.ToFloat64(notAfter.WithLabelValues("rotating")), "set when wrapped, before any handshake")

	serving = &second // what tlsreload does after a rotated pair loads
	got, err := get(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Same(t, &second, got, "Wrap must serve exactly what the wrapped hook serves")
	secondLeaf, err := x509.ParseCertificate(second.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, float64(secondLeaf.NotAfter.Unix()), testutil.ToFloat64(notAfter.WithLabelValues("rotating")), "gauge must follow the rotated certificate")
}
