package notary

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// derLen encodes a DER definite length (short form under 128, else long form).
func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

// TestValidateDERFraming_AcceptsRealToken is the positive path: a genuine
// validly-signed token must pass framing and still verify end-to-end. The guard
// must never reject anything spec-compliant.
func TestValidateDERFraming_AcceptsRealToken(t *testing.T) {
	fixedTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	msg := []byte("checkpoint bytes being anchored")
	want := sha256.Sum256(msg)
	token, cert := craftTokenWithHashAlgorithm(t, fixedTime, crypto.SHA256, want[:])

	assert.NoError(t, validateDERFraming(token), "real token must pass framing")

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	at, err := VerifyReceipt(roots, msg, token)
	require.NoError(t, err)
	assert.WithinDuration(t, fixedTime, at, time.Second)
}

// TestValidateDERFraming_Framing spot-checks each rejection reason so the
// guard's own logic is covered, not just end-to-end behaviour.
func TestValidateDERFraming_Framing(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"minimal SEQUENCE{}", []byte{0x30, 0x00}, true},
		{"SEQUENCE with one NULL child", []byte{0x30, 0x02, 0x05, 0x00}, true},
		{"indefinite length", []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}, false},
		{"child overruns parent", []byte{0x30, 0x02, 0x30, 0x20}, false},
		{"trailing bytes", []byte{0x05, 0x00, 0x05, 0x00}, false},
		{"length past buffer", []byte{0x04, 0x7f}, false},
		{"truncated header", []byte{0x30}, false},
	}
	for _, c := range cases {
		err := validateDERFraming(c.in)
		if c.ok {
			assert.NoErrorf(t, err, "%s should be accepted", c.name)
		} else {
			assert.Errorf(t, err, "%s should be rejected", c.name)
		}
	}
}

// TestValidateDERFraming_Limits covers the depth and node caps with small,
// non-amplifying inputs. Both are rejected during the header walk before any
// content is read, so the inputs themselves stay a few KB at most.
func TestValidateDERFraming_Limits(t *testing.T) {
	// One level deeper than maxDERDepth: definite-length SEQUENCEs wrapping a
	// NULL. Lengths stay well under 128, so the whole thing is a few dozen bytes.
	deep := []byte{0x05, 0x00}
	for range maxDERDepth + 1 {
		deep = append([]byte{0x30, byte(len(deep))}, deep...)
	}
	assert.Error(t, validateDERFraming(deep), "nesting past maxDERDepth must be rejected")

	// A flat SEQUENCE holding more than maxDERNodes empty NULLs: many nodes, two
	// bytes each, so it trips the node cap rather than any allocation.
	var kids bytes.Buffer
	for range maxDERNodes + 1 {
		kids.Write([]byte{0x05, 0x00})
	}
	body := kids.Bytes()
	seq := append([]byte{0x30}, derLen(len(body))...)
	seq = append(seq, body...)
	assert.Error(t, validateDERFraming(seq), "more than maxDERNodes elements must be rejected")
}

// TestVerifyReceipt_RejectsMalformedFramingEarly proves the guard is wired into
// the verify path: a token that is not strict DER is rejected before the
// decoder is ever reached.
func TestVerifyReceipt_RejectsMalformedFramingEarly(t *testing.T) {
	roots := x509.NewCertPool()                          // non-nil, so we pass the nil-roots guard and reach framing
	notDER := []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00} // indefinite length
	_, err := VerifyReceipt(roots, []byte("m"), notDER)
	require.Error(t, err, "a non-DER token must be rejected")
}
