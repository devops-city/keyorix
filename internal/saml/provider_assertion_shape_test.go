package saml

// provider_assertion_shape_test.go covers ParseResponse's namespace-strict assertion shape
// check (strictAssertionShape) and the recover() around the library call: every case is a
// validly signed assertion, so only the shape check stands between it and a login.

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

// signMutatedAssertion applies mutate to the unsigned assertion element and signs it the
// way crewjam's IdP does (enveloped, exclusive C14N, Signature right after Issuer).
func signMutatedAssertion(t *testing.T, assertion *etree.Element, mutate func(*etree.Element), key *rsa.PrivateKey, cert *x509.Certificate) *etree.Element {
	t.Helper()
	mutate(assertion)
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert,
	}))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	require.NoError(t, ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
	signed, err := ctx.SignEnveloped(assertion)
	require.NoError(t, err)
	children := signed.ChildElements()
	sig := children[len(children)-1]
	signed.RemoveChild(sig)
	signed.InsertChildAt(1, sig) // after Issuer, as the schema orders it
	return signed
}

func childByTag(el *etree.Element, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}

func foreignNameID(value string) *etree.Element {
	el := etree.NewElement("evil:NameID")
	el.CreateAttr("xmlns:evil", "urn:example:not-saml")
	el.SetText(value)
	return el
}

func TestParseResponse_StrictShape_AcceptsCorrectNamespaceSpellings(t *testing.T) {
	cases := map[string]func(*etree.Element){
		"unchanged": func(*etree.Element) {},
		"other prefix bound to the assertion namespace": func(a *etree.Element) {
			nid := childByTag(childByTag(a, "Subject"), "NameID")
			nid.Space = "a2"
			nid.CreateAttr("xmlns:a2", samlAssertionNS)
		},
		"default namespace": func(a *etree.Element) {
			nid := childByTag(childByTag(a, "Subject"), "NameID")
			nid.Space = ""
			nid.CreateAttr("xmlns", samlAssertionNS)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, acsURL, b64 := buildSignedResponseB64WithAssertion(t, mutate)
			info, err := submitSAMLResponse(t, p, acsURL, b64)
			require.NoError(t, err)
			require.Equal(t, "user@corp.example", info.Subject)
		})
	}
}

func TestParseResponse_StrictShape_Refuses(t *testing.T) {
	cases := map[string]func(*etree.Element){
		"foreign-namespace NameID replaces the real one": func(a *etree.Element) {
			s := childByTag(a, "Subject")
			s.RemoveChild(childByTag(s, "NameID"))
			s.InsertChildAt(0, foreignNameID("attacker@corp.example"))
		},
		"foreign-namespace NameID after the real one": func(a *etree.Element) {
			s := childByTag(a, "Subject")
			s.InsertChildAt(1, foreignNameID("attacker@corp.example"))
		},
		"duplicate NameID": func(a *etree.Element) {
			s := childByTag(a, "Subject")
			dup := childByTag(s, "NameID").Copy()
			dup.SetText("attacker@corp.example")
			s.InsertChildAt(1, dup)
		},
		"missing Subject": func(a *etree.Element) {
			a.RemoveChild(childByTag(a, "Subject"))
		},
		"missing Conditions": func(a *etree.Element) {
			a.RemoveChild(childByTag(a, "Conditions"))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, acsURL, b64 := buildSignedResponseB64WithAssertion(t, mutate)
			var (
				info *AssertionInfo
				err  error
			)
			require.NotPanics(t, func() { info, err = submitSAMLResponse(t, p, acsURL, b64) })
			require.ErrorIs(t, err, errInvalidSAMLResponse)
			require.Nil(t, info)
		})
	}
}

// TestParseResponseRecovered_TurnsLibraryPanicIntoError drives the library directly (no
// shape check in front) with assertions it dereferences unconditionally, and requires the
// local recover() to turn that into an error.
func TestParseResponseRecovered_TurnsLibraryPanicIntoError(t *testing.T) {
	for _, tag := range []string{"Subject", "Conditions"} {
		t.Run("missing "+tag, func(t *testing.T) {
			p, acsURL, b64 := buildSignedResponseB64WithAssertion(t, func(a *etree.Element) {
				a.RemoveChild(childByTag(a, tag))
			})
			req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(url.Values{"SAMLResponse": {b64}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			require.NoError(t, req.ParseForm())
			var err error
			require.NotPanics(t, func() { _, err = p.parseResponseRecovered(req, nil) })
			require.Error(t, err)
		})
	}
}
