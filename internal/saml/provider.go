// Package saml implements a SAML 2.0 Service Provider (SP) core for Keyorix human SSO
// (ADR-063). It is a thin, safe wrapper over the vetted crewjam/saml + goxmldsig stack:
// the dangerous XML-DSig validation (signature, audience, recipient, time, InResponseTo,
// replay) is delegated to the library on purpose — SAML signature handling must never be
// hand-rolled. This package owns provider construction, SP metadata, the SP-initiated
// AuthnRequest, and mapping a validated assertion to (subject, email, name, groups).
//
// Phase 1b (the HTTP routes and SSO-provider wiring that turn a parsed assertion into a
// Keyorix session) has since shipped: server/http/router.go wires
// /auth/saml/{provider}/{metadata,login,acs}, and BeginSAML/CompleteSAML
// (server/http/handlers/sso.go) are live callers. Corrected 2026-09-07 -- this comment
// previously said "no callers yet," which was true only at this package's original writing.
package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	csaml "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// Default attribute names (used when a Config field is empty). These cover the common
// Azure AD / ADFS claim URIs; operators override per IdP.
const (
	defaultEmailAttr  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	defaultNameAttr   = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname"
	defaultGroupsAttr = "http://schemas.xmlsoap.org/claims/Group"
)

// Config configures one SAML provider (one IdP).
type Config struct {
	Name string
	// IDPMetadataXML is the IdP's SAML metadata (entityID, SSO URL, signing certificate).
	IDPMetadataXML []byte
	// SPEntityID is our SP entity ID (conventionally the metadata URL).
	SPEntityID string
	// ACSURL is our Assertion Consumer Service URL (where the IdP POSTs the response).
	ACSURL string
	// AllowIDPInitiated permits responses with no InResponseTo. Off by default — it loses
	// CSRF/replay protection — enable only for IdPs that require it.
	AllowIDPInitiated bool
	// Attribute names to read from the assertion (empty → the defaults above).
	EmailAttr, NameAttr, GroupsAttr string
}

// Provider is a configured SAML Service Provider for one IdP.
type Provider struct {
	name                            string
	sp                              *csaml.ServiceProvider
	emailAttr, nameAttr, groupsAttr string
}

// AssertionInfo is the identity extracted from a validated assertion. A type
// alias of ports.SAMLAssertion (ADR-109 step 1) so Provider — unchanged below —
// satisfies ports.SAMLServiceProvider directly, with no adapter.
type AssertionInfo = ports.SAMLAssertion

// NewProvider builds a Provider from config, parsing the IdP metadata.
func NewProvider(cfg Config) (*Provider, error) {
	if strings.TrimSpace(cfg.ACSURL) == "" {
		return nil, errors.New("saml: acs_url is required")
	}
	if strings.TrimSpace(cfg.SPEntityID) == "" {
		return nil, errors.New("saml: sp_entity_id is required")
	}
	acs, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: invalid acs_url: %w", err)
	}
	meta, err := url.Parse(cfg.SPEntityID)
	if err != nil {
		return nil, fmt.Errorf("saml: invalid sp_entity_id: %w", err)
	}
	idp, err := parseIDPMetadata(cfg.IDPMetadataXML)
	if err != nil {
		return nil, fmt.Errorf("saml: parse idp metadata: %w", err)
	}

	sp := &csaml.ServiceProvider{
		EntityID:          cfg.SPEntityID,
		MetadataURL:       *meta,
		AcsURL:            *acs,
		IDPMetadata:       idp,
		AllowIDPInitiated: cfg.AllowIDPInitiated,
	}
	// The library's default AudienceRestriction check treats an assertion with NO
	// AudienceRestriction element as valid (see crewjam/saml's
	// validateAudienceRestriction: an empty list is vacuously "valid"). That weakens
	// replay/cross-service-use protection — AudienceRestriction is what scopes an
	// assertion to THIS service provider, so an IdP or attacker omitting it produces
	// an assertion this SP would accept even though it was never scoped to us.
	// Override the hook to require at least one AudienceRestriction matching our
	// entity ID; a missing element is rejected, not silently accepted.
	sp.ValidateAudienceRestriction = requireAudienceRestriction(cfg.SPEntityID)
	return &Provider{
		name:       cfg.Name,
		sp:         sp,
		emailAttr:  orDefault(cfg.EmailAttr, defaultEmailAttr),
		nameAttr:   orDefault(cfg.NameAttr, defaultNameAttr),
		groupsAttr: orDefault(cfg.GroupsAttr, defaultGroupsAttr),
	}, nil
}

// requireAudienceRestriction builds a csaml.ServiceProvider.ValidateAudienceRestriction
// hook that requires the assertion to carry at least one AudienceRestriction whose
// Audience is entityID — a missing AudienceRestriction element is a hard failure, not
// vacuously valid (see the comment at the call site).
func requireAudienceRestriction(entityID string) func(assertion *csaml.Assertion) error {
	return func(assertion *csaml.Assertion) error {
		if assertion == nil || assertion.Conditions == nil || len(assertion.Conditions.AudienceRestrictions) == 0 {
			return errors.New("assertion has no AudienceRestriction")
		}
		for _, ar := range assertion.Conditions.AudienceRestrictions {
			if ar.Audience.Value == entityID {
				return nil
			}
		}
		return errors.New("assertion AudienceRestriction does not match this service provider")
	}
}

// Name returns the provider name.
func (p *Provider) Name() string { return p.name }

// Metadata returns this SP's SAML metadata XML — hand it to the IdP administrator.
func (p *Provider) Metadata() ([]byte, error) {
	out, err := xml.MarshalIndent(p.sp.Metadata(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return out, nil
}

// AuthnRequest builds an SP-initiated authentication request: it returns the IdP redirect
// URL (HTTP-Redirect binding) and the request ID to remember for InResponseTo matching.
func (p *Provider) AuthnRequest(relayState string) (redirectURL, requestID string, err error) {
	ssoURL := p.sp.GetSSOBindingLocation(csaml.HTTPRedirectBinding)
	if ssoURL == "" {
		return "", "", errors.New("saml: IdP has no HTTP-Redirect SSO binding")
	}
	req, err := p.sp.MakeAuthenticationRequest(ssoURL, csaml.HTTPRedirectBinding, csaml.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("saml: build authn request: %w", err)
	}
	u, err := req.Redirect(relayState, p.sp)
	if err != nil {
		return "", "", fmt.Errorf("saml: build redirect: %w", err)
	}
	return u.String(), req.ID, nil
}

// errInvalidSAMLResponse is the fixed, sanitized error ParseResponse returns to every
// caller on a validation failure — see the comment on ParseResponse for why the
// library's own error text must never reach a caller.
var errInvalidSAMLResponse = errors.New("saml: invalid response")

// validatePostedResponseHasNoEpilogue rejects a POST-binding SAMLResponse that carries
// any byte after its root element closes (an "XML epilogue").
//
// FuzzParseResponse found that appending arbitrary bytes to an already-signed, valid
// response is still accepted: neither this package's XML-DSig verification nor
// crewjam/saml's own internal xrv.Validate call catch it, because xrv checks that each
// XML token round-trips byte-for-byte through encode/decode — a trailing plain-text (or
// comment) token round-trips cleanly, so it's not flagged, even though the XML spec's
// own grammar (Misc* is only whitespace/comments/PIs after the root) makes a non-empty
// epilogue invalid there. The appended bytes don't change the signed assertion's
// content, but accepting a response Keyorix never itself observed turns an
// already-used, captured SAMLResponse into an unbounded number of byte-distinct
// "different" values, defeating any exact-response replay/dedup check downstream.
//
// Deliberately stricter than the XML spec: a spec-legal epilogue comment can still
// carry arbitrary attacker bytes (anything not containing "--"), so this rejects the
// epilogue outright — comment, PI, extra element, or non-whitespace text alike — rather
// than allow-listing spec-legal Misc content there. No legitimate IdP response has an
// epilogue at all.
//
// Mirrors crewjam/saml's own field read exactly (same form field, same encoding, same
// artifact-binding carve-out) so this never fires on a request crewjam wouldn't itself
// treat as a POST-binding SAMLResponse; a decode/parse failure here is left for
// crewjam's own error path to report, not duplicated here.
func validatePostedResponseHasNoEpilogue(r *http.Request) error {
	if r.PostForm.Get("SAMLart") != "" {
		return nil // artifact binding: no SAMLResponse form value involved
	}
	raw := r.PostForm.Get("SAMLResponse")
	if raw == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil // let crewjam's own base64 error path report this
	}
	// #nosec G709 -- token-walking untrusted bytes, not deserializing into a struct;
	// Go's encoding/xml has no DTD/external-entity expansion to exploit here, and
	// crewjam/saml decodes these same bytes into a full Response struct regardless.
	dec := xml.NewDecoder(bytes.NewReader(decoded))
	depth := 0
	sawRoot := false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return nil // let crewjam's own XML error path report this
		}
		epilogue := depth == 0 && sawRoot
		switch t := tok.(type) {
		case xml.StartElement:
			if epilogue {
				return errors.New("saml: response has more than one top-level XML element")
			}
			depth++
			sawRoot = true
		case xml.EndElement:
			depth--
		case xml.CharData:
			if epilogue && len(bytes.TrimSpace(t)) > 0 {
				return errors.New("saml: response has content after its root element")
			}
		default:
			// Comment, ProcInst, Directive: legal inside the document, but in
			// epilogue position they're an unbounded attacker-controlled byte
			// carrier (see doc comment) — reject unconditionally there.
			if epilogue {
				return errors.New("saml: response has content after its root element")
			}
		}
	}
}

// ParseResponse validates the SAMLResponse on r (signature against the pinned IdP
// certificate, audience, recipient, time window, and — for SP-initiated — InResponseTo
// against possibleRequestIDs) via the vetted library, then maps the assertion to an
// AssertionInfo. A validation failure is returned as an error; nothing is trusted from an
// unvalidated response.
//
// The ACS endpoint this feeds is unauthenticated (the caller controls the SAMLResponse
// body), so the library's own error — including InvalidResponseError.PrivateErr, which
// crewjam/saml documents as carrying internal detail (XML parse errors, signature/
// certificate internals) never meant for an untrusted caller — must not be reflected
// back verbatim. The detail is logged server-side for operators; every caller gets the
// same fixed, generic error.
func (p *Provider) ParseResponse(r *http.Request, possibleRequestIDs []string) (*AssertionInfo, error) {
	if err := validatePostedResponseHasNoEpilogue(r); err != nil {
		log.Printf("saml: provider %q: response validation failed: %v", p.name, err)
		return nil, errInvalidSAMLResponse
	}
	strictNameID, err := strictAssertionShape(r)
	if err != nil {
		log.Printf("saml: provider %q: response validation failed: %v", p.name, err)
		return nil, errInvalidSAMLResponse
	}
	assertion, err := p.parseResponseRecovered(r, possibleRequestIDs)
	if err != nil {
		var ire *csaml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			log.Printf("saml: provider %q: response validation failed: %v", p.name, ire.PrivateErr)
		} else {
			log.Printf("saml: provider %q: response validation failed: %v", p.name, err)
		}
		return nil, errInvalidSAMLResponse
	}
	// The library binds Subject.NameID by local name only; confirm the identifier it
	// authenticated is the one our namespace-strict parse found.
	if assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Value != strictNameID {
		log.Printf("saml: provider %q: response validation failed: library NameID differs from the namespace-strict NameID", p.name)
		return nil, errInvalidSAMLResponse
	}
	return extractAssertion(assertion, p.emailAttr, p.nameAttr, p.groupsAttr), nil
}

// parseResponseRecovered calls the library's ParseResponse and turns a panic inside it
// into an ordinary validation error, so a malformed-but-signed response is refused here
// (logged, generic error) instead of relying on the outer Recovery() middleware.
func (p *Provider) parseResponseRecovered(r *http.Request, possibleRequestIDs []string) (assertion *csaml.Assertion, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			assertion = nil
			err = fmt.Errorf("saml: panic while validating response: %v", rec)
		}
	}()
	return p.sp.ParseResponse(r, possibleRequestIDs)
}

// samlAssertionNS is the SAML 2.0 assertion namespace.
const samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"

// maxResponseDepth bounds strictAssertionShape's element stack: real responses nest
// about a dozen deep, and an unbounded stack lets a 10 MiB body of "<a>" allocate a frame
// per 3 input bytes before the library ever sees it.
const maxResponseDepth = 64

// strictAssertionShape parses the posted SAMLResponse with namespace resolution (so a
// correctly-bound prefix of any name passes) and refuses any shape the library would
// either mis-bind or fail to handle safely:
//
//   - the root has exactly one Assertion child, in the assertion namespace, and no
//     Assertion-named child in any other namespace;
//   - every Assertion has exactly one Subject and exactly one Conditions child, both in
//     the assertion namespace, and no Subject/Conditions-named child in any other
//     namespace;
//   - every such Subject has exactly one identifier child, and it is a NameID in the
//     assertion namespace (no NameID-named child in any other namespace, no BaseID or
//     EncryptedID beside it), and that NameID holds text only;
//   - only the HTTP-POST binding with plaintext assertions: no SAMLart form key, no
//     root-level EncryptedAssertion, one root element, at most maxResponseDepth deep.
//
// It returns the text of the root Assertion's Subject NameID, which the caller compares
// against what the library authenticated. Unlike the epilogue check this is fail-closed:
// no SAMLResponse, bad base64 or malformed XML is a refusal, not a deferral to the
// library. It does not check signatures, so it only ever narrows what is accepted.
func strictAssertionShape(r *http.Request) (string, error) {
	// The library switches to the artifact binding when r.Form (query string included)
	// carries SAMLart, and then never reads the SAMLResponse checked below. Keyorix only
	// asks for the POST binding, so refuse the artifact binding outright (the key at all,
	// not only a non-empty first value).
	if _, ok := r.Form["SAMLart"]; ok {
		return "", errors.New("saml: artifact binding is not supported")
	}
	raw := r.PostForm.Get("SAMLResponse")
	if raw == "" {
		return "", errors.New("saml: no SAMLResponse form value")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("saml: SAMLResponse is not valid base64: %w", err)
	}

	type frame struct {
		name                         xml.Name
		parentIsRoot, parentIsAssert bool // this element's position
		assertions                   int  // root: direct Assertion children
		subjects, conditions         int  // Assertion: direct Subject/Conditions children
		nameIDs, identifiers         int  // Subject: direct NameID / any identifier children
		text                         strings.Builder
	}
	isNS := func(n xml.Name, local string) bool { return n.Space == samlAssertionNS && n.Local == local }

	// #nosec G709 -- token-walking untrusted bytes, not deserializing into a struct;
	// Go's encoding/xml has no DTD/external-entity expansion to exploit here.
	dec := xml.NewDecoder(bytes.NewReader(decoded))
	var stack []*frame
	nameID, haveNameID, sawRoot := "", false, false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("saml: response is not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			f := &frame{name: t.Name}
			if len(stack) == 0 {
				// The library reads only the first root element; refuse a second one.
				if sawRoot {
					return "", errors.New("saml: response has more than one root element")
				}
				sawRoot = true
			}
			if n := len(stack); n > 0 {
				parent := stack[n-1]
				f.parentIsRoot = n == 1
				f.parentIsAssert = isNS(parent.name, "Assertion")
				switch {
				case f.parentIsRoot && t.Name.Local == "Assertion":
					if t.Name.Space != samlAssertionNS {
						return "", fmt.Errorf("saml: Assertion element in namespace %q", t.Name.Space)
					}
					parent.assertions++
				case f.parentIsRoot && t.Name.Local == "EncryptedAssertion":
					// The library returns a decrypted assertion ahead of the plaintext one
					// this check reads; Keyorix configures no decryption key, so refuse.
					return "", errors.New("saml: EncryptedAssertion is not supported")
				case isNS(parent.name, "NameID"):
					return "", errors.New("saml: NameID has child elements")
				}
				if f.parentIsAssert && (t.Name.Local == "Subject" || t.Name.Local == "Conditions") {
					if t.Name.Space != samlAssertionNS {
						return "", fmt.Errorf("saml: %s element in namespace %q", t.Name.Local, t.Name.Space)
					}
					if t.Name.Local == "Subject" {
						parent.subjects++
					} else {
						parent.conditions++
					}
				}
				if isNS(parent.name, "Subject") && parent.parentIsAssert {
					switch {
					case t.Name.Local == "NameID" && t.Name.Space != samlAssertionNS:
						return "", fmt.Errorf("saml: Subject NameID in namespace %q", t.Name.Space)
					case isNS(t.Name, "NameID"):
						parent.nameIDs++
						parent.identifiers++
					case t.Name.Local == "BaseID", t.Name.Local == "EncryptedID":
						// Any namespace: an identifier beside the NameID is refused however it is spelled.
						parent.identifiers++
					}
				}
			}
			if len(stack) >= maxResponseDepth {
				return "", fmt.Errorf("saml: response nests deeper than %d elements", maxResponseDepth)
			}
			stack = append(stack, f)
		case xml.CharData:
			if n := len(stack); n > 0 && isNS(stack[n-1].name, "NameID") {
				stack[n-1].text.Write(t)
			}
		case xml.EndElement:
			n := len(stack)
			if n == 0 {
				return "", errors.New("saml: unbalanced XML")
			}
			f := stack[n-1]
			stack = stack[:n-1]
			switch {
			case n == 1:
				if f.assertions != 1 {
					return "", fmt.Errorf("saml: response has %d Assertion elements, want exactly 1", f.assertions)
				}
			case isNS(f.name, "Assertion"):
				if f.subjects != 1 || f.conditions != 1 {
					return "", fmt.Errorf("saml: Assertion has %d Subject and %d Conditions elements, want exactly 1 each", f.subjects, f.conditions)
				}
			case isNS(f.name, "Subject") && f.parentIsAssert:
				if f.nameIDs != 1 || f.identifiers != 1 {
					return "", fmt.Errorf("saml: Subject has %d NameID and %d identifier elements, want exactly 1 NameID", f.nameIDs, f.identifiers)
				}
			case isNS(f.name, "NameID") && n == 4 && isNS(stack[2].name, "Subject") && stack[1].parentIsRoot && isNS(stack[1].name, "Assertion"):
				// Root > Assertion > Subject > NameID: the identifier the library binds.
				nameID, haveNameID = f.text.String(), true
			}
		}
	}
	if len(stack) != 0 || !haveNameID {
		return "", errors.New("saml: response has no Subject NameID in its Assertion")
	}
	return nameID, nil
}

// extractAssertion maps a validated assertion to identity fields. Split out so the
// mapping is unit-tested without needing a signed response.
func extractAssertion(a *csaml.Assertion, emailAttr, nameAttr, groupsAttr string) *AssertionInfo {
	info := &AssertionInfo{}
	if a.Subject != nil && a.Subject.NameID != nil {
		info.Subject = a.Subject.NameID.Value
	}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			// Presence is recorded BEFORE the empty-values skip below: a groups
			// attribute with no (non-blank) values is the IdP asserting "no
			// groups", which must reconcile to zero, not read as absent (#2903).
			if attrMatches(attr, groupsAttr) {
				info.GroupsPresent = true
			}
			vals := attributeValues(attr)
			if len(vals) == 0 {
				continue
			}
			switch {
			case attrMatches(attr, emailAttr):
				info.Email = vals[0]
			case attrMatches(attr, nameAttr):
				info.Name = vals[0]
			case attrMatches(attr, groupsAttr):
				info.Groups = append(info.Groups, vals...)
			}
		}
	}
	return info
}

// attrMatches reports whether the attribute is the one named by want (by Name or
// FriendlyName, case-insensitive on FriendlyName).
func attrMatches(attr csaml.Attribute, want string) bool {
	return attr.Name == want || strings.EqualFold(attr.FriendlyName, want)
}

// attributeValues returns the non-empty string values of an attribute.
func attributeValues(attr csaml.Attribute) []string {
	out := make([]string, 0, len(attr.Values))
	for _, v := range attr.Values {
		if s := strings.TrimSpace(v.Value); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// parseIDPMetadata parses IdP SAML metadata, accepting either a single EntityDescriptor
// or an EntitiesDescriptor wrapper (picking the entity that has an IDPSSODescriptor). It
// runs the XML round-trip validator first (defence against XML parser quirks), mirroring
// crewjam's samlsp.ParseMetadata without pulling that package's heavier dependencies.
func parseIDPMetadata(data []byte) (*csaml.EntityDescriptor, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty metadata")
	}
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("metadata failed XML validation: %w", err)
	}
	entity := &csaml.EntityDescriptor{}
	err := xml.Unmarshal(data, entity)
	if err != nil && strings.Contains(err.Error(), "EntitiesDescriptor") {
		entities := &csaml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		for i := range entities.EntityDescriptors {
			if len(entities.EntityDescriptors[i].IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		return nil, errors.New("no IDPSSODescriptor in metadata")
	}
	if err != nil {
		return nil, err
	}
	if len(entity.IDPSSODescriptors) == 0 {
		return nil, errors.New("metadata has no IDPSSODescriptor")
	}
	return entity, nil
}
