### Security
- **SAML responses are now checked strictly before processing.** The ACS endpoint accepts only the
  HTTP-POST binding with plaintext assertions: the artifact binding and encrypted assertions are
  refused (neither was documented as supported). A response must carry exactly one assertion with
  one subject `NameID` and one `Conditions` in the SAML 2.0 assertion namespace. Refusals return the
  same generic SAML login error as every other rejection and are logged server-side.
