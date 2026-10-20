// Package webauthnparse holds the WebAuthn parser fuzz targets, with no Keyorix
// production code to wrap: FuzzWebAuthnCredentialResponse (the parse alone),
// and FuzzWebAuthnRegistrationCeremony / FuzzWebAuthnAssertionCeremony (parse
// plus the library verification the finish handlers run, seeded with real
// ceremonies; ceremony_fuzz_test.go). The first fuzzes go-webauthn/webauthn's
// own protocol.ParseCredentialCreationResponseBytes/
// ParseCredentialRequestResponseBytes directly on raw browser-supplied bytes
// — the WebAuthn ceremony-finish endpoints (server/http/handlers/webauthn.go)
// hand these bytes straight to the library with no Keyorix-side schema
// validation in front of them, so a panic/hang inside the parser is a
// pre-auth DoS reachable before any Keyorix code runs. There is nothing here
// to move OUT of server/http/handlers: the test file already imported only
// the third-party protocol package, testing, and internal/fuzzutil — never
// anything from package handlers — so moving the file lowers coverage-map
// size (Go's fuzzer tracks coverage over every package the compiled test
// binary links, and package handlers links the whole HTTP server dependency
// tree) with zero production-code change on either side.
//
// This file exists only so TestWebauthnparseStaysALeaf has at least one
// non-test file to check — matching the leaf-package pattern started at
// internal/core/rules (#2001) even though, uniquely among this codebase's
// leaf packages so far, there is no production wrapper/compat layer: no
// Keyorix function moved, so no Keyorix caller needs one.
package webauthnparse
