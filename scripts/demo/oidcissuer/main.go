// Command oidcissuer is a local stand-in for a CI platform's OIDC issuer (think GitHub
// Actions / GitLab CI) for scripts/demo/scenario-oidc-federation.sh: it serves a JWKS and
// mints short-lived RS256 ID tokens signed by its own key. DEMO/TEST helper only - it is
// never part of a shipped binary and its key is a throwaway.
//
//	oidcissuer serve -dir DIR -addr 127.0.0.1:18520       # GET /jwks.json (blocks)
//	oidcissuer mint  -dir DIR -issuer URL -sub SUBJECT -aud AUDIENCE [-ttl 5m] [-iat-offset 0s]
//
// The signing key lives in DIR/oidc-signing-key.pem (0600, created on first use). `mint`
// prints the compact JWT on stdout; callers pass it to curl through a header file, never
// on a command line.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const keyID = "demo-issuer-key-1"

func main() {
	if len(os.Args) < 2 {
		fail("usage: oidcissuer serve|mint [flags]")
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "mint":
		mint(os.Args[2:])
	default:
		fail("unknown subcommand " + os.Args[1])
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "oidcissuer:", msg)
	os.Exit(1)
}

func loadOrCreateKey(dir string) *rsa.PrivateKey {
	path := filepath.Join(dir, "oidc-signing-key.pem")
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- demo helper, path under the demo dir
		block, _ := pem.Decode(b)
		if block == nil {
			fail("unreadable key file " + path)
		}
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			fail(err.Error())
		}
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fail(err.Error())
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fail(err.Error())
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		fail(err.Error())
	}
	return k
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory holding the signing key")
	addr := fs.String("addr", "127.0.0.1:18520", "listen address (loopback only)")
	_ = fs.Parse(args)
	key := loadOrCreateKey(*dir)
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": keyID,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintln(os.Stderr, "oidcissuer: serving JWKS on http://"+*addr+"/jwks.json")
	if err := srv.ListenAndServe(); err != nil {
		fail(err.Error())
	}
}

func mint(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory holding the signing key")
	issuer := fs.String("issuer", "", "token issuer (iss)")
	sub := fs.String("sub", "", "token subject (sub)")
	aud := fs.String("aud", "", "token audience (aud)")
	ttl := fs.Duration("ttl", 5*time.Minute, "token lifetime")
	iatOffset := fs.Duration("iat-offset", 0, "shift iat/exp (negative = minted in the past)")
	_ = fs.Parse(args)
	if *issuer == "" || *sub == "" || *aud == "" {
		fail("mint needs -issuer, -sub and -aud")
	}
	key := loadOrCreateKey(*dir)
	now := time.Now().Add(*iatOffset)
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": *issuer, "sub": *sub, "aud": *aud,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(*ttl).Unix(),
	})
	t.Header["kid"] = keyID
	s, err := t.SignedString(key)
	if err != nil {
		fail(err.Error())
	}
	fmt.Println(s)
}
