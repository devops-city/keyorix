package config

import "errors"

// ErrAutoCertInAirgapBuild refuses server.http.tls.auto_cert: true in the
// air-gapped server profile. ACME (Let's Encrypt) needs to reach a certificate
// authority on the internet: the autocert code is linked into every build, so
// without this check an air-gapped server started, resolved
// acme-v02.api.letsencrypt.org at the first TLS handshake and failed every
// handshake while start-up looked healthy (AIRGAP-PROOF-1 finding F1). Same
// fail-closed intent as the cloud-KMS refusal (internal/encryption/service.go),
// but raised by Config.Validate, so the server refuses before it listens.
var ErrAutoCertInAirgapBuild = errors.New("server.http.tls.auto_cert: true is not available in this build: " +
	"the air-gapped server profile never contacts the internet, and automatic (ACME / Let's Encrypt) " +
	"certificates need to reach a certificate authority. " +
	"Remove server.http.tls.auto_cert and domains, and set server.http.tls.cert_file and key_file " +
	"(certificate files issued by your internal CA), or use the full server build if the host can reach an ACME CA")

// validateAutoCertForProfile returns ErrAutoCertInAirgapBuild when airgap is
// true and the HTTP listener asks for auto_cert. It is refused whether or not
// tls.enabled is set (like the gRPC check): an operator who asked for ACME must
// not get a server that silently serves something else. airgap is a parameter
// so the default-profile tests can exercise the air-gapped decision too.
func validateAutoCertForProfile(c *Config, airgap bool) error {
	if airgap && c.Server.HTTP.TLS.AutoCert {
		return ErrAutoCertInAirgapBuild
	}
	return nil
}
