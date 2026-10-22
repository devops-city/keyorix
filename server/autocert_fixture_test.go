package main

import "github.com/keyorixhq/keyorix/internal/config"

// autoCertTLSFixtureConfig is the HTTP TLS + auto_cert config the S27 AutoCert
// tests use. It is untagged so autocert_tls_full_test.go (builds only where
// auto_cert is allowed) and autocert_failclosed_airgap_test.go (the air-gap
// counterpart, asserting the refusal) share one fixture and cannot drift apart.
//
// #1475: cfg.Validate() requires at least one domain when AutoCert is set. The
// domain is a placeholder that is never resolved (no ACME handshake happens).
func autoCertTLSFixtureConfig(port, dbPath, domain string) *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: dbPath},
		},
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    port,
				TLS: config.TLSConfig{
					Enabled:  true,
					AutoCert: true,
					Domains:  []string{domain},
				},
			},
		},
	}
}
