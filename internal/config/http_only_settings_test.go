package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPOnlySettingsSetUnderGRPC(t *testing.T) {
	t.Run("nothing set: no warnings", func(t *testing.T) {
		assert.Empty(t, HTTPOnlySettingsSetUnderGRPC(&Config{}))
	})
	t.Run("the same keys under http are the real ones: no warnings", func(t *testing.T) {
		cfg := &Config{}
		cfg.Server.HTTP.TrustedProxies = []string{"10.0.0.0/8"}
		cfg.Server.HTTP.HSTSPreload = true
		assert.Empty(t, HTTPOnlySettingsSetUnderGRPC(cfg))
	})
	t.Run("trusted_proxies under grpc warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Server.GRPC.TrustedProxies = []string{"10.0.0.0/8"}
		got := HTTPOnlySettingsSetUnderGRPC(cfg)
		if assert.Len(t, got, 1) {
			assert.Contains(t, got[0], "server.grpc.trusted_proxies")
			assert.Contains(t, got[0], "server.http.trusted_proxies")
		}
	})
	t.Run("hsts_preload under grpc warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Server.GRPC.HSTSPreload = true
		got := HTTPOnlySettingsSetUnderGRPC(cfg)
		if assert.Len(t, got, 1) {
			assert.Contains(t, got[0], "server.grpc.hsts_preload")
		}
	})
	t.Run("both warn", func(t *testing.T) {
		cfg := &Config{}
		cfg.Server.GRPC.TrustedProxies = []string{"10.0.0.1"}
		cfg.Server.GRPC.HSTSPreload = true
		assert.Len(t, HTTPOnlySettingsSetUnderGRPC(cfg), 2)
	})
}
