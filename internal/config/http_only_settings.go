package config

import "fmt"

// HTTPOnlySettingsSetUnderGRPC lists every security setting that is set under
// server.grpc but is implemented only by the HTTP server. server.http and
// server.grpc share ServerInstanceConfig, so these keys parse under grpc yet do
// nothing there: the gRPC server rewrites no client IP and sends no HSTS. A
// security setting that is accepted and ignored must not be silent, so the server
// warns about each one at start-up (server/main.go warnHTTPOnlySettingsUnderGRPC).
func HTTPOnlySettingsSetUnderGRPC(cfg *Config) []string {
	var out []string
	if len(cfg.Server.GRPC.TrustedProxies) > 0 {
		out = append(out, httpOnlyWarning("server.grpc.trusted_proxies", "server.http.trusted_proxies"))
	}
	if cfg.Server.GRPC.HSTSPreload {
		out = append(out, httpOnlyWarning("server.grpc.hsts_preload", "server.http.hsts_preload"))
	}
	return out
}

func httpOnlyWarning(key, httpKey string) string {
	return fmt.Sprintf("%s is set but has no effect: it is an HTTP-only setting (the gRPC server does not read it). Set %s instead, or remove it.", key, httpKey)
}
