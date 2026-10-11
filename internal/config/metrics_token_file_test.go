package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// SECURE-DEFAULT-1: server.{http,grpc}.metrics_token_file. admin init points
// both listeners at a generated 0600 token file.
func TestResolveMetricsToken(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	if err := os.WriteFile(good, []byte("tok-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		inst    ServerInstanceConfig
		want    string
		wantErr string
	}{
		{"neither", ServerInstanceConfig{}, "", ""},
		{"inline", ServerInstanceConfig{MetricsToken: "inline"}, "inline", ""},
		{"file", ServerInstanceConfig{MetricsTokenFile: good}, "tok-from-file", ""},
		{"both", ServerInstanceConfig{MetricsToken: "x", MetricsTokenFile: good}, "", "both metrics_token and metrics_token_file"},
		{"missing file", ServerInstanceConfig{MetricsTokenFile: filepath.Join(dir, "nope")}, "", "metrics_token_file"},
		{"empty file", ServerInstanceConfig{MetricsTokenFile: empty}, "", "metrics_token_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.inst.ResolveMetricsToken()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("returned token %q alongside an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ResolveMetricsToken() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// An unreadable token file refuses to start (Validate), counts as "no token"
// in the posture registry, and is covered by the secret-file permission check.
func TestMetricsTokenFile_ValidateRegistryAndPermissionCheck(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	if err := os.WriteFile(good, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := func(t *testing.T) InsecureSetting {
		for _, s := range InsecureSettingsRegistry {
			if s.Name == "server.insecure_allow_unauthenticated_metrics" {
				return s
			}
		}
		t.Fatal("registry entry server.insecure_allow_unauthenticated_metrics not found")
		return InsecureSetting{}
	}(t)

	c := &Config{}
	c.Server.HTTP.MetricsTokenFile = good
	c.Server.GRPC.MetricsTokenFile = good
	if err := c.ValidateSecretSources(); err != nil {
		t.Fatalf("ValidateSecretSources with a readable token file: %v", err)
	}
	if entry.InEffect(c) {
		t.Fatal("unauthenticated-metrics deviation reported although both listeners have a token file")
	}
	if paths := c.SecretFilePaths(); !slices.Contains(paths, good) || len(slices.Compact(slices.Sorted(slices.Values(paths)))) != len(paths) {
		t.Fatalf("SecretFilePaths() = %v, want %s exactly once", paths, good)
	}

	c.Server.GRPC.MetricsTokenFile = filepath.Join(dir, "missing")
	if err := c.ValidateSecretSources(); err == nil || !strings.Contains(err.Error(), "server.grpc") {
		t.Fatalf("ValidateSecretSources with a missing token file = %v, want an error naming server.grpc", err)
	}
	if !entry.InEffect(c) {
		t.Fatal("an unreadable token file must count as no token (fail closed)")
	}
}
