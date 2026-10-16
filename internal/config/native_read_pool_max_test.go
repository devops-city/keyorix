package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestNativeReadPoolMax_DefaultIsUnchanged: unset (or 0) is the cap the pool
// always had.
func TestNativeReadPoolMax_DefaultIsUnchanged(t *testing.T) {
	assert.Equal(t, 8, DefaultNativeReadPoolMax, "the default must not change")
	assert.Equal(t, 8, (&DatabaseConfig{}).EffectiveNativeReadPoolMax())
	assert.Equal(t, 3, (&DatabaseConfig{NativeReadPoolMax: 3}).EffectiveNativeReadPoolMax())
}

// TestNativeReadPoolMax_ReadFromYAML: the key is storage.database.native_read_pool_max.
func TestNativeReadPoolMax_ReadFromYAML(t *testing.T) {
	var s struct {
		Storage StorageConfig `yaml:"storage"`
	}
	require.NoError(t, yaml.Unmarshal([]byte("storage:\n  type: postgres\n  database:\n    native_read_pool_max: 12\n"), &s))
	assert.Equal(t, 12, s.Storage.Database.NativeReadPoolMax)
}

func TestValidate_NativeReadPoolMax(t *testing.T) {
	for _, tc := range []struct {
		name        string
		storageType string
		n           int
		wantErr     string
	}{
		{"unset on postgres", "postgres", 0, ""},
		{"unset on local", "local", 0, ""},
		{"one", "postgres", 1, ""},
		{"max", "postgresql", MaxNativeReadPoolMax, ""},
		{"negative", "postgres", -1, "out of range"},
		{"above max", "postgres", MaxNativeReadPoolMax + 1, "out of range"},
		{"on local", "local", 4, "applies only to storage.type postgres"},
		{"on remote", "remote", 4, "applies only to storage.type postgres"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNativeReadPoolMax(tc.storageType, &DatabaseConfig{NativeReadPoolMax: tc.n})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Contains(t, err.Error(), "storage.database.native_read_pool_max")
		})
	}
}

// TestValidate_RefusesBadNativeReadPoolMax: the refusal is reached through Validate.
func TestValidate_RefusesBadNativeReadPoolMax(t *testing.T) {
	cfg := postgresConfig(&DatabaseConfig{DSN: "host=db user=keyorix dbname=keyorix sslmode=require", NativeReadPoolMax: -5})
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.database.native_read_pool_max")
}
