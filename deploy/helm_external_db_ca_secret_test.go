package deploy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// externalDatabase.caSecret (PG-TLS-2 item 3): the chart could pass
// externalDatabase.sslRootCert through as storage.database.ssl_root_cert but
// could not get a CA file into the server pod, so verify-full against a
// private CA needed a hand-patched Deployment. With caSecret the chart mounts
// the Secret's key read-only at /app/db-ca/ca.crt and names that path in the
// config.
//
// What this does not cover: a kubelet's real file modes for the mounted
// Secret (0440 + fsGroup, the same mode the chart's `secrets` volume relies
// on), and a pod connecting to a real TLS PostgreSQL through it; the CA check
// itself (config.ValidateDatabaseTLS) is exercised on a file written with
// that mode.

var externalDBSets = []string{
	"postgresql.enabled=false", "externalDatabase.host=db.example", "externalDatabase.password=x",
}

const dbCAFile = "/app/db-ca/ca.crt"

type k8sDeployment struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				InitContainers []k8sContainer `yaml:"initContainers"`
				Containers     []k8sContainer `yaml:"containers"`
				Volumes        []struct {
					Name   string `yaml:"name"`
					Secret *struct {
						SecretName  string `yaml:"secretName"`
						DefaultMode *int   `yaml:"defaultMode"`
						Items       []struct {
							Key  string `yaml:"key"`
							Path string `yaml:"path"`
						} `yaml:"items"`
					} `yaml:"secret"`
				} `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type k8sContainer struct {
	Name         string `yaml:"name"`
	VolumeMounts []struct {
		Name      string `yaml:"name"`
		MountPath string `yaml:"mountPath"`
		SubPath   string `yaml:"subPath"`
		ReadOnly  bool   `yaml:"readOnly"`
	} `yaml:"volumeMounts"`
}

// serverDeployment renders the chart and returns the server Deployment.
func serverDeployment(t *testing.T, sets ...string) k8sDeployment {
	t.Helper()
	out, err := helmTemplateRaw(t, sets...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dec := yaml.NewDecoder(bytes.NewReader([]byte(out)))
	for {
		var d k8sDeployment
		if err := dec.Decode(&d); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if d.Kind == "Deployment" && strings.HasSuffix(d.Metadata.Name, "-server") {
			return d
		}
	}
	t.Fatalf("no server Deployment in the render")
	return k8sDeployment{}
}

func TestHelmExternalDatabaseCASecret_MountedReadOnlyAndNamedInConfig(t *testing.T) {
	for _, secure := range []string{"false", "true"} {
		t.Run("secureBaseline="+secure, func(t *testing.T) {
			sets := append(append([]string{}, externalDBSets...),
				"secureBaseline.enabled="+secure,
				"externalDatabase.sslMode=verify-full",
				"externalDatabase.caSecret.name=pg-ca", "externalDatabase.caSecret.key=root.pem")
			d := serverDeployment(t, sets...)

			var found bool
			for _, v := range d.Spec.Template.Spec.Volumes {
				if v.Name != "db-ca" {
					continue
				}
				found = true
				if v.Secret == nil || v.Secret.SecretName != "pg-ca" {
					t.Fatalf("db-ca volume must be the Secret pg-ca, got %+v", v.Secret)
				}
				if v.Secret.DefaultMode == nil || *v.Secret.DefaultMode != 0o440 {
					t.Errorf("db-ca defaultMode must be 0440 (the CA check refuses group/world-writable files)")
				}
				if len(v.Secret.Items) != 1 || v.Secret.Items[0].Key != "root.pem" || v.Secret.Items[0].Path != "ca.crt" {
					t.Errorf("db-ca must project exactly key root.pem to ca.crt, got %+v", v.Secret.Items)
				}
			}
			if !found {
				t.Fatal("no db-ca volume rendered for externalDatabase.caSecret")
			}

			var mounted bool
			for _, c := range d.Spec.Template.Spec.Containers {
				if c.Name != "server" {
					continue
				}
				for _, m := range c.VolumeMounts {
					if m.Name != "db-ca" {
						continue
					}
					mounted = true
					if m.MountPath+"/ca.crt" != dbCAFile || !m.ReadOnly || m.SubPath != "" {
						t.Errorf("server must mount db-ca read-only as a directory at %s, got %+v", filepath.Dir(dbCAFile), m)
					}
				}
			}
			if !mounted {
				t.Fatal("server container does not mount db-ca")
			}

			cfgPath := renderHelmServerConfig(t, sets...)
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Storage.Database.SSLRootCert; got != dbCAFile {
				t.Fatalf("ssl_root_cert = %q, want %q", got, dbCAFile)
			}
		})
	}
}

// The rendered config, with the CA file present at the mount path with the
// mount's mode, passes the server's own check; the check still refuses the
// file when it is group-writable, so the 0440 above is load-bearing.
func TestHelmExternalDatabaseCASecret_RenderedConfigPassesServerCheck(t *testing.T) {
	sets := append(append([]string{}, externalDBSets...),
		"externalDatabase.sslMode=verify-full", "externalDatabase.caSecret.name=pg-ca")
	body, err := os.ReadFile(renderHelmServerConfig(t, sets...))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, testCAPEM(t), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o440); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(p, bytes.ReplaceAll(body, []byte(dbCAFile), []byte(ca)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateDatabaseTLS(&cfg.Storage.Database); err != nil {
		t.Fatalf("rendered caSecret config refused by the server's check: %v", err)
	}
	if err := os.Chmod(ca, 0o460); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateDatabaseTLS(&cfg.Storage.Database); err == nil {
		t.Fatal("calibration: a group-writable CA file must be refused")
	}
}

// Shapes the server would refuse at boot, or that are ambiguous, fail the
// render with a message naming the fix.
func TestHelmExternalDatabaseCASecret_RefusedShapes(t *testing.T) {
	cases := map[string]struct {
		sets []string
		want string
	}{
		"verify-full without any CA": {
			append(append([]string{}, externalDBSets...), "externalDatabase.sslMode=verify-full"),
			"externalDatabase.sslMode is verify-full but no CA is configured",
		},
		"verify-ca without any CA": {
			append(append([]string{}, externalDBSets...), "externalDatabase.sslMode=verify-ca"),
			"externalDatabase.sslMode is verify-ca but no CA is configured",
		},
		"caSecret and sslRootCert": {
			append(append([]string{}, externalDBSets...), "externalDatabase.sslMode=verify-full",
				"externalDatabase.caSecret.name=pg-ca", "externalDatabase.sslRootCert=system"),
			"not both",
		},
		"caSecret with sslMode disable": {
			append(append([]string{}, externalDBSets...), "externalDatabase.sslMode=disable",
				"externalDatabase.caSecret.name=pg-ca"),
			"externalDatabase.caSecret needs externalDatabase.sslMode verify-full",
		},
		"caSecret with sslMode prefer": {
			append(append([]string{}, externalDBSets...), "externalDatabase.sslMode=prefer",
				"externalDatabase.caSecret.name=pg-ca"),
			"externalDatabase.caSecret needs externalDatabase.sslMode verify-full",
		},
		"caSecret with an empty key": {
			append(append([]string{}, externalDBSets...), "externalDatabase.sslMode=verify-full",
				"externalDatabase.caSecret.name=pg-ca", "externalDatabase.caSecret.key="),
			"externalDatabase.caSecret.key must name",
		},
		"caSecret with the bundled PostgreSQL": {
			[]string{"externalDatabase.caSecret.name=pg-ca"},
			"externalDatabase.caSecret applies to an external database only",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := helmTemplateRaw(t, tc.sets...)
			if err == nil {
				t.Fatalf("render must fail, got success")
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("render error must contain %q, got:\n%s", tc.want, out)
			}
		})
	}
}

// The controls: without caSecret nothing new is rendered (no db-ca volume, no
// ssl_root_cert), and sslRootCert alone still renders as before.
func TestHelmExternalDatabaseCASecret_AbsentRendersNothingNew(t *testing.T) {
	for _, sets := range [][]string{
		nil, // bundled PostgreSQL
		externalDBSets,
		append(append([]string{}, externalDBSets...), "externalDatabase.sslMode=verify-full", "externalDatabase.sslRootCert=system"),
	} {
		out, err := helmTemplateRaw(t, sets...)
		if err != nil {
			t.Fatalf("helm template %v: %v\n%s", sets, err, out)
		}
		if strings.Contains(out, "db-ca") {
			t.Errorf("render %v mounts db-ca without externalDatabase.caSecret", sets)
		}
	}
	cfg, err := config.Load(renderHelmServerConfig(t, append(append([]string{}, externalDBSets...),
		"externalDatabase.sslMode=verify-full", "externalDatabase.sslRootCert=system")...))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Database.SSLRootCert != config.SSLRootCertSystem {
		t.Errorf("sslRootCert=system must still render as ssl_root_cert: system, got %q", cfg.Storage.Database.SSLRootCert)
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pg-tls-2-helm-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
