package cmd

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
)

// doctorServer is a fake Keyorix server for doctor: every request method is recorded so
// tests can prove doctor only reads.
type doctorServer struct {
	mu      sync.Mutex
	methods []string
	paths   []string

	healthStatus   int
	versionBody    string // JSON for /api/v1/version; empty = 404
	dateOverride   string // sent as the Date header when non-empty
	profileStatus  int
	profileBody    string
	auditStatus    int
	auditBody      string
	systemInfoBody string
}

func healthyDoctorServer() *doctorServer {
	return &doctorServer{
		healthStatus:   200,
		versionBody:    `{"api_version":1,"minimum_cli_version":"1.0.0"}`,
		profileStatus:  200,
		profileBody:    `{"data":{"username":"alice","roles":["admin"]}}`,
		auditStatus:    200,
		auditBody:      `{"data":{"valid":true,"status":"valid","mode":"incremental","chained_events":42,"head_id":42,"last_full_verification_at":"2026-10-15T00:00:00Z"}}`,
		systemInfoBody: `{"data":{"version":"v9.9.9"}}`,
	}
}

func (d *doctorServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.methods = append(d.methods, r.Method)
		d.paths = append(d.paths, r.URL.Path)
		d.mu.Unlock()
		if d.dateOverride != "" {
			w.Header().Set("Date", d.dateOverride)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(d.healthStatus)
			_, _ = fmt.Fprint(w, `{"status":"healthy"}`)
		case "/api/v1/version":
			if d.versionBody == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprint(w, d.versionBody)
		case "/api/v1/auth/profile":
			w.WriteHeader(d.profileStatus)
			_, _ = fmt.Fprint(w, d.profileBody)
		case "/api/v1/audit/verify":
			w.WriteHeader(d.auditStatus)
			_, _ = fmt.Fprint(w, d.auditBody)
		case "/api/v1/system/info":
			_, _ = fmt.Fprint(w, d.systemInfoBody)
		default:
			http.NotFound(w, r)
		}
	})
}

func runDoctorReport(t *testing.T) *doctorReport {
	t.Helper()
	return collectDoctorReport(nil) //nolint:staticcheck // collectDoctorReport treats a nil context as Background
}

func (r *doctorReport) check(t *testing.T, name string) doctorCheck {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, r.Checks)
	return doctorCheck{}
}

// doctorIsolateEnv gives the test an empty user config directory and no CLI settings from
// the environment, so the developer's own credentials are never read.
func doctorIsolateEnv(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("APPDATA", home)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_CA_FILE", "")
}

func useServer(t *testing.T, url, token string) {
	t.Helper()
	doctorIsolateEnv(t)
	t.Setenv("KEYORIX_SERVER", url)
	t.Setenv("KEYORIX_TOKEN", token)
	t.Setenv("KEYORIX_CA_FILE", "")
}

func TestDoctor_HealthyServerPassesEverythingAndOnlyReads(t *testing.T) {
	d := healthyDoctorServer()
	srv := httptest.NewServer(d.handler())
	defer srv.Close()
	useServer(t, srv.URL, "tok")

	rep := runDoctorReport(t)
	for _, name := range []string{"config", "reachable", "version", "clock", "auth", "audit"} {
		if c := rep.check(t, name); c.Status != doctorPass {
			t.Errorf("%s: %s: %s (next: %s)", name, c.Status, c.Detail, c.NextStep)
		}
	}
	// Plain http to a loopback address: nothing to inspect, and not a warning.
	if c := rep.check(t, "tls"); c.Status != doctorSkip || !strings.Contains(c.Detail, "loopback") {
		t.Errorf("tls on loopback http: %+v", c)
	}
	if !rep.OK || rep.Failed != 0 {
		t.Errorf("report should be OK: %+v", rep)
	}
	if c := rep.check(t, "auth"); !strings.Contains(c.Detail, "alice") || !strings.Contains(c.Detail, "admin") {
		t.Errorf("auth should say who is logged in: %q", c.Detail)
	}
	if c := rep.check(t, "version"); !strings.Contains(c.Detail, "v9.9.9") {
		t.Errorf("version should include the server build when readable: %q", c.Detail)
	}
	// Read-only: no request may use a method that can change state, and the long
	// full audit walk (?full=true) must never be started.
	for i, m := range d.methods {
		if m != http.MethodGet {
			t.Errorf("doctor sent %s %s; it must only read", m, d.paths[i])
		}
	}
}

func TestDoctor_NeverShowsTheToken(t *testing.T) {
	srv := httptest.NewServer(healthyDoctorServer().handler())
	defer srv.Close()
	useServer(t, srv.URL, "super-secret-token-value")
	doctorOutput = "json"
	defer func() { doctorOutput = "table" }()
	out := captureStdout(t, func() {
		if err := runDoctor(doctorCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "super-secret-token-value") {
		t.Fatalf("the token leaked into doctor's output:\n%s", out)
	}
}

func TestDoctor_NotLoggedInAndNoServer(t *testing.T) {
	doctorIsolateEnv(t)
	rep := runDoctorReport(t)
	c := rep.check(t, "config")
	if c.Status != doctorFail || !strings.Contains(c.NextStep, "keyorix login") {
		t.Errorf("config: %+v", c)
	}
	for _, name := range []string{"reachable", "tls", "version", "clock", "auth", "audit"} {
		if got := rep.check(t, name).Status; got != doctorSkip {
			t.Errorf("%s should be skipped when nothing is configured, got %s", name, got)
		}
	}
	if rep.OK {
		t.Error("report must not be OK")
	}
}

func TestDoctor_NoTokenFailsAuthButNotTheRest(t *testing.T) {
	srv := httptest.NewServer(healthyDoctorServer().handler())
	defer srv.Close()
	useServer(t, srv.URL, "")
	rep := runDoctorReport(t)
	if c := rep.check(t, "reachable"); c.Status != doctorPass {
		t.Errorf("reachable: %+v", c)
	}
	if c := rep.check(t, "auth"); c.Status != doctorFail || !strings.Contains(c.NextStep, "keyorix login") {
		t.Errorf("auth: %+v", c)
	}
	if c := rep.check(t, "audit"); c.Status != doctorSkip {
		t.Errorf("audit needs a login: %+v", c)
	}
}

func TestDoctor_ServerDown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	useServer(t, url, "tok")
	rep := runDoctorReport(t)
	if c := rep.check(t, "reachable"); c.Status != doctorFail || !strings.Contains(c.NextStep, "server is running") {
		t.Errorf("reachable: %+v", c)
	}
	for _, name := range []string{"version", "clock", "auth", "audit"} {
		if got := rep.check(t, name).Status; got != doctorSkip {
			t.Errorf("%s should be skipped when the server is down, got %s", name, got)
		}
	}
}

func TestDoctor_ClockSkew(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset time.Duration
		want   string
	}{
		{"in sync", 2 * time.Second, doctorPass},
		{"a minute off", 90 * time.Second, doctorWarn},
		{"ten minutes off", 10 * time.Minute, doctorFail},
		{"ten minutes behind", -10 * time.Minute, doctorFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := healthyDoctorServer()
			d.dateOverride = time.Now().Add(tc.offset).UTC().Format(http.TimeFormat)
			srv := httptest.NewServer(d.handler())
			defer srv.Close()
			useServer(t, srv.URL, "tok")
			c := runDoctorReport(t).check(t, "clock")
			if c.Status != tc.want {
				t.Fatalf("status %s, want %s: %s", c.Status, tc.want, c.Detail)
			}
			if tc.want != doctorPass && !strings.Contains(c.NextStep, "NTP") {
				t.Errorf("a skewed clock should name how to fix it: %+v", c)
			}
		})
	}
}

func TestDoctor_VersionCompatibility(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"compatible", `{"api_version":1,"minimum_cli_version":"1.0.0"}`, doctorPass},
		{"cli below the server's floor", `{"api_version":1,"minimum_cli_version":"99.0.0"}`, doctorFail},
		{"old server without the endpoint", ``, doctorWarn},
	}
	// A "dev" build is not a semver, so skew.Check cannot compare it with a floor.
	realVersion := cliversion.Version
	cliversion.Version = "1.2.3"
	defer func() { cliversion.Version = realVersion }()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := healthyDoctorServer()
			d.versionBody = tc.body
			srv := httptest.NewServer(d.handler())
			defer srv.Close()
			useServer(t, srv.URL, "tok")
			c := runDoctorReport(t).check(t, "version")
			if c.Status != tc.want {
				t.Fatalf("status %s, want %s: %s", c.Status, tc.want, c.Detail)
			}
			if tc.want != doctorPass && c.NextStep == "" {
				t.Errorf("a problem needs a next step: %+v", c)
			}
		})
	}
}

func TestDoctor_AuthStates(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
		next   string
	}{
		{"expired session", 401, `{"message":"Invalid or expired token"}`, doctorFail, "keyorix login"},
		{"mfa enrolment wall", 403, `{"error":"MFAEnrollmentRequired","message":"mfa required"}`, doctorWarn, "keyorix mfa enroll"},
		{"other refusal", 403, `{"message":"nope"}`, doctorFail, "administrator"},
		{"unfinished setup", 200, `{"data":{"username":"bob","pending_steps":["enroll_mfa"]}}`, doctorWarn, "mfa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := healthyDoctorServer()
			d.profileStatus, d.profileBody = tc.status, tc.body
			srv := httptest.NewServer(d.handler())
			defer srv.Close()
			useServer(t, srv.URL, "tok")
			c := runDoctorReport(t).check(t, "auth")
			if c.Status != tc.want || !strings.Contains(c.NextStep, tc.next) {
				t.Fatalf("got %+v, want status %s with next step containing %q", c, tc.want, tc.next)
			}
		})
	}
}

func TestDoctor_AuditStates(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
		next   string
	}{
		{"valid", 200, `{"data":{"valid":true,"status":"valid","chained_events":5,"head_id":5}}`, doctorPass, ""},
		{"not proven", 200, `{"data":{"valid":true,"status":"not_proven","not_proven_reason":"no full walk yet","chained_events":5,"head_id":5}}`, doctorWarn, "--full"},
		{"broken", 200, `{"data":{"valid":false,"status":"broken","first_broken_id":3,"reason":"hash mismatch"}}`, doctorFail, "incident"},
		{"no audit.read", 403, `{"message":"forbidden"}`, doctorSkip, "auditor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := healthyDoctorServer()
			d.auditStatus, d.auditBody = tc.status, tc.body
			srv := httptest.NewServer(d.handler())
			defer srv.Close()
			useServer(t, srv.URL, "tok")
			c := runDoctorReport(t).check(t, "audit")
			if c.Status != tc.want || !strings.Contains(c.NextStep, tc.next) {
				t.Fatalf("got %+v, want status %s with next step containing %q", c, tc.want, tc.next)
			}
		})
	}
}

func TestDoctor_TLS(t *testing.T) {
	d := healthyDoctorServer()
	srv := httptest.NewTLSServer(d.handler())
	defer srv.Close()
	useServer(t, srv.URL, "tok")

	t.Run("a private CA that is not trusted fails with the fix", func(t *testing.T) {
		rep := runDoctorReport(t)
		// Without the CA, even reaching the server fails verification...
		if c := rep.check(t, "reachable"); c.Status != doctorFail {
			t.Fatalf("reachable should fail on an untrusted certificate: %+v", c)
		}
		// ...and the tls check says why and how to fix it.
		c := rep.check(t, "tls")
		if c.Status != doctorFail || !strings.Contains(c.Detail, "does not verify against system roots") ||
			!strings.Contains(c.NextStep, "ca_file") {
			t.Fatalf("tls: %+v", c)
		}
	})

	t.Run("with the CA file everything verifies and the chain is shown", func(t *testing.T) {
		caPath := filepath.Join(t.TempDir(), "ca.pem")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KEYORIX_CA_FILE", caPath)
		rep := runDoctorReport(t)
		c := rep.check(t, "tls")
		if c.Status != doctorPass {
			t.Fatalf("tls: %+v", c)
		}
		for _, w := range []string{"chain verifies against " + caPath, "TLS 1.", "expires"} {
			if !strings.Contains(c.Detail, w) {
				t.Errorf("tls detail lacks %q: %s", w, c.Detail)
			}
		}
		if got := rep.check(t, "reachable").Status; got != doctorPass {
			t.Errorf("reachable with the CA: %s", got)
		}
	})

	t.Run("an expired or near-expiry leaf is reported", func(t *testing.T) {
		caPath := filepath.Join(t.TempDir(), "ca.pem")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KEYORIX_CA_FILE", caPath)
		real := doctorNow
		defer func() { doctorNow = real }()

		doctorNow = func() time.Time { return srv.Certificate().NotAfter.Add(-10 * 24 * time.Hour) }
		if c := runDoctorReport(t).check(t, "tls"); c.Status != doctorWarn || !strings.Contains(c.NextStep, "renew") {
			t.Errorf("10 days left: %+v", c)
		}
	})
}

func TestDoctor_BadCAFileIsAConfigFailure(t *testing.T) {
	srv := httptest.NewServer(healthyDoctorServer().handler())
	defer srv.Close()
	useServer(t, srv.URL, "tok")
	t.Setenv("KEYORIX_CA_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	rep := runDoctorReport(t)
	if c := rep.check(t, "config"); c.Status != doctorFail || !strings.Contains(c.NextStep, "ca_file") {
		t.Errorf("config: %+v", c)
	}
	if got := rep.check(t, "reachable").Status; got != doctorSkip {
		t.Errorf("reachable should be skipped, got %s", got)
	}
}

func TestDoctor_PlainHTTPToARemoteHostWarns(t *testing.T) {
	rep := &doctorReport{}
	doctorTLS(t.Context(), rep, "http://kx.example.com", "", true)
	if c := rep.Checks[0]; c.Status != doctorWarn || !strings.Contains(c.Detail, "plain http") {
		t.Errorf("tls: %+v", c)
	}
}

func TestDoctor_OutputFormatsAndExitStatus(t *testing.T) {
	srv := httptest.NewServer(healthyDoctorServer().handler())
	defer srv.Close()
	useServer(t, srv.URL, "tok")
	defer func() { doctorOutput = "table" }()

	doctorOutput = "table"
	out := captureStdout(t, func() {
		if err := runDoctor(doctorCmd, nil); err != nil {
			t.Fatalf("healthy server: %v", err)
		}
	})
	if !strings.Contains(out, "PASS  config") || !strings.Contains(out, "6 passed") {
		t.Errorf("table output:\n%s", out)
	}

	doctorOutput = "json"
	out = captureStdout(t, func() { _ = runDoctor(doctorCmd, nil) })
	var asJSON doctorReport
	if err := json.Unmarshal([]byte(out), &asJSON); err != nil || len(asJSON.Checks) != 7 || !asJSON.OK {
		t.Errorf("json output: %v\n%s", err, out)
	}

	doctorOutput = "yaml"
	out = captureStdout(t, func() { _ = runDoctor(doctorCmd, nil) })
	var asYAML map[string]any
	if err := yaml.Unmarshal([]byte(out), &asYAML); err != nil || asYAML["ok"] != true {
		t.Errorf("yaml output: %v\n%s", err, out)
	}

	doctorOutput = "xml"
	if err := runDoctor(doctorCmd, nil); err == nil || !strings.Contains(err.Error(), "table, json or yaml") {
		t.Errorf("a bad format must be refused, got %v", err)
	}

	// A failing check makes the command fail (after printing the report).
	doctorOutput = "table"
	d := healthyDoctorServer()
	d.profileStatus, d.profileBody = 401, `{"message":"expired"}`
	bad := httptest.NewServer(d.handler())
	defer bad.Close()
	useServer(t, bad.URL, "tok")
	var runErr error
	out = captureStdout(t, func() { runErr = runDoctor(doctorCmd, nil) })
	if runErr == nil || !strings.Contains(out, "FAIL  auth") || !strings.Contains(out, "Next step: run `keyorix login`") {
		t.Errorf("a failed check must fail the command and show its next step: err=%v\n%s", runErr, out)
	}
}
