// secret_create_env_test.go -- #3155: `secret create --project N` without --environment used to
// send environment 1 whatever the project, and the refusal did not name a valid one.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretEnvServer serves project 2's environments (4 development, 5 staging, 6 production) and
// records the environment_id of the secret it is asked to create. A create into an environment
// that is not one of project 2's gets the server's real refusal text.
func secretEnvServer(t *testing.T, gotEnv *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/2/environments":
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":5,"name":"staging"},{"id":4,"name":"development"},{"id":6,"name":"production"}]}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets":
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				EnvironmentID int `json:"environment_id"`
			}
			_ = json.Unmarshal(raw, &body)
			*gotEnv = body.EnvironmentID
			if body.EnvironmentID < 4 || body.EnvironmentID > 6 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"error":"BadRequest","message":"environment %d does not belong to project 2"}`, body.EnvironmentID)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"id":9,"name":"s","type":"generic","project_id":2,"environment_id":%d}}`, body.EnvironmentID)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func resetSecretCreateFlags() {
	secretCreateName, secretCreateValue, secretCreateFromFile = "", "", ""
	secretCreateType, secretCreateProjectID, secretCreateEnvironmentID = "generic", 1, 1
	secretCreateCmd.Flags().Lookup("environment").Changed = false
}

func TestSecretCreate_DefaultEnvironmentIsTheProjectsDevelopment(t *testing.T) {
	var gotEnv int
	setPATCreds(t, secretEnvServer(t, &gotEnv))
	secretCreateName, secretCreateValue, secretCreateProjectID = "s", "v", 2
	defer resetSecretCreateFlags()

	captureStdout(t, func() {
		if err := runSecretCreate(secretCreateCmd, nil); err != nil {
			t.Fatalf("runSecretCreate without --environment: %v", err)
		}
	})
	if gotEnv != 4 {
		t.Fatalf("sent environment_id %d, want 4 (project 2's development)", gotEnv)
	}
}

// A project with no "development" environment must not silently fall back to its first
// listed environment (here production): the create is refused client-side, naming the
// environments, and nothing is sent. An explicit --environment still works.
func TestSecretCreate_NoDevelopmentEnvironmentRequiresTheFlag(t *testing.T) {
	var created bool
	var gotEnv int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/3/environments":
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":9,"name":"production"},{"id":8,"name":"staging"}]}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets":
			created = true
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				EnvironmentID int `json:"environment_id"`
			}
			_ = json.Unmarshal(raw, &body)
			gotEnv = body.EnvironmentID
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"id":9,"name":"s","type":"generic","project_id":3,"environment_id":%d}}`, body.EnvironmentID)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	setPATCreds(t, srv)
	secretCreateName, secretCreateValue, secretCreateProjectID = "s", "v", 3
	defer resetSecretCreateFlags()

	err := runSecretCreate(secretCreateCmd, nil)
	if err == nil {
		t.Fatal("expected an error: project 3 has no development environment and --environment was not given")
	}
	if created {
		t.Fatalf("a secret was created (environment %d) without --environment", gotEnv)
	}
	for _, want := range []string{"no \"development\" environment", "--environment is required", "9 (production)", "8 (staging)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}

	if err := secretCreateCmd.Flags().Set("environment", "8"); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if err := runSecretCreate(secretCreateCmd, nil); err != nil {
			t.Fatalf("explicit --environment 8: %v", err)
		}
	})
	if !created || gotEnv != 8 {
		t.Fatalf("explicit --environment not sent as given: created=%v env=%d", created, gotEnv)
	}
}

func TestSecretCreate_ExplicitWrongEnvironmentNamesTheValidOnes(t *testing.T) {
	var gotEnv int
	setPATCreds(t, secretEnvServer(t, &gotEnv))
	secretCreateName, secretCreateValue, secretCreateProjectID = "s", "v", 2
	if err := secretCreateCmd.Flags().Set("environment", "1"); err != nil {
		t.Fatal(err)
	}
	defer resetSecretCreateFlags()

	err := runSecretCreate(secretCreateCmd, nil)
	if err == nil {
		t.Fatal("expected the server's refusal for environment 1 in project 2")
	}
	if gotEnv != 1 {
		t.Fatalf("an explicit --environment must be sent as given, got %d", gotEnv)
	}
	for _, want := range []string{"does not belong to project 2", "4 (development)", "5 (staging)", "6 (production)", "--environment"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

func TestReadSecretValueFromFile_AbsolutePathRefusalSaysWhatToDo(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "v.txt")
	if err := os.WriteFile(abs, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readSecretValueFromFile(abs)
	if err == nil {
		t.Fatal("an absolute path must still be refused")
	}
	for _, want := range []string{"absolute paths are not allowed", "relative to the current directory", "./v.txt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}
