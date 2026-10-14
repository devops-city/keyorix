// secret_ops_test.go — flag-validation and golden-output tests for PR 5's remaining
// commands (rotation-simulate, auto-rotate, bulk-rotate/rename/delete, expiring,
// orphaned, name-conformance, quota-report, ownership-history, reassign-owner,
// score, blast-radius, cert, audit, render, export, explain).
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// secretOpsRoute is one (method, path) -> responder pair for secretOpsServer.
type secretOpsRoute struct {
	method, path string
	respond      func(w http.ResponseWriter, r *http.Request)
}

func secretJSONRoute(method, path, body string) secretOpsRoute {
	return secretOpsRoute{method, path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}}
}

// secretOpsServer dispatches to the first matching (method, path) route --
// many of these commands each need their own small fixture.
func secretOpsServer(t *testing.T, routes ...secretOpsRoute) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, route := range routes {
			if r.Method == route.method && r.URL.Path == route.path {
				route.respond(w, r)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── versions / diff / rollback / comments ───────────────────────────────────────

func TestRunSecretVersions_RequiresID(t *testing.T) {
	secretVersionsID = 0
	if err := runSecretVersions(secretVersionsCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretVersions_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		secretJSONRoute(http.MethodGet, "/api/v1/secrets/1", `{"data":{"ID":1,"Name":"db-pass","Type":"generic"}}`),
		secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/versions", `{"data":{"versions":[{"ID":9,"VersionNumber":2,"ReadCount":3,"CreatedAt":"2026-01-02T00:00:00Z"}]}}`),
	)
	setPATCreds(t, srv)
	secretVersionsID, secretVersionsFormat = 1, "table"
	defer func() { secretVersionsID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretVersions(secretVersionsCmd, nil); err != nil {
			t.Fatalf("runSecretVersions: %v", err)
		}
	})
	if !containsAll(out, "db-pass", "VERSION", "READS", "2", "3") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// TestRunSecretVersions_LatestVersionIsTheHighestVersionNumber guards against a real
// DEMO-1 finding (#2563): the server returns versions newest-first (as this fixture
// does, matching production), but the summary line picked versions[len-1] -- the
// OLDEST entry, not the newest -- for "Latest Version". Red without the fix: the
// summary printed "Latest Version: 1" even though version 2 is newer and listed first.
func TestRunSecretVersions_LatestVersionIsTheHighestVersionNumber(t *testing.T) {
	srv := secretOpsServer(t,
		secretJSONRoute(http.MethodGet, "/api/v1/secrets/1", `{"data":{"ID":1,"Name":"stripe-api-key","Type":"generic"}}`),
		secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/versions", `{"data":{"versions":[
			{"ID":9,"VersionNumber":2,"ReadCount":0,"CreatedAt":"2026-10-03T10:46:35Z"},
			{"ID":8,"VersionNumber":1,"ReadCount":0,"CreatedAt":"2026-10-03T10:46:04Z"}
		]}}`),
	)
	setPATCreds(t, srv)
	secretVersionsID, secretVersionsFormat = 1, "table"
	defer func() { secretVersionsID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretVersions(secretVersionsCmd, nil); err != nil {
			t.Fatalf("runSecretVersions: %v", err)
		}
	})
	if !containsAll(out, "Latest Version: 2") {
		t.Fatalf("expected the higher version number (2) to be reported as latest, got: %q", out)
	}
	if containsAll(out, "Latest Version: 1") {
		t.Fatalf("latest version regressed to the oldest entry, got: %q", out)
	}
}

func TestRunSecretDiff_RequiresProjectAndEnvironmentWithoutID(t *testing.T) {
	secretDiffID, secretDiffProject, secretDiffEnv = 0, 0, 0
	if err := runSecretDiff(secretDiffCmd, []string{"my-secret", "1", "2"}); err == nil {
		t.Fatal("expected an error when --project/--environment are omitted and --id is unset")
	}
}

func TestRunSecretDiff_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/versions/1/diff/2",
			`{"data":{"secret_name":"db-pass","from_version":1,"to_version":2,"changes":[{"field":"classification","old_value":"","new_value":"confidential"}],"acl_user_ids":[7],"degraded":false}}`),
	)
	setPATCreds(t, srv)
	secretDiffID = 1
	defer func() { secretDiffID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretDiff(secretDiffCmd, []string{"db-pass", "1", "2"}); err != nil {
			t.Fatalf("runSecretDiff: %v", err)
		}
	})
	if !containsAll(out, "db-pass", "v1 -> v2", "classification", "confidential", "users [7]") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretRollback_RequiresIDAndVersion(t *testing.T) {
	secretRollbackID, secretRollbackVersion = 0, 0
	if err := secretRollbackCmd.RunE(secretRollbackCmd, nil); err == nil {
		t.Fatal("expected an error when --id/--version are omitted")
	}
}

func TestVersionCommentAdd_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		secretJSONRoute(http.MethodPost, "/api/v1/secrets/1/versions/2/comments", `{"data":{"id":5,"comment":"rotated","username":"alice","created_at":"2026-01-02T00:00:00Z"}}`),
	)
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := versionCommentAddCmd.RunE(versionCommentAddCmd, []string{"1", "2", "rotated"}); err != nil {
			t.Fatalf("versionCommentAddCmd: %v", err)
		}
	})
	if !containsAll(out, "Comment added (id=5)", "alice") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── acl ─────────────────────────────────────────────────────────────────────────

func TestSecretACLList_EmptyPrintsNoGrantsMessage(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/acl", `{"data":[]}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretACLListCmd.RunE(secretACLListCmd, []string{"1"}); err != nil {
			t.Fatalf("secretACLListCmd: %v", err)
		}
	})
	if !containsAll(out, "No ACL grants for this secret.") {
		t.Fatalf("output missing the empty-state message, got: %q", out)
	}
}

func TestSecretACLGrant_RequiresUserAndPerm(t *testing.T) {
	secretACLGrantSecret, secretACLGrantUser, secretACLGrantPerms = 1, 0, nil
	if err := secretACLGrantCmd.RunE(secretACLGrantCmd, nil); err == nil {
		t.Fatal("expected an error when --user/--perm are omitted")
	}
}

// ── folder ──────────────────────────────────────────────────────────────────────

func TestSecretFolderCreate_RequiresName(t *testing.T) {
	secretFolderCreateName = ""
	if err := runSecretFolderCreate(secretFolderCreateCmd, nil); err == nil {
		t.Fatal("expected an error when --name is omitted")
	}
}

func TestSecretFolderList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/folders", `{"data":[{"id":3,"name":"db-creds","project_id":1,"environment_id":1}]}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretFolderList(secretFolderListCmd, nil); err != nil {
			t.Fatalf("runSecretFolderList: %v", err)
		}
	})
	if !containsAll(out, "db-creds", "3") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── move / copy / copy-environment ──────────────────────────────────────────────

func TestSecretMove_RequiresID(t *testing.T) {
	secretMoveID = 0
	if err := secretMoveCmd.RunE(secretMoveCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretCopy_RequiresIDAndTargetEnv(t *testing.T) {
	secretCopyID, secretCopyToEnv = 0, 0
	if err := secretCopyCmd.RunE(secretCopyCmd, nil); err == nil {
		t.Fatal("expected an error when --id/--to-environment are omitted")
	}
}

func TestSecretCopyEnvironment_FromAndToMustDiffer(t *testing.T) {
	secretCopyEnvProject, secretCopyEnvFrom, secretCopyEnvTo = 1, 2, 2
	defer func() { secretCopyEnvProject, secretCopyEnvFrom, secretCopyEnvTo = 0, 0, 0 }()
	if err := secretCopyEnvironmentCmd.RunE(secretCopyEnvironmentCmd, nil); err == nil {
		t.Fatal("expected an error when --from-environment equals --to-environment")
	}
}

// ── deps ────────────────────────────────────────────────────────────────────────

func TestSecretDepsList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/dependencies",
		`{"data":{"secret_id":1,"depends_on":[{"id":2,"secret_id":5,"secret_name":"db-root","note":"rotation source"}],"dependents":[]}}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretDepsListCmd.RunE(secretDepsListCmd, []string{"1"}); err != nil {
			t.Fatalf("secretDepsListCmd: %v", err)
		}
	})
	if !containsAll(out, "Depends on (1)", "db-root", "rotation source", "Used by (0)") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestSecretDepsImpact_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/impact",
		`{"data":{"secret_id":1,"secret_name":"db-root","affected":[{"secret_id":9,"secret_name":"app-conn","depth":1}]}}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretDepsImpactCmd.RunE(secretDepsImpactCmd, []string{"1"}); err != nil {
			t.Fatalf("secretDepsImpactCmd: %v", err)
		}
	})
	if !containsAll(out, "db-root", "affects 1 secret(s)", "app-conn", "1 hop") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── access / access-log ──────────────────────────────────────────────────────────

func TestSecretAccess_RequiresID(t *testing.T) {
	secretAccessID = 0
	if err := secretAccessCmd.RunE(secretAccessCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretAccess_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/access",
		`{"data":{"accessors":[{"username":"alice","permission":"read","source":"owner"}]}}`))
	setPATCreds(t, srv)
	secretAccessID = 1
	defer func() { secretAccessID = 0 }()

	out := captureStdout(t, func() {
		if err := secretAccessCmd.RunE(secretAccessCmd, nil); err != nil {
			t.Fatalf("secretAccessCmd: %v", err)
		}
	})
	if !containsAll(out, "alice", "read", "owner") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// The effective level and every grant behind it are shown, so a write share that
// elevates a viewer role is visible (#2941).
func TestSecretAccess_ShowsEffectiveLevelAndGrants(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/access",
		`{"data":{"accessors":[{"username":"alice","permission":"write","source":"direct_share","grants":["role:read","direct_share:write"]},`+
			`{"username":"bob","permission":"read","source":"role","grants":["role:read"]}]}}`))
	setPATCreds(t, srv)
	secretAccessID = 1
	defer func() { secretAccessID = 0 }()

	out := captureStdout(t, func() {
		if err := secretAccessCmd.RunE(secretAccessCmd, nil); err != nil {
			t.Fatalf("secretAccessCmd: %v", err)
		}
	})
	if !containsAll(out, "GRANTS", "alice", "write", "role:read, direct_share:write", "bob", "role") {
		t.Fatalf("output missing the effective level or grants, got: %q", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("a complete list must not carry the incomplete warning, got: %q", out)
	}
}

// A degraded list (part withheld from this caller, or a lookup failed) is an
// under-count: the CLI must say so with the server's reasons, whether or not any
// accessor is listed, instead of printing a shortened list as if it were complete.
func TestSecretAccess_WarnsWhenDegraded(t *testing.T) {
	for name, body := range map[string]string{
		"with rows": `{"data":{"accessors":[{"username":"owner","permission":"owner","source":"owner","grants":["owner:owner"]}],` +
			`"degraded":true,"degraded_reasons":["project_members: the caller lacks users.read in the project","secret_acls: the caller lacks secrets.manage on the secret"]}}`,
		"no rows": `{"data":{"accessors":[],"degraded":true,` +
			`"degraded_reasons":["project_members: the caller lacks users.read in the project","secret_acls: the caller lacks secrets.manage on the secret"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/access", body))
			setPATCreds(t, srv)
			secretAccessID = 1
			defer func() { secretAccessID = 0 }()

			out := captureStdout(t, func() {
				if err := secretAccessCmd.RunE(secretAccessCmd, nil); err != nil {
					t.Fatalf("secretAccessCmd: %v", err)
				}
			})
			if !containsAll(out, "WARNING: this list is incomplete",
				"project_members: the caller lacks users.read in the project",
				"secret_acls: the caller lacks secrets.manage on the secret") {
				t.Fatalf("degraded list printed without the warning and its reasons, got: %q", out)
			}
		})
	}
}

func TestSecretAccessLog_RequiresID(t *testing.T) {
	secretAccessLogID = 0
	if err := secretAccessLogCmd.RunE(secretAccessLogCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

// TestSecretAccessLog_OmitsIPWhenServerOmitsIt is the CLI-side counterpart to
// the server fix in docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md:
// GET /api/v1/secrets/{id}/access-log now omits ip_address/user_agent entirely
// for a caller who doesn't separately hold audit.read (the common case). The
// CLI must render that row without erroring or printing a stale/garbage value.
func TestSecretAccessLog_OmitsIPWhenServerOmitsIt(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/access-log",
		`{"data":{"access_log":[{"id":9,"secret_version_id":1,"accessed_by":"bob","action":"secret.read","access_time":"2026-01-02T00:00:00Z"}],"total":1}}`))
	setPATCreds(t, srv)
	secretAccessLogID = 1
	defer func() { secretAccessLogID = 0 }()

	out := captureStdout(t, func() {
		if err := secretAccessLogCmd.RunE(secretAccessLogCmd, nil); err != nil {
			t.Fatalf("secretAccessLogCmd: %v", err)
		}
	})
	if !containsAll(out, "bob", "secret.read", "2026-01-02") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// TestSecretAccessLog_ShowsIPWhenServerIncludesIt confirms the audit.read-holder
// case (ip_address present) still renders correctly.
func TestSecretAccessLog_ShowsIPWhenServerIncludesIt(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/access-log",
		`{"data":{"access_log":[{"id":9,"secret_version_id":1,"accessed_by":"bob","action":"secret.read","access_time":"2026-01-02T00:00:00Z","ip_address":"203.0.113.5","user_agent":"curl/8.0"}],"total":1}}`))
	setPATCreds(t, srv)
	secretAccessLogID = 1
	defer func() { secretAccessLogID = 0 }()

	out := captureStdout(t, func() {
		if err := secretAccessLogCmd.RunE(secretAccessLogCmd, nil); err != nil {
			t.Fatalf("secretAccessLogCmd: %v", err)
		}
	})
	if !containsAll(out, "bob", "secret.read", "203.0.113.5") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── schedule ────────────────────────────────────────────────────────────────────

func TestSecretSetSchedule_RejectsInvalidDay(t *testing.T) {
	if _, err := convertSecretDayNames("notaday"); err == nil {
		t.Fatal("expected an error for an invalid day name")
	}
}

func TestSecretSetSchedule_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodPut, "/api/v1/secrets/1/schedule",
		`{"data":{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}}`))
	setPATCreds(t, srv)
	secretSchedDays, secretSchedStartHour, secretSchedEndHour, secretSchedTimezone = "mon,tue,wed,thu,fri", 9, 17, "UTC"
	defer func() { secretSchedDays = "" }()

	out := captureStdout(t, func() {
		if err := secretSetScheduleCmd.RunE(secretSetScheduleCmd, []string{"1"}); err != nil {
			t.Fatalf("secretSetScheduleCmd: %v", err)
		}
	})
	if !containsAll(out, "Schedule set", "1,2,3,4,5", "09:00-17:00", "UTC") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── suspend / resume / trash / restore ──────────────────────────────────────────

func TestSecretSuspend_RequiresID(t *testing.T) {
	secretSuspendID = 0
	if err := secretSuspendCmd.RunE(secretSuspendCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

// SUSPEND-PURGE-1: --clear-synced-copies puts clear_synced_copies:true in the request and
// tells the person to rotate; without the flag the body has no such member and the output
// does not mention synced copies.
func TestSecretSuspend_ClearSyncedCopiesFlag(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flag        bool
		wantInBody  bool
		wantInPrint []string
		notInPrint  string
	}{
		{"flag set", true, true, []string{"suspended", "cleared on their next sync", "secret rotate"}, ""},
		{"flag unset", false, false, []string{"suspended"}, "synced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody string
			srv := secretOpsServer(t, secretOpsRoute{http.MethodPost, "/api/v1/secrets/7/suspend", func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"data":{}}`)
			}})
			setPATCreds(t, srv)
			secretSuspendID, secretSuspendReason, secretSuspendClearCopies = 7, "leaked", tc.flag
			defer func() { secretSuspendID, secretSuspendReason, secretSuspendClearCopies = 0, "", false }()

			out := captureStdout(t, func() {
				if err := secretSuspendCmd.RunE(secretSuspendCmd, nil); err != nil {
					t.Fatalf("secretSuspendCmd: %v", err)
				}
			})
			if has := strings.Contains(gotBody, `"clear_synced_copies":true`); has != tc.wantInBody {
				t.Fatalf("request body %q: clear_synced_copies present=%v, want %v", gotBody, has, tc.wantInBody)
			}
			if !strings.Contains(gotBody, `"reason":"leaked"`) {
				t.Fatalf("the reason must still be sent: %q", gotBody)
			}
			if !containsAll(out, tc.wantInPrint...) {
				t.Fatalf("output missing %v, got: %q", tc.wantInPrint, out)
			}
			if tc.notInPrint != "" && strings.Contains(out, tc.notInPrint) {
				t.Fatalf("output must not mention %q, got: %q", tc.notInPrint, out)
			}
		})
	}
}

func TestSecretTrash_RequiresProject(t *testing.T) {
	secretTrashProject = 0
	if err := secretTrashCmd.RunE(secretTrashCmd, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestSecretTrash_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/projects/1/secrets/deleted",
		`{"data":{"deleted":[{"id":4,"name":"old-key","type":"generic","classification":"","deleted_at":"2026-01-02T00:00:00Z"}]}}`))
	setPATCreds(t, srv)
	secretTrashProject = 1
	defer func() { secretTrashProject = 0 }()

	out := captureStdout(t, func() {
		if err := secretTrashCmd.RunE(secretTrashCmd, nil); err != nil {
			t.Fatalf("secretTrashCmd: %v", err)
		}
	})
	if !containsAll(out, "4", "old-key", "generic") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// RETENTION-1: the trash listing prints the server's real purge date per row, and "-" (not
// a guessed one) for a row from a server that predates the field.
func TestSecretTrash_PrintsPurgeDate(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/projects/1/secrets/deleted",
		`{"data":{"deleted":[`+
			`{"id":4,"name":"old-key","type":"generic","deleted_at":"2026-01-02T00:00:00Z","purge_at":"2026-02-01T00:00:00Z"},`+
			`{"id":5,"name":"legacy","type":"generic","deleted_at":"2026-01-03T00:00:00Z"}]}}`))
	setPATCreds(t, srv)
	secretTrashProject = 1
	defer func() { secretTrashProject = 0 }()

	out := captureStdout(t, func() {
		if err := secretTrashCmd.RunE(secretTrashCmd, nil); err != nil {
			t.Fatalf("secretTrashCmd: %v", err)
		}
	})
	if !containsAll(out, "PURGE AFTER (UTC)", "2026-02-01T00:00:00Z") {
		t.Fatalf("trash output missing the purge column / date: %q", out)
	}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "legacy") && !strings.HasSuffix(strings.TrimSpace(line), "-") {
			t.Fatalf("a row without purge_at must show '-', got %q", line)
		}
	}
}

// ── templates ───────────────────────────────────────────────────────────────────

func TestSecretTemplateCreate_RequiresName(t *testing.T) {
	secretTmplName = ""
	if err := secretTemplateCreateCmd.RunE(secretTemplateCreateCmd, nil); err == nil {
		t.Fatal("expected an error when --name is omitted")
	}
}

func TestSecretTemplateList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secret-templates",
		`{"data":{"templates":[{"id":2,"name":"db-cred","description":"Standard DB credential"}]}}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretTemplateListCmd.RunE(secretTemplateListCmd, nil); err != nil {
			t.Fatalf("secretTemplateListCmd: %v", err)
		}
	})
	if !containsAll(out, "db-cred", "Standard DB credential") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── metadata: tags / description / classify / info ──────────────────────────────

func TestSecretTags_RequiresID(t *testing.T) {
	secretTagsID = 0
	if err := secretTagsCmd.RunE(secretTagsCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretTags_ListEmptyPrintsNoTags(t *testing.T) {
	srv := secretOpsServer(t, secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/tags", `{"data":{"tags":[]}}`))
	setPATCreds(t, srv)
	secretTagsID = 1
	defer func() { secretTagsID = 0 }()

	out := captureStdout(t, func() {
		if err := secretTagsCmd.RunE(secretTagsCmd, nil); err != nil {
			t.Fatalf("secretTagsCmd: %v", err)
		}
	})
	if !containsAll(out, "(no tags)") {
		t.Fatalf("output missing the empty-state message, got: %q", out)
	}
}

func TestSecretClassify_RejectsInvalidLevel(t *testing.T) {
	secretClassifyID, secretClassifyLevel = 1, "not-a-level"
	defer func() { secretClassifyID, secretClassifyLevel = 0, "" }()
	if err := secretClassifyCmd.RunE(secretClassifyCmd, nil); err == nil {
		t.Fatal("expected an error for an invalid --level")
	}
}

func TestSecretInfo_RequiresID(t *testing.T) {
	secretInfoID = 0
	if err := secretInfoCmd.RunE(secretInfoCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretInfo_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		secretJSONRoute(http.MethodGet, "/api/v1/secrets/1", `{"data":{"id":1,"name":"db-pass","type":"generic","status":"active","classification":"confidential","owner_id":9,"created_by":"alice"}}`),
		secretJSONRoute(http.MethodGet, "/api/v1/secrets/1/tags", `{"data":{"tags":["prod","db"]}}`),
	)
	setPATCreds(t, srv)
	secretInfoID = 1
	defer func() { secretInfoID = 0 }()

	out := captureStdout(t, func() {
		if err := secretInfoCmd.RunE(secretInfoCmd, nil); err != nil {
			t.Fatalf("secretInfoCmd: %v", err)
		}
	})
	if !containsAll(out, "Secret 1: db-pass", "confidential", "user #9", "alice", "prod, db") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── PR 5 (bulk / rotation / export / import / hygiene) ──────────────────────

// ── required-flag validation ─────────────────────────────────────────────────

func TestRunSecretRotationSimulate_RequiresID(t *testing.T) {
	rotationSimulateID = 0
	if err := runSecretRotationSimulate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretAutoRotate_RequiresID(t *testing.T) {
	autoRotateID = 0
	if err := runSecretAutoRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretAutoRotate_RejectsUnknownCharset(t *testing.T) {
	autoRotateID = 1
	autoRotateCharset = "not-a-real-charset"
	defer func() { autoRotateID, autoRotateCharset = 0, "" }()
	if err := runSecretAutoRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error for an unknown --charset value")
	}
}

func TestRunSecretAutoRotate_RequiresBackendAndRefTogether(t *testing.T) {
	autoRotateID = 1
	autoRotateBackend = "vault"
	autoRotateRef = ""
	defer func() { autoRotateID, autoRotateBackend = 0, "" }()
	if err := runSecretAutoRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --backend is set without --ref")
	}
}

func TestRunSecretBulkRotate_RequiresProject(t *testing.T) {
	bulkRotateProject = 0
	bulkRotateConfirm = true
	defer func() { bulkRotateConfirm = false }()
	if err := runSecretBulkRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretBulkRotate_RequiresConfirm(t *testing.T) {
	bulkRotateProject = 1
	bulkRotateConfirm = false
	defer func() { bulkRotateProject = 0 }()
	if err := runSecretBulkRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --confirm is omitted")
	}
}

func TestRunSecretBulkRename_RequiresProject(t *testing.T) {
	bulkRenameProject = 0
	bulkRenamePairs = []string{"1=NEW_NAME"}
	defer func() { bulkRenamePairs = nil }()
	if err := runSecretBulkRename(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretBulkRename_RequiresAtLeastOneRename(t *testing.T) {
	bulkRenameProject = 1
	bulkRenamePairs = nil
	defer func() { bulkRenameProject = 0 }()
	if err := runSecretBulkRename(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when no --rename is given")
	}
}

func TestParseSecretRenamePairs_RejectsMalformedPair(t *testing.T) {
	if _, err := parseSecretRenamePairs([]string{"not-a-valid-pair"}); err == nil {
		t.Fatal("expected an error for a pair missing '='")
	}
	if _, err := parseSecretRenamePairs([]string{"abc=NEW_NAME"}); err == nil {
		t.Fatal("expected an error for a non-numeric ID")
	}
	if _, err := parseSecretRenamePairs([]string{"1="}); err == nil {
		t.Fatal("expected an error for an empty new name")
	}
}

func TestRunSecretBulkDelete_RequiresIDsOrNames(t *testing.T) {
	bulkDeleteIDs, bulkDeleteNames = nil, nil
	if err := runSecretBulkDelete(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when neither --ids nor --names is given")
	}
}

func TestRunSecretBulkDelete_NamesRequireProjectAndEnv(t *testing.T) {
	bulkDeleteIDs = nil
	bulkDeleteNames = []string{"s1"}
	bulkDeleteProject, bulkDeleteEnv = 0, 0
	defer func() { bulkDeleteNames = nil }()
	if err := runSecretBulkDelete(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --names is used without --project/--env")
	}
}

func TestRunSecretExpiring_RequiresProject(t *testing.T) {
	expiringProject = 0
	if err := runSecretExpiring(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretOrphaned_RequiresProject(t *testing.T) {
	orphanedProject = 0
	if err := runSecretOrphaned(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretOwnershipHistory_RequiresID(t *testing.T) {
	ownershipHistoryID = 0
	if err := runSecretOwnershipHistory(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretReassignOwner_RequiresAllFlags(t *testing.T) {
	reassignProject, reassignFrom, reassignTo = 0, 0, 0
	if err := runSecretReassignOwner(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project/--from/--to are omitted")
	}
}

func TestRunSecretScore_RequiresID(t *testing.T) {
	scoreID = 0
	if err := runSecretScore(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretAudit_RequiresID(t *testing.T) {
	auditID = 0
	if err := runSecretAudit(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretBlastRadius_RejectsNonNumericArg(t *testing.T) {
	if err := runSecretBlastRadius(&cobra.Command{}, []string{"not-a-number"}); err == nil {
		t.Fatal("expected an error for a non-numeric secret ID argument")
	}
}

func TestRunSecretCert_RejectsNonNumericArg(t *testing.T) {
	if err := runSecretCert(&cobra.Command{}, []string{"not-a-number"}); err == nil {
		t.Fatal("expected an error for a non-numeric secret ID argument")
	}
}

func TestRunSecretRender_RequiresProject(t *testing.T) {
	renderProject = 0
	if err := runSecretRender(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretExport_RequiresProjectAndEnv(t *testing.T) {
	exportProject, exportEnv = 0, 0
	if err := runSecretExport(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project/--env are omitted")
	}
}

func TestRunSecretImport_RequiresFile(t *testing.T) {
	importFile = ""
	if err := runSecretImport(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --file is omitted")
	}
}

func TestRunSecretScan_RejectsInvalidSeverity(t *testing.T) {
	scanSeverity = "not-a-real-severity"
	defer func() { scanSeverity = "" }()
	if err := runSecretScan(&cobra.Command{}, []string{t.TempDir()}); err == nil {
		t.Fatal("expected an error for an invalid --severity value")
	}
}

// ── golden-output / decode-correctness tests ─────────────────────────────────

func TestRunSecretExpiring_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"expiring":[{"id":7,"name":"db-pass","type":"generic","environment_id":3,"expiration":"2026-12-01T00:00:00Z","expired":false}],"total":1,"truncated":false}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	expiringProject = 1
	defer func() { expiringProject = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretExpiring(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretExpiring: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "TYPE", "STATE", "EXPIRES", "7", "db-pass", "generic", "expiring") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretQuotaReport_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secrets":[{"secret_id":3,"secret_name":"api-key","read_count":9,"max_reads":10,"usage_pct":90,"status":"warning"}]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretQuotaReport(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretQuotaReport: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "READ_COUNT", "MAX_READS", "USAGE%", "STATUS", "3", "api-key", "9", "10", "90%", "warning") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretScore_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secret_id":5,"secret_name":"db-pass","score":42,"band":"medium","factors":[{"key":"rotation","label":"Rotation age","score":10,"weight":0.3,"detail":"90 days"}],"degraded":false}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	scoreID = 5
	defer func() { scoreID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretScore(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretScore: %v", err)
		}
	})
	if !containsAll(out, "db-pass", "42/100", "MEDIUM", "rotation", "90 days") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretBlastRadius_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"source_secret_id":1,"source_secret_name":"root-cert","dependents":[{"secret_id":2,"secret_name":"leaf-cert","project_id":1,"owner_id":1,"depth":1,"risk_level":"high"}],"total_impact":1,"max_depth":1,"truncated":false}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretBlastRadius(&cobra.Command{}, []string{"1"}); err != nil {
			t.Fatalf("runSecretBlastRadius: %v", err)
		}
	})
	if !containsAll(out, "root-cert", "leaf-cert", "depth 1", "high") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretCert_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secret_id":1,"secret_name":"tls-cert","subject":"CN=example.com","issuer":"CN=example.com","serial_number":"01","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","days_until_expiry":90,"is_expired":false,"is_ca":false,"self_signed":true,"signature_algorithm":"SHA256-RSA","public_key_algorithm":"RSA"}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretCert(&cobra.Command{}, []string{"1"}); err != nil {
			t.Fatalf("runSecretCert: %v", err)
		}
	})
	if !containsAll(out, "tls-cert", "CN=example.com", "self-signed", "90 days left") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretNameConformance_OrgWide_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"policy_enabled":true,"total_secrets":2,"violations":[{"project_id":1,"project_name":"web","id":9,"name":"bad name","type":"generic","reason":"contains space"}]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	nameConformanceProject = 0

	out := captureStdout(t, func() {
		if err := runSecretNameConformance(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretNameConformance: %v", err)
		}
	})
	if !containsAll(out, "PROJECT", "web", "bad name", "contains space") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretReassignOwner_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"reassigned":3}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	reassignProject, reassignFrom, reassignTo = 1, 2, 3
	defer func() { reassignProject, reassignFrom, reassignTo = 0, 0, 0 }()

	out := captureStdout(t, func() {
		if err := runSecretReassignOwner(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretReassignOwner: %v", err)
		}
	})
	if !containsAll(out, "Reassigned 3 secret(s)", "user 2", "user 3") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretBulkRotate_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"triggered":[1,2],"failed":[{"secret_id":3,"name":"skip-me","error":"no auto-rotate configured"}],"total":3}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	bulkRotateProject, bulkRotateConfirm = 1, true
	defer func() { bulkRotateProject, bulkRotateConfirm = 0, false }()

	out := captureStdout(t, func() {
		if err := runSecretBulkRotate(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretBulkRotate: %v", err)
		}
	})
	if !containsAll(out, "2 scheduled", "1 failed", "skip-me", "no auto-rotate configured") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretBulkDelete_PreviewWithoutConfirm(t *testing.T) {
	bulkDeleteIDs = []int{1, 2, 3}
	bulkDeleteNames = nil
	bulkDeleteConfirm = false
	defer func() { bulkDeleteIDs, bulkDeleteConfirm = nil, false }()

	out := captureStdout(t, func() {
		if err := runSecretBulkDelete(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretBulkDelete: %v", err)
		}
	})
	if !containsAll(out, "Would delete 3 secret(s)", "1, 2, 3", "Pass --confirm") {
		t.Fatalf("output missing expected preview text, got: %q", out)
	}
}
