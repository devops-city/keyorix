package cmd

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// secretFileMatrix is the shared secret-file trust table. It lives in the main
// module (internal/secretenv/testdata) and is read as a file, not imported:
// this module must not depend on the main one (ADR-108 Decision A).
const secretFileMatrix = "../../internal/secretenv/testdata/permission-matrix.tsv"

// TestLookupSecretEnv_PermissionMatrix runs this module's copy of the
// secret-file rule (checkSecretFileMode, through lookupSecretEnv) over the
// table internal/secretenv and server/entrypoint.sh are held to. The copy had
// drifted: it never got the #3393 owner rule, so a 0600 file owned by an
// unrelated account (which can rewrite it) was trusted for KEYORIX_TOKEN_FILE,
// KEYORIX_PASSWORD_FILE and the rest (SECRETENV-REVIEW-1).
func TestLookupSecretEnv_PermissionMatrix(t *testing.T) {
	f, err := os.Open(secretFileMatrix)
	if err != nil {
		t.Fatalf("the shared matrix must be readable from a repo checkout: %v", err)
	}
	defer func() { _ = f.Close() }()

	const name = "KEYORIX_TEST_CLI_SECRETFILE"
	const fileGID = 5555
	rows := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != 6 {
			t.Fatalf("malformed matrix row %q", line)
		}
		mode64, err := strconv.ParseUint(c[0], 8, 32)
		if err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		mode := os.FileMode(mode64)
		process, owner, group, verdict, why := c[1], c[2], c[3], c[4], c[5]
		rows++
		t.Run(c[0]+"/"+process+"/"+owner+"/"+group, func(t *testing.T) {
			euid := 4000
			if process == "root" {
				euid = 0
			}
			fileUID := map[string]int{"self": euid, "root": 0, "other": 4242}[owner]
			oldUID, oldGroups, oldOwner := secretFileProcessUID, secretFileProcessGroups, secretFileOwner
			t.Cleanup(func() { secretFileProcessUID, secretFileProcessGroups, secretFileOwner = oldUID, oldGroups, oldOwner })
			secretFileProcessUID = func() int { return euid }
			secretFileProcessGroups = func() []int {
				if group == "held" {
					return []int{fileGID}
				}
				return []int{fileGID + 1}
			}
			secretFileOwner = func(os.FileInfo) (int, int, bool) { return fileUID, fileGID, true }

			p := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(p, []byte("TOPSECRET\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			t.Setenv(name, "")
			t.Setenv(name+"_FILE", p)
			_, _, err := lookupSecretEnv(name)
			switch {
			case verdict == "accept" && err != nil:
				t.Fatalf("must accept (%s), got %v", why, err)
			case verdict == "refuse" && err == nil:
				t.Fatalf("must refuse (%s), was accepted", why)
			case err != nil && strings.Contains(err.Error(), "TOPSECRET"):
				t.Fatalf("error carries the file contents: %v", err)
			}
		})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if rows == 0 {
		t.Fatal("the shared matrix has no rows")
	}
}
