package secretenv

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// permissionMatrixRow is one line of testdata/permission-matrix.tsv.
type permissionMatrixRow struct {
	mode                          os.FileMode
	process, owner, group, reason string
	accept                        bool
}

func (r permissionMatrixRow) name() string {
	return "0" + strconv.FormatUint(uint64(r.mode), 8) + "/" + r.process + "/" + r.owner + "/" + r.group
}

func readPermissionMatrix(t *testing.T, path string) []permissionMatrixRow {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- repo test data
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var rows []permissionMatrixRow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		require.Len(t, c, 6, "malformed matrix row %q", line)
		mode, err := strconv.ParseUint(c[0], 8, 32)
		require.NoError(t, err, "row %q", line)
		require.Contains(t, []string{"user", "root"}, c[1], "row %q", line)
		require.Contains(t, []string{"self", "root", "other"}, c[2], "row %q", line)
		require.Contains(t, []string{"held", "not"}, c[3], "row %q", line)
		require.Contains(t, []string{"accept", "refuse"}, c[4], "row %q", line)
		rows = append(rows, permissionMatrixRow{os.FileMode(mode), c[1], c[2], c[3], c[5], c[4] == "accept"})
	}
	require.NoError(t, sc.Err())
	require.NotEmpty(t, rows)
	return rows
}

// matrixIdentity maps a row's names to the uids and gids the seams report.
func matrixIdentity(r permissionMatrixRow) (euid, fileUID int) {
	euid = 4000
	if r.process == "root" {
		euid = 0
	}
	switch r.owner {
	case "self":
		fileUID = euid
	case "root":
		fileUID = 0
	default:
		fileUID = 4242
	}
	return euid, fileUID
}

const matrixFileGID = 5555

// TestPermissionMatrix_Server is the reference implementation's run over the
// shared table. The CLI (cli/cmd) and the container entrypoint
// (server/entrypoint.sh) run the same table; a row they decide differently is
// a drift between the copies of the rule.
func TestPermissionMatrix_Server(t *testing.T) {
	for _, r := range readPermissionMatrix(t, "testdata/permission-matrix.tsv") {
		t.Run(r.name(), func(t *testing.T) {
			p := writeSecret(t, "TOPSECRET\n", r.mode)
			euid, fileUID := matrixIdentity(r)
			oldUID, oldGroups, oldOwner := processUID, processGroups, fileOwner
			t.Cleanup(func() { processUID, processGroups, fileOwner = oldUID, oldGroups, oldOwner })
			processUID = func() int { return euid }
			processGroups = func() []int {
				if r.group == "held" {
					return []int{matrixFileGID}
				}
				return []int{matrixFileGID + 1}
			}
			fileOwner = func(os.FileInfo) (int, int, bool) { return fileUID, matrixFileGID, true }

			t.Setenv(testVar, "")
			t.Setenv(testVar+FileSuffix, p)
			_, _, lerr := LookupChecked(testVar)
			cerr := CheckPermissions(p)
			if r.accept {
				require.NoError(t, lerr, "LookupChecked must accept (%s)", r.reason)
				require.NoError(t, cerr, "CheckPermissions must accept (%s)", r.reason)
			} else {
				require.Error(t, lerr, "LookupChecked must refuse (%s)", r.reason)
				require.Error(t, cerr, "CheckPermissions must refuse (%s)", r.reason)
				require.NotContains(t, lerr.Error(), "TOPSECRET")
			}
		})
	}
}
