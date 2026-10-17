// last_activity_inventory_test.go — RECERT-BOUND-1 item 1: every "last user
// activity" lookup on the Storage interface is listed here with the callers that
// need it. A new LastUser*Activity method fails this test until it is classified,
// so a new unbounded audit_events lookup cannot slip in unnoticed.
package store

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// lastActivityInventory maps each lookup to what its callers do with the result.
// All five are served by LocalStorage.lastUserActivityByEventTypes (one shared
// query on audit_events); RemoteStorage has no implementation of its own.
var lastActivityInventory = map[string]string{
	// access review (GenerateProjectAccessReview → annotateLastUsedAt): stamps each
	// user entry's LastUsedAt; the campaign snapshot copies it into its items, and
	// the campaign CSV export and the project access-review API/UI/CLI show it.
	"LastUserSecretActivity": "access review LastUsedAt (campaign items, CSV export, API/UI/CLI)",
	// compliance posture (countDormantRoleGrants): the dormant-role-grant count behind
	// the dashboard, the controls framework, the digest and the evidence export.
	"LastUserSecretReadActivity":     "dormant role grants, plain tier, secrets.read",
	"LastUserSecretWriteActivity":    "dormant role grants, plain tier, secrets.write",
	"LastUserRoleManagementActivity": "dormant role grants, admin tier, roles.assign",
	"LastUserSecretDeletionActivity": "dormant role grants, admin tier, secrets.delete",
}

func TestLastActivityInventory_CoversEveryStorageMethod(t *testing.T) {
	var found []string
	st := reflect.TypeFor[storage.Storage]()
	for i := range st.NumMethod() {
		name := st.Method(i).Name
		if strings.HasPrefix(name, "LastUser") && strings.HasSuffix(name, "Activity") {
			found = append(found, name)
		}
	}
	var listed []string
	for name := range lastActivityInventory {
		listed = append(listed, name)
	}
	sort.Strings(found)
	sort.Strings(listed)
	assert.Equal(t, listed, found,
		"a LastUser*Activity method was added or removed: classify it in lastActivityInventory (what its callers need) and bound it by the review period (docs/recertification-activity-window.md)")
}
