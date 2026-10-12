// share_transfer_reown_test.go — FIX-3102 over REST: after POST /secrets/{id}/transfer-ownership
// the secret's shares follow the secret. The previous owner stops LISTING them
// (GET /shares/owned) and is refused on PUT/DELETE /shares/{id}; the new owner lists
// them and may update and revoke them; the recipient's access does not change.
//
// Driven through the real router and real sessions (ownedShareFixture): olga owns
// "olga-p" in P and shared it with alice; wendy (secret_writer at P) is a write-tier
// project member, a valid transfer target.
package http

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransferOwnership_ReownsSharesOverREST(t *testing.T) {
	f := newOwnedShareFixture(t)
	secretID := mustShareSecretID(t, f, f.olgaShareP)
	sharePath := fmt.Sprintf("/api/v1/shares/%d", f.olgaShareP)
	secretPath := fmt.Sprintf("/api/v1/secrets/%d", secretID)

	// Baseline: olga lists both of her shares; wendy only her own; alice can read the secret.
	code, out, raw := f.owned(t, f.ownerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	require.Equal(t, []uint{f.olgaShareP, f.olgaSharePayments}, shareIDs(out.Data.Data), raw)
	aliceBefore, aliceRawBefore := doMachineRequest(t, f.d.srv, f.viewerTok, http.MethodGet, secretPath, nil)
	require.Equal(t, http.StatusOK, aliceBefore, aliceRawBefore)

	// --- the transfer, olga -> wendy ---
	code, raw = doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodPost, secretPath+"/transfer-ownership",
		[]byte(fmt.Sprintf(`{"new_owner_id":%d}`, f.ids["wendy"])))
	require.Equal(t, http.StatusOK, code, raw)

	// Lists: olga keeps only the share of the secret she still owns; wendy has both of hers.
	code, out, raw = f.owned(t, f.ownerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.olgaSharePayments}, shareIDs(out.Data.Data), "previous owner still lists the transferred secret's share: %s", raw)
	code, out, raw = f.owned(t, f.writerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.olgaShareP, f.wendyShareP}, shareIDs(out.Data.Data), "new owner must list the transferred secret's share: %s", raw)

	// The previous owner is refused on update and revoke, and nothing changes.
	code, raw = doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodPut, sharePath, []byte(`{"permission":"write"}`))
	assert.Equal(t, http.StatusForbidden, code, raw)
	code, raw = doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodDelete, sharePath, nil)
	assert.Equal(t, http.StatusForbidden, code, raw)
	code, out, raw = f.owned(t, f.writerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Contains(t, shareIDs(out.Data.Data), f.olgaShareP, "a refused revoke must not remove the share: %s", raw)

	// The recipient keeps exactly the access they had.
	aliceAfter, aliceRawAfter := doMachineRequest(t, f.d.srv, f.viewerTok, http.MethodGet, secretPath, nil)
	assert.Equal(t, aliceBefore, aliceAfter, aliceRawAfter)

	// The new owner may update, then revoke, and the share leaves their list.
	code, raw = doMachineRequest(t, f.d.srv, f.writerTok, http.MethodPut, sharePath, []byte(`{"permission":"write"}`))
	assert.Equal(t, http.StatusOK, code, raw)
	code, raw = doMachineRequest(t, f.d.srv, f.writerTok, http.MethodDelete, sharePath, nil)
	require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, code, raw)
	code, out, raw = f.owned(t, f.writerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.wendyShareP}, shareIDs(out.Data.Data), raw)
}
