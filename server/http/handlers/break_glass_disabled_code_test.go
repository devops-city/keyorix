// break_glass_disabled_code_test.go — the "break-glass is disabled" refusal carries a
// typed error code (BreakGlassDisabled) so a client switches on the code, not on the
// message. The status (403), the message and the position in the order of checks are
// unchanged. Not t.Parallel(): the locale test flips the process-global localizer.
package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bgErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func activateBG(t *testing.T, enabled bool, projectID string) (int, bgErrorBody) {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	cs.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: enabled, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour,
	})
	w := doActivateBreakGlass(t, NewCatalogHandler(cs), projectID, `{"justification":"prod incident, db is down"}`)
	var body bgErrorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
	return w.Code, body
}

func TestActivateBreakGlass_DisabledCarriesTypedCode(t *testing.T) {
	code, body := activateBG(t, false, "1")
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "BreakGlassDisabled", body.Error)
	assert.Equal(t, core.BreakGlassDisabledCode, body.Error)
	assert.Equal(t, http.StatusForbidden, body.Code)
	// The message is unchanged (still says what to turn on).
	assert.Contains(t, body.Message, "break-glass is not enabled")
}

// The order of checks is unchanged: user 1 holds only a global grant (not a member of
// project 1) and a project that does not exist is just as unknown, yet while the feature
// is off both get the disabled answer, exactly as before this code existed -- the code
// reveals nothing new. With the feature on, the same two callers get the plain,
// code-less refusal / validation answers.
func TestActivateBreakGlass_DisabledCodeKeepsOrderOfChecks(t *testing.T) {
	for _, pid := range []string{"1", "987654"} {
		code, body := activateBG(t, false, pid)
		assert.Equal(t, http.StatusForbidden, code, pid)
		assert.Equal(t, "BreakGlassDisabled", body.Error, pid)
	}
	// Enabled: a non-member is refused with the generic code, never BreakGlassDisabled.
	code, body := activateBG(t, true, "1")
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "Error", body.Error)
	assert.NotEqual(t, core.BreakGlassDisabledCode, body.Error)
	// Enabled: invalid input is still the plain 400.
	code, body = activateBG(t, true, "0")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.NotEqual(t, core.BreakGlassDisabledCode, body.Error)
}

// The code does not depend on the deployment's language.
func TestActivateBreakGlass_DisabledCodeIsLocaleIndependent(t *testing.T) {
	withTranslatedErrorMessages(t)
	code, body := activateBG(t, false, "1")
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "BreakGlassDisabled", body.Error)
}
