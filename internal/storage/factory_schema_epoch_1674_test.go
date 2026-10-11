// factory_schema_epoch_1674_test.go — #1674 regression guard.
//
// #1674's investigation and its recorded decision (docs/adr-101-schema-epoch-
// compatibility-floor.md) explicitly keep checkSchemaEpoch's refusal
// unconditional -- no grace window, no retry, no N+1 tolerance -- while making
// the refusal self-diagnosing (report the recorded-at timestamp and both
// plausible causes, in plain language, rather than deciding between them).
//
// These two tests exist so that a future "helpful" patch adding one of the
// rejected options (a time-based grace window, a bounded tolerance, an
// in-process retry loop) cannot land silently: the first proves the refusal is
// still unconditional, the second proves the diagnostic content survives.
package storage

import (
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckSchemaEpoch_1674_StillRefusesUnconditionally proves the refusal is
// NOT made conditional on how recently the newer epoch was recorded -- a
// grace-window patch that let a JUST-recorded newer epoch through would make
// this test fail (the row here is written and read back within the same
// test, i.e. as recent as it is possible to be).
func TestCheckSchemaEpoch_1674_StillRefusesUnconditionally(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-1674-unconditional.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: strconv.Itoa(currentSchemaEpoch + 1)}).Error)

	err = checkSchemaEpoch(db)
	require.Error(t, err, "checkSchemaEpoch must refuse a newer recorded epoch regardless of how recently it was written -- a grace window would let this pass")
}

// TestCheckSchemaEpoch_1674_ErrorCarriesAllFourDiagnosticElements asserts the
// refusal's error text names: the database's recorded epoch, this binary's
// compiled-in epoch, when the newer epoch was recorded, and both plausible
// causes (rolling-upgrade self-resolving vs. genuine downgrade) in plain
// operator language -- not just that it refuses, which
// TestSchemaEpoch_NewerRecordedEpoch_RefusesToStart (factory_schema_epoch_test.go)
// already covers.
func TestCheckSchemaEpoch_1674_ErrorCarriesAllFourDiagnosticElements(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-1674-diagnostic.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))

	before := time.Now()
	require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: "7"}).Error)

	err = checkSchemaEpoch(db)
	require.Error(t, err)
	msg := err.Error()

	// (1) the database's recorded epoch. (2) this binary's compiled-in epoch.
	// Anchored to the surrounding words, not bare digits -- a bare "1" or "7"
	// would trivially match inside the RFC3339 timestamp asserted below too.
	assert.Contains(t, msg, "schema epoch 7", "error must name the database's recorded epoch")
	assert.Contains(t, msg, fmt.Sprintf("schema epoch %d ", currentSchemaEpoch), "error must name this binary's compiled-in epoch")
	// (3) when the newer epoch was recorded -- an RFC3339 timestamp AND a
	// relative age ("... ago"), not just a bare number.
	assert.Contains(t, msg, before.Format("2006-01-02"), "error must name the date the newer epoch was recorded")
	assert.Contains(t, msg, "ago", "error must state how long ago the newer epoch was recorded")
	// (4) both plausible causes, in plain language -- a rolling upgrade
	// (self-resolving) and a genuine downgrade (needs operator action) -- and
	// an explicit statement that this process cannot tell them apart.
	assert.Contains(t, msg, "rolling upgrade", "error must name the rolling-upgrade cause")
	assert.Contains(t, msg, "self-resolving", "error must state the rolling-upgrade case is self-resolving")
	assert.Contains(t, msg, "downgraded", "error must name the downgrade cause")
	assert.Contains(t, msg, "restore a backup", "error must state the downgrade remediation")
	assert.Contains(t, msg, "cannot tell them apart", "error must be explicit that this process cannot distinguish the two causes")
}
