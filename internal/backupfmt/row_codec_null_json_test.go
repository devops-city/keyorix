package backupfmt

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MIGRATE-VERIFY-1: a SQL NULL in a models.JSON column is written to the archive
// as JSON null. models.JSON.UnmarshalJSON keeps the four bytes "null" as a
// non-nil value, so every restored row came back with the TEXT 'null' where the
// source had NULL -- found by comparing every table of a SQLite source against
// its PostgreSQL restore (secret_nodes.metadata). The restore codec must give a
// JSON null back as the field's zero value.
func TestRowCodec_NullJSONColumnRestoresAsNull(t *testing.T) {
	in := models.SecretNode{Name: "n", Metadata: nil}
	data, err := marshalRow(&in)
	require.NoError(t, err)

	var out models.SecretNode
	require.NoError(t, unmarshalRow(data, &out))
	require.Nil(t, out.Metadata, "a NULL metadata column must restore as NULL, not the text 'null'")
}

// A reused destination struct must not keep the previous row's value when the
// next row has NULL there.
func TestRowCodec_NullJSONColumnClearsReusedDestination(t *testing.T) {
	withMeta, err := marshalRow(&models.SecretNode{Name: "a", Metadata: models.JSON(`{"k":"v"}`)})
	require.NoError(t, err)
	withoutMeta, err := marshalRow(&models.SecretNode{Name: "b", Metadata: nil})
	require.NoError(t, err)

	var out models.SecretNode
	require.NoError(t, unmarshalRow(withMeta, &out))
	require.JSONEq(t, `{"k":"v"}`, string(out.Metadata))
	require.NoError(t, unmarshalRow(withoutMeta, &out))
	require.Nil(t, out.Metadata)
}

// Real JSON values survive untouched.
func TestRowCodec_NonNullJSONColumnRoundTrips(t *testing.T) {
	in := models.SecretNode{Name: "n", Metadata: models.JSON(`{"owner":"payments","tier":2}`)}
	data, err := marshalRow(&in)
	require.NoError(t, err)
	var out models.SecretNode
	require.NoError(t, unmarshalRow(data, &out))
	require.JSONEq(t, `{"owner":"payments","tier":2}`, string(out.Metadata))
}
