package http

// secret_certificate_refusal_test.go — FIX-3175B (follow-up to ERRMAP-1, #3175).
//
// GET /secrets/{id}/certificate runs the same read-guard bundle as a value read but
// charges no max-reads budget, so it is outside the derived value-read family
// (TestValueReadRouteFamily_IsCovered). It still must map the refusals the same way:
// schedule 403 SecretAccessOutsideSchedule, expired / suspended 409, with the fixed
// messages, and show the state only to a caller who may read the secret. Driven
// through the real router, so the route gate is in front. The handler-level
// "outsider past the gate" case is in handlers/secret_read_refusal_outsider_test.go.
//
// Session principal only: the handler inspects as a user (a machine principal has no
// user id there), which is unchanged by this follow-up.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

func refusalCertPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "refusal.example.com"},
		NotBefore: notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSecretCertificateRefusals_MapLikeValueReads(t *testing.T) {
	w := buildRefusalFamilyWorld(t)
	ctx := t.Context()
	pemValue := refusalCertPEM(t)

	// Max-reads is deliberately absent: inspecting public metadata is not a value read.
	var cases []refusalCase
	for _, rc := range refusalCases() {
		if rc.sentinel != core.ErrSecretMaxReadsExhausted {
			cases = append(cases, rc)
		}
	}
	require.Len(t, cases, 3)

	inspect := func(token string, id uint) valueReadOutcome {
		return restValueRead(w, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/certificate", id), token, nil,
			func(map[string]json.RawMessage) string { return "ok" })
	}

	for i, rc := range cases {
		t.Run(rc.name, func(t *testing.T) {
			sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
				Name: fmt.Sprintf("certrefused%d", i), Value: []byte(pemValue),
				ProjectID: w.projID, EnvironmentID: w.envID,
				Type: "certificate", CreatedBy: "guardadmin", OwnerID: w.adminID,
			})
			require.NoError(t, err)

			before := inspect(w.tokens["session"], sec.ID)
			require.Truef(t, before.ok, "precondition: the unrefused certificate must be inspectable (got %+v)", before)
			outsiderBefore := map[string]valueReadOutcome{}
			for _, o := range []string{"outsider-session", "outsider-machine"} {
				outsiderBefore[o] = inspect(w.tokens[o], sec.ID)
				require.Falsef(t, outsiderBefore[o].ok, "precondition: %s must not inspect the certificate", o)
			}

			rc.apply(t, w, sec)
			audit0, access0 := refusalRowCounts(t, w, sec.ID)

			got := inspect(w.tokens["session"], sec.ID)
			assert.False(t, got.ok, "the refused inspection succeeded")
			assert.Equal(t, rc.restStatus, got.restCode, "HTTP status (body: %s)", got.restBody)
			assert.Equal(t, rc.code, got.errCode, "stable error code (body: %s)", got.restBody)
			assert.Equal(t, rc.message, got.errMsg, "fixed client-safe message (body: %s)", got.restBody)

			audit1, access1 := refusalRowCounts(t, w, sec.ID)
			assert.Equal(t, audit0, audit1, "a refused inspection must not add audit rows")
			assert.Equal(t, access0, access1, "a refused inspection must not add access-log rows")

			for _, o := range []string{"outsider-session", "outsider-machine"} {
				after := inspect(w.tokens[o], sec.ID)
				assert.Equalf(t, outsiderBefore[o], after, "%s: the refusal changed what an unauthorized caller sees", o)
				assert.NotEqualf(t, http.StatusConflict, after.restCode, "%s got a secret-state answer", o)
			}
		})
	}
}
