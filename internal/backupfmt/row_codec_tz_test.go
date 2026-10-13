package backupfmt

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// FIX-3088: a row read from a database on a host whose time.Local is not UTC
// carries Local-located times. The zero time (0001-01-01 00:00:00 UTC) shown in
// such a zone gets the zone's local-mean-time offset (Europe/Berlin: +00:53:28),
// which RFC 3339 cannot represent exactly (minute resolution only), so a
// json.Marshal of that Local-located time does not decode back to the same
// instant. The codec must therefore write every time as UTC.

// withLocalTZ loads the zone name. It deliberately does NOT assign time.Local
// (a package global: writing it races with every goroutine that calls
// time.Now). The codec never reads time.Local; it is handed values already
// located in the host zone, which is exactly what a driver on such a host
// returns, so every input below is built with .In(loc) instead.
func withLocalTZ(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	require.NoError(t, err)
	return loc
}

var codecTZs = []string{"UTC", "Europe/Berlin", "America/Los_Angeles", "Asia/Kolkata", "Pacific/Auckland"}

func TestRowCodec_TimeRoundTripIsExactOnAnyHostTZ(t *testing.T) {
	instants := map[string]time.Time{
		"zero":          {},
		"unixEpoch":     time.Unix(0, 0),
		"year1Plus1s":   time.Date(1, 1, 1, 0, 0, 1, 0, time.UTC),
		"pre1900":       time.Date(1850, 6, 1, 12, 0, 0, 0, time.UTC),
		"modernMicros":  time.Date(2026, 10, 12, 13, 14, 15, 123456000, time.UTC),
		"dstEdgeBerlin": time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC),
	}
	for _, tz := range codecTZs {
		t.Run(tz, func(t *testing.T) {
			loc := withLocalTZ(t, tz)
			for name, inst := range instants {
				t.Run(name, func(t *testing.T) {
					// What a DB driver hands back on this host: the instant, Local-located.
					local := inst.In(loc)

					src := models.User{DeletedAt: gorm.DeletedAt{Time: local, Valid: true}}
					ev := models.AuditEvent{EventType: "x", EventTime: local}

					evBytes, err := marshalRow(&ev)
					require.NoError(t, err)
					var evBack models.AuditEvent
					require.NoError(t, unmarshalRow(evBytes, &evBack))
					require.True(t, evBack.EventTime.Equal(inst),
						"AuditEvent.EventTime %v decoded as %v (unixmicro %d vs %d)",
						local, evBack.EventTime, evBack.EventTime.UnixMicro(), inst.UnixMicro())

					userBytes, err := marshalRow(&src)
					require.NoError(t, err)
					var userBack models.User
					require.NoError(t, unmarshalRow(userBytes, &userBack))
					require.True(t, userBack.DeletedAt.Valid)
					require.True(t, userBack.DeletedAt.Time.Equal(inst),
						"DeletedAt %v decoded as %v", local, userBack.DeletedAt.Time)
				})
			}
		})
	}
}

// The encoding itself must not depend on the host zone: the same instant
// encodes to the same bytes whatever time.Local is. This is what keeps the
// per-table manifest hash (writer.go) stable across hosts.
func TestRowCodec_EncodingIsHostTZIndependent(t *testing.T) {
	inst := time.Date(2026, 10, 12, 13, 14, 15, 0, time.UTC)
	var want []byte
	for _, tz := range codecTZs {
		loc := withLocalTZ(t, tz)
		for _, ts := range []time.Time{inst.In(loc), (time.Time{}).In(loc)} {
			b, err := marshalRow(&models.AuditEvent{EventTime: ts})
			require.NoError(t, err)
			if ts.Equal(inst) {
				if want == nil {
					want = b
				}
				require.JSONEq(t, string(want), string(b), "tz %s", tz)
			}
		}
	}
}

// Pointer and sql.NullTime shapes are normalised too, not just time.Time.
func TestRowCodec_NormalisesPointerAndNullTimeShapes(t *testing.T) {
	loc := withLocalTZ(t, "Europe/Berlin")
	type shapes struct {
		P *time.Time
		N sql.NullTime
		T time.Time
	}
	z := time.Time{}.In(loc)
	in := shapes{P: &z, N: sql.NullTime{Time: z, Valid: true}, T: z}
	b, err := marshalRow(&in)
	require.NoError(t, err)
	var out shapes
	require.NoError(t, unmarshalRow(b, &out))
	require.True(t, out.P.Equal(time.Time{}))
	require.True(t, out.N.Time.Equal(time.Time{}))
	require.True(t, out.T.Equal(time.Time{}))
}
