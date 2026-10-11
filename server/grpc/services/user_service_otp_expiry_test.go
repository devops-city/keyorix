package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/server/proto/pb"
)

// OTP-EXPIRY-1: CreateUser with generate_one_time_password reports when the
// one-time password expires, next to the password itself.
func TestCreateUser_OneTimePassword_ReportsExpiry(t *testing.T) {
	svc := newUserService(t)
	before := time.Now()
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username:                "otp_expiry_grpc",
		Email:                   "otp_expiry_grpc@example.com",
		GenerateOneTimePassword: true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetOneTimePassword())
	require.NotEmpty(t, resp.GetOneTimePasswordExpiresAt())

	exp, err := time.Parse(time.RFC3339, resp.GetOneTimePasswordExpiresAt())
	require.NoError(t, err)
	assert.Equal(t, time.UTC, exp.Location())
	assert.WithinDuration(t, before.Add(72*time.Hour), exp, time.Minute, "default one-time-password lifetime is 72h")
}
