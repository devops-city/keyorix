package storage

import "github.com/keyorixhq/keyorix/internal/storage/models"

// AllModels is the single source of truth for "every table this binary
// creates or migrates" -- consumed by migrateDatabase (via AutoMigrate,
// directly or through the generic bulk-migration loop) and by
// design-b3-backup-v2.md §3.2's backend-neutral backup/restore table walk,
// so the two can never independently drift the way the
// internal/storage/store test-fixture incident already showed a hand-picked
// AutoMigrate subset can (see that incident's own note in CLAUDE.md).
//
// This list is still hand-written -- migrateDatabase has no single slice to
// refactor into an export (it is ~90 individually and conditionally gated
// AutoMigrate calls, several deliberately excluded from bulk treatment for a
// documented pgx re-inspection-on-existing-table hazard) -- but per this
// repo's "derive it, or derive-and-check it" preference order, a hand-written
// list is acceptable exactly because TestAllModels_MatchesLiveMigratedTables
// (all_models_test.go) fails loudly, on every CI run, the day a model is
// added to migrateDatabase and forgotten here, or vice versa. That test is
// the mechanism this list's correctness actually rests on, not this comment.
func AllModels() []any {
	return []any{
		&models.AccessRequest{},
		&models.AccessRequestApproval{},
		&models.AccessReviewCampaign{},
		&models.AccessReviewItem{},
		&models.AlertEscalationPolicy{},
		&models.AnomalyAlert{},
		&models.AnomalyConfigRecord{},
		&models.APICallLog{},
		&models.APIClient{},
		&models.APIToken{},
		&models.AuditCheckpoint{},
		&models.AuditEvent{},
		&models.BreakGlassActivation{},
		&models.CompliancePostureSnapshot{},
		&models.ConnectorProjectBinding{},
		&models.ConnectRefGrant{},
		&models.DeploymentStatsSnapshot{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.Environment{},
		&models.ExternalIdentity{},
		&models.Group{},
		&models.GroupRole{},
		&models.GRPCService{},
		&models.HygieneTrendSnapshot{},
		&models.IdentityProvider{},
		&models.LegalHold{},
		&models.LoginAttempt{},
		&models.MachineIdentity{},
		&models.MachineIdentityCredential{},
		&models.MachineIdentityOIDCBinding{},
		&models.MachineIdentityRole{},
		&models.MFAChallenge{},
		&models.MFARecoveryCode{},
		&models.MFASecret{},
		&models.MFAStepUpGrant{},
		&models.MFAStepupToken{},
		&models.Notification{},
		&models.NotificationChannel{},
		&models.PasswordHistory{},
		&models.PasswordReset{},
		&models.Permission{},
		&models.PendingAuditEvent{},
		&models.PersonalAccessToken{},
		&models.Project{},
		&models.ProjectInvitation{},
		&models.ProjectMembership{},
		&models.RateLimit{},
		&models.RecoveryKeyRecord{},
		&models.RejectionReasonTemplate{},
		&models.RiskException{},
		&models.Role{},
		&models.RolePermission{},
		&models.RotationPolicy{},
		&models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SecretAccessSchedule{},
		&models.SecretACL{},
		&models.SecretDependency{},
		&models.SecretMetadataHistory{},
		&models.SecretNode{},
		&models.SecretTag{},
		&models.SecretTemplate{},
		&models.SecretVersion{},
		&models.SecretVersionComment{},
		&models.Session{},
		&models.Setting{},
		&models.SetupToken{},
		&models.ShareRecord{},
		&models.SoDPolicy{},
		&models.SSOLoginState{},
		&models.StatsSnapshot{},
		&models.SystemMetadata{},
		&models.Tag{},
		&models.User{},
		&models.UserGroup{},
		&models.UserRole{},
		&models.WebAuthnCredential{},
		&models.WebAuthnSession{},
	}
}
