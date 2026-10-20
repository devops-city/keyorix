- **INV-CORE-notifier-recipients-declared-and-include-install-admins** Every function in
  `internal/core` that emits a notification declares its recipient set in
  `notifierRegistry`, and every "tell the project's admins" notifier resolves that audience
  through `projectAdminRecipients` — approver-role project members PLUS active install-wide
  admins (direct or group-inherited), each once — never `ListProjectMembers` directly. A
  project-scoped read matches `user_roles.project_id` exactly, so it silently skips the
  install's global admin, who has admin authority on every project but no project-scoped
  row (#2955: break-glass alerts reached nobody on a fresh install). Deactivated or deleted
  install-wide admins are dropped so no subject detail (secret names, anomaly text) reaches
  an account that is off. Why: #2955, NOTIFY-1. Guard: `guards/notify_recipients_guard_test.go`
  (`TestNotifierRecipients_EveryEmitterDeclaresItsRecipientSet`,
  `_DeclaredSetIsActuallyUsed`, `_NoDirectProjectMemberFanOut`, and the red-proof
  `_GuardCatchesPlantedProjectMemberOnlyNotifier`); per-notifier effect tests in
  `notify_global_admin_recipients_test.go`.
