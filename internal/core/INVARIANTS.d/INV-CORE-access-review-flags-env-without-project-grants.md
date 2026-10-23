- **INV-CORE-access-review-flags-env-without-project-grants** A project's access review
  (`GenerateProjectAccessReview`, and the campaign snapshot taken from it) never reads as
  complete while a user or group grant at `{project_id: 0, environment_id: X}` exists for an
  environment X of that project: such a grant applies inside X but is not among the review's
  entries (`ListProjectRoleAssignments(P)` does not return it), so the report is `degraded`
  with one reason per grant naming it and the fix (re-create with the project_id, then
  remove), and a failed lookup degrades it too. The same grants, of every project, are named
  at startup (`server/wire_global_project_roles.go`). Rows are reported, never changed (no
  destructive migration; new ones are refused by INV-CORE-role-grant-scope-valid-for-role).
  Why: ROLE-SHAPE-1 (#2857 follow-up; ISO 27001 A.5.18 under-report). Guard:
  `env_without_project_grants_test.go` (`TestGenerateProjectAccessReview_FlagsEnvironmentWithoutProjectGrant`,
  `TestListEnvironmentWithoutProjectGrants_ReportsLegacyRowsWithTheirProject`),
  `server/http` `TestProjectAccessReviewHTTP_NamesEnvironmentWithoutProjectGrantUntilFixed`,
  `server` `TestWireGlobalProjectRoleGrantsNotice_LogsEnvironmentWithoutProjectGrants`.
  **Not covered**: machine-identity grants (the shape was never writable for them:
  `requireEnvironmentInProject`); the web UI and CLI access-review views do not display
  `degraded_reasons` of the review itself (the API response and the campaign row carry them).
