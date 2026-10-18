# Project soft-delete and restore: what happens to each child

`DELETE /api/v1/projects/{id}` (`keyorix project delete`, gRPC `ProjectService.DeleteProject`)
soft-deletes a project. `POST /api/v1/projects/{id}/restore` brings it back until the retention
window ends. After that, the purge job (`PurgeDeletedProjectsBefore`) hard-deletes the project
and its children. The table below lists, for every kind of row that belongs to a project, what
each of the three steps does to it.

The delete is one transaction (`core.DeleteProject`: `deleteProjectCascade`, then the
machine-identity step). The restore is also one transaction (`core.RestoreProject`: the
machine-identity step, then `LocalStorage.RestoreProject`). The only work done after commit is
revoking dynamic-secret leases against their external targets.

| Child | On soft-delete | On restore | On purge | Guard |
|-------|----------------|------------|----------|-------|
| Project row | `deleted_at` set (row-locked first, INV-STORE-21) | `deleted_at` cleared | hard-deleted | `concurrency_restore_project_vs_delete_postgres_test.go` |
| Secrets (and folders) | soft-deleted with the project's `deleted_at`; purge date frozen | only those with that `deleted_at` come back; secrets deleted earlier stay in the recycle bin | hard-deleted with versions, dependencies, ACLs | `restore_test.go`, `local_secrets_cascade_sweep_test.go` |
| Environments | soft-deleted with the same `deleted_at` | the same matching rule | hard-deleted | `restore_test.go` |
| Shares (`share_records`) | revoked | **not** restored ("delete means gone", #370) | removed | `local_sharing_test.go` |
| Secret ACL grants | deleted (#2798) | **not** restored | n/a | `local_lifecycle_cascade_test.go` |
| Approved secret-scoped access requests | moved to `expired` (#2797) | **not** re-opened | normal resolved-request retention | `local_lifecycle_cascade_test.go` |
| User and group role grants at the project | kept, they stop applying while the project is deleted | apply again, but only if the restoring admin could grant every admin-tier role among them (#161) | hard-deleted | `restore_admin_ceiling_test.go` |
| Machine-identity role grants at the project | kept, they stop applying | apply again | hard-deleted (#2795) | `TestPurgeDeletedProjectsBefore_RemovesMachineIdentityRoles` |
| **Machine identities** (#3433) | an **active** identity whose only live roles are in this project (home project or a role there; no role at global scope or in another live project) is **suspended**. Its tokens and OIDC logins stop on every replica: the auth cache re-reads the identity state on each hit. One `machine_identity.suspended` audit event per identity, actor = the deleting admin, reason "project soft-delete". Identities with a live role elsewhere keep working. | exactly the identities this delete suspended come back to `active`, and only those nothing has written since; one `machine_identity.activated` event each, reason "project restore". An identity an admin suspended, or acted on during the deletion window, stays as the admin left it. | the identities are not purged; they stay suspended | `project_delete_machine_suspend_test.go`, `dead_credentials_walk_test.go` (`machine_token_project_deleted`) |
| Dynamic-secret configs | disabled; active leases revoked against their targets after commit (#369) | **not** re-enabled: an admin re-enables each config explicitly | n/a | `TestDeleteProject_RealStorage_DisablesDynamicSecretConfigsAndRevokesLeases` |

Invariants: `internal/storage/store/INVARIANTS.d/INV-STORE-project-child-liveness.md` (no child
becomes live under a deleted project) and
`INV-STORE-project-delete-suspends-machine-identities.md`.
