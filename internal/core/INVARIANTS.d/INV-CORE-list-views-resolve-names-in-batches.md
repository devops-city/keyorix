- **INV-CORE-list-views-resolve-names-in-batches** A list view (secrets list, audit log and
  search, shares list) resolves usernames, group and machine-identity names, share records,
  shared secrets, ACL-granted secrets and tags with one batched storage call per kind
  (`GetUsernamesByIDs`, `GetGroupNamesByIDs`, `GetMachineIdentityNamesByIDs`,
  `GetSecretTagsBySecretIDs`, `GetSecretsByIDs`, `ListSharesBySecretIDs`), never one call per row,
  so the statements a request issues do not grow with the rows on the page. The batch lookups select
  only the id and the display column and skip soft-deleted rows, as the single-row getters do.
  Why: LIST-ENDPOINTS-1 — a 1000-secret list issued ~1180 statements, an audit page one per actor.
  Guard: `server/http/list_endpoints_query_count_test.go` `TestListSecrets_QueryCountDoesNotGrowWithRows`,
  `TestAuditLogs_QueryCountDoesNotGrowWithActors`.
  **Not covered**: `annotateShareViewSecrets` still runs `AuthorizeSecret` once per share's secret
  (the shares list stays per-row until authorization has a batch form); `collectFolderDescendants`
  lists children per folder of an ACL grant.
