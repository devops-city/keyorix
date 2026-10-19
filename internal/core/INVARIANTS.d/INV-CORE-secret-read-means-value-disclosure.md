- **INV-CORE-secret-read-means-value-disclosure** A `secret.read` audit event (and an
  access-log row of action `read`) is written only when a secret's value is disclosed.
  Two metadata-only paths have their own events, so they never count as reads:
  (1) listing a secret's version history (HTTP `GET /secrets/{id}/versions`, gRPC
  `GetSecretVersions`; `SecretVersion.EncryptedValue` is `json:"-"`) is audited as
  `secret.versions_listed` with access-log action `versions_list`, through the atomic,
  audit-before-response writer (`LogSecretVersionsListed` → `emitAuditWithAccessLog`);
  (2) the by-name lookup (HTTP `GET /secrets/by-name`, `SecretHandler.GetSecretByName`)
  returns metadata only and is audited as `secret.metadata_read` with access-log action
  `metadata_read` (`LogSecretMetadataRead`, same writer; the handler keeps it
  fire-and-forget as before, there being no value to gate). Read counts, billing/usage
  reads, read summaries, `total_reads` and the dashboard's "accessed" all key on
  `secret.read` / action `read`, so neither ever counts as a read; anomaly detection reads
  every access-log action, so it still sees who listed versions or resolved a name from
  where. Every remaining `LogSecretReadWithProject` call site is a value disclosure and
  must be checked and synchronous (`secretReadAuditCallSiteAllowlist` is empty). Why:
  AUDIT-UX-2 (#2951 follow-up): `keyorix secret delete` previews the version count and so
  wrote a `secret.read` for the secret it was deleting; AUDIT-UX-3: by-name lookups
  inflated reads, billing and `total_reads` the same way. Guard: `server/http`
  `TestCLISecretDeleteFlow_WritesNoSecretRead` and `TestGetSecretByName_AuditsMetadataReadNotRead`
  (against the real router), `server/grpc/services`
  `TestSecretService_GetSecretVersions_AuditsListingNotRead`, `internal/core/guards`
  `TestSecretReadAuditCallSites_CheckedAndNotInGoSafe`.
