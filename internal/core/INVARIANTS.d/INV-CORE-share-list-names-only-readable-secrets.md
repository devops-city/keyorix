- **INV-CORE-share-list-names-only-readable-secrets** The share lists
  (`ListUserShareViews`, `ListOwnedShareViews`) set a view's `SecretName`, `ProjectID` and
  `ProjectName` (`share_view_secret_names.go`, `annotateShareViewSecrets`) only for a secret
  the caller passes `AuthorizeSecret(secrets.read)` on (ACL, role, share, PAT restriction),
  checked per distinct secret. A secret that fails the check, no longer resolves, or whose
  check errors keeps `SecretID` only; a storage error resolving the secrets leaves every name
  out. The share lists themselves are not narrowed by the PAT on `GET /api/v1/shares`, so
  the name is the one thing this check withholds there. Why: #3153 (the Sharing page showed
  "Secret #2"); naming the secret must not disclose names the caller cannot read. Guard:
  `server/http/share_view_secret_names_test.go:TestShareList_DoesNotNameSecretsTheCallerCannotRead`
  (PAT confined to P / to payments / without secrets.read; mutating the check to name
  everything goes red), `TestOwnedShares_NameTheSecretAndProject`,
  `TestGlobalShareList_NamesTheSecret`. All default-ci.
