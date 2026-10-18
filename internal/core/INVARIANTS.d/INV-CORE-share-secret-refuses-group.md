- **INV-CORE-share-secret-refuses-group** `ShareSecret` refuses `IsGroup: true`
  (`validateShareSecretRequest`, before any lookup or write). It has no group-scope check; a
  group recipient is shared only through `ShareSecretWithGroup`, whose `IsGroupProjectScoped`
  check is the one thing that keeps a group from another project out of a secret
  (`CheckGroupPermissions` checks membership only, never project affiliation). Why: #3422.
  Guard: `sharing_test.go` (`TestKeyorixCore_ShareSecret_RejectsGroupShare`); no caller passes
  a group: `server/http/share_secret_isgroup_guard_test.go` (`TestNoShareSecretCaller_PassesIsGroup`).
