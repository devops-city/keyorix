- **INV-CORE-transfer-reowns-shares** A secret's `ShareRecord.OwnerID` is always the
  secret's current `OwnerID`. `transferOwnership` (the one primitive behind
  `TransferSecretOwnership` and `ReassignOwnedSecrets`, INV-CORE-07) writes the secret's
  owner and calls `Storage.ReassignSecretShareOwner` inside ONE `WithTransaction`, so the
  two cannot be observed apart: the owner-scoped lists (`ListSharesByOwner`, behind
  `GET /api/v1/shares/owned`, gRPC `ListUserShares`) key on `ShareRecord.OwnerID` while
  revoke/update gate on owning the SECRET (`requireShareAuthority`). Every row of the
  secret is re-stamped (live, expired-unswept and soft-deleted), only `owner_id` is
  written (recipients, permissions, expiry, `deleted_at` untouched, so no access is
  granted or removed and a revoked share is not resurrected), and the one
  `secret.owner_transferred` audit event carries `shares_reassigned`. The sibling writer
  `LocalStorage.CreateShareRecord` re-reads the secret's owner AFTER its parent
  `FOR SHARE` lock and rolls back if it no longer equals `share.OwnerID`, so a share
  authorised by the previous owner cannot commit with the previous owner's stamp after
  a transfer. Why: #3102 (found in the #3018 review). Guard:
  `TestTransferSecretOwnership_ReownsShares` (SQLite + Postgres, list/update/revoke by
  both owners, recipient grants unchanged, revoked/expired rows re-stamped, audit count),
  `TestShareService_TransferOwnership_ReownsShares` (gRPC),
  `TestTransferOwnership_ReownsSharesOverREST`, and the two-pool Postgres tests
  `TestCTAReview_TransferOwnership_vs_RevokeShare_CrossReplicaPostgres`,
  `..._RevokeBlockedBehindRestamp_CrossReplicaPostgres`,
  `TestCTAReview_ShareSecret_vs_TransferOwnership_CrossReplicaPostgres`. **Not covered**:
  no static guard forbids a future writer of `share_records.owner_id` outside these two
  (it is only the INSERT in `createShareRecordTx`, stamped from the secret's owner, and
  `ReassignSecretShareOwner`); `ShareView.createdBy` now names the CURRENT owner, not the
  original sharer (the original is in the `share_created` audit event).
