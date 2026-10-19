- **INV-CORE-activated-mfa-secret-never-replaced-by-enrolment** An activated TOTP secret is
  never replaced by enrolment. `BeginMFAEnrollment`'s MFAEnabled check reads a row that can be
  stale by the time it writes, so the guarantee lives in the write itself:
  `LocalStorage.UpsertMFASecret` is one conditional upsert (`ON CONFLICT (user_id) DO UPDATE
  ... WHERE mfa_secrets.activated` is false) that replaces only a PENDING row, and an
  activated row yields `storage.ErrMFASecretActivated` with nothing written, which
  `BeginMFAEnrollment` returns as `ErrMFAAlreadyEnabled` without handing out the seed it
  generated. The reverse interleaving is INV-CORE-43 (activation only binds the secret its
  code was validated against). Second layer: only an activated secret is a second factor;
  `loadTOTPSecret`, the single seed read behind login, re-auth and step-up verification,
  refuses a pending row. Why: #2692 (the late upsert overwrote the activated row with a fresh
  seed returned to the enroller, and verification did not read `Activated`). Guard:
  `TestCTAReview_BeginMFAEnrollment_vs_ActivateMFA_CrossReplicaPostgres` (pg-gated),
  `TestBeginMFAEnrollment_DoesNotReplaceActivatedSecret`,
  `TestMFAVerifiers_PendingSecretIsNotASecondFactor`, store
  `TestUpsertMFASecret_NeverReplacesActivatedSecret` (SQLite + Postgres), and
  `TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels`, which no longer exempts
  `UpsertMFASecret` (an `OnConflict{UpdateAll}` there would fail it).
