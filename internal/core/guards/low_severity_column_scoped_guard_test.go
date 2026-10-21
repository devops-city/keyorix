package guards

import "testing"

// TestLowSeverityWrites_AreColumnScoped is the default-ci half of #2700, so the
// fix is guarded in the DSN-less CI leg too (the four
// TestCTAReview_*_CrossReplicaPostgres tests are the behavioural proof and need
// real Postgres).
//
// All three full-row primitives are DELETED here, unlike #2695/#2698 where one
// caller each belonged to another open PR — so this guard does not need a
// "no remaining caller" sweep: the methods are simply gone from
// storage.Storage, and re-adding one would not compile against any caller. They
// are still named as forbidden below, because re-adding one is the likeliest way
// this regresses and a guard that goes red is better than a build error
// somewhere unrelated.
//
// Hops checked, one per entry point:
//
//	core.UpdateRotationPolicy          -> c.storage.UpdateRotationPolicyFields
//	core.UpdateSecretTemplate          -> c.storage.UpdateSecretTemplateFields
//	markWebAuthnCredentialClonedDisabled -> c.storage.DisableWebAuthnCredential
//
//	AdvanceWebAuthnCredentialCounter  -> tx.SetWebAuthnCredentialCounterState
//
// That last one was previously declared out of reach, on the grounds that it
// lives in internal/storage/store and "these core-scoped helpers cannot reach
// it". That was wrong, and wrong in the direction that leaves a gap: what was
// core-scoped was the WRAPPER's hardcoded "KeyorixCore" receiver type, not the
// AST walk underneath it, which has always taken an arbitrary path and receiver
// type. #2836 added assertStorageWritesOnlyVia and the site is now covered like
// every other. #2700 still classes it SAFE on its own merits (it holds
// SELECT ... FOR UPDATE on the row inside the same transaction) — the guard is
// about keeping the model free of any full-row writer, not about that site being
// unsafe.
func TestLowSeverityWrites_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_rotation_policies.go", "UpdateRotationPolicyFields")
	assertColumnScopedStorageWrite(t, "../../storage/store/local_secret_templates.go", "UpdateSecretTemplateFields")
	assertColumnScopedStorageWrite(t, "../../storage/store/local_webauthn.go", "DisableWebAuthnCredential")
	assertColumnScopedStorageWrite(t, "../../storage/store/local_webauthn.go", "SetWebAuthnCredentialCounterState")

	assertCoreWritesOnlyVia(t, "../rotation_policies.go", "UpdateRotationPolicy", "tx", // AUDIT-TX-3: written through the audited transaction
		"UpdateRotationPolicyFields", "Save", "UpdateRotationPolicy")
	assertCoreWritesOnlyVia(t, "../secret_templates.go", "UpdateSecretTemplate", "storage",
		"UpdateSecretTemplateFields", "Save", "UpdateSecretTemplate")
	assertCoreWritesOnlyVia(t, "../webauthn.go", "markWebAuthnCredentialClonedDisabled", "storage",
		"DisableWebAuthnCredential", "Save", "UpdateWebAuthnCredential")
	assertStorageWritesOnlyVia(t, "../../storage/store/local_webauthn.go", "AdvanceWebAuthnCredentialCounter", "tx",
		"SetWebAuthnCredentialCounterState", "Save", "UpdateWebAuthnCredential")
}
