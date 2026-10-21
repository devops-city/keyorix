### Documentation
- **Pilot operator runbooks.** New `docs/operator/audit-chain-break-runbook.md` (what the online and
  offline verifiers report, benign causes, tampering versus truncation, evidence to keep, and that no
  re-seal command exists), `lost-totp-runbook.md` (recovery paths per account type, with the gap for
  a non-admin without a recovery code) and `key-rotation-runbook.md` (preflight, verification,
  rollback, what not to do, the audit-checkpoint key change after `rotate-kek`). Linked from the
  docs index next to the break-glass runbook.
