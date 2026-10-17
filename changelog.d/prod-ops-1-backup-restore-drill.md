### Testing
- **Backup/restore drill.** `scripts/drills/backup-restore.sh` backs up a seeded instance, restores into a fresh SQLite directory or an empty PostgreSQL database, and checks decryption, MFA login, shares, machine tokens, `verify-audit` against an off-host anchor, the recovery point and the refusals (tampered archive, populated target, stale backup). Runbook: `docs/operator/drill-backup-restore.md`.

### Documentation
- **Backup/restore docs match the commands.** `admin restore --help` no longer says restoring into PostgreSQL is unsupported; `UPGRADING.md` §3 uses the real `--config` flags instead of `--output-db`/`--db`/`--target-dsn`; `SELF_HOSTING.md` §5 states the recovery point.
