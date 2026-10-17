### Testing
- **Upgrade drill.** `scripts/drills/upgrade.sh` seeds an old release (users with MFA, secrets with versions, a share, a machine token, audit history), swaps in the build under test and checks that data, logins, tokens and `admin verify-audit` survive, on SQLite and PostgreSQL. Runbook: `docs/operator/drill-upgrade.md`.
