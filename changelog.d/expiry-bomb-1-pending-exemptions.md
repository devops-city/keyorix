### Security
- **Expired pending exemptions resolved; guards warn 3 days ahead.** The #2671/#2673 exemption rows (landed in #2785) no longer carry expiry dates, and `TestChildParentLiveness_PendingRowsNotExpired` / `TestFullRowWriteGuard_PendingRowsNotExpired` log a `WARNING` for rows expiring within 3 days while still failing hard once expired.
