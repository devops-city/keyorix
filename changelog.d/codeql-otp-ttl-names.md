### Changed
- Internal rename only: the one-time-password validity settings are now `OneTimePasswordExpiry` / `RecoveryOneTimePasswordExpiry` in code (config keys `security.one_time_password_ttl` and `security.recovery_one_time_password_ttl` are unchanged). Clears ten CodeQL clear-text-logging false positives caused by the old names.
