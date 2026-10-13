### Fixed
- **The web footer no longer requests `GET /api/v1/system/info` while the session is MFA-pending.** The footer's system-info query now runs only for a fully authenticated session that owes no setup step, so an enrolment-confined session fires no refused request (restores `web-e2e-real-smoke` shard 1/2 on main). The server-side confinement is unchanged.
