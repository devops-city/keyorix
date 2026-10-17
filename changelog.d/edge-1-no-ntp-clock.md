### Added
- **Clock warnings for devices without a time source.** The server now logs, on every start, when the system clock reads earlier than the binary's build date (an unset or reset clock) and when a configured TLS certificate is expired, not valid yet on this clock, or within 30 days of expiry; while running, it logs when the wall clock steps by 30 s or more, saying that a backward step makes the server refuse secret value reads and second-factor logins until the clock catches up or the service restarts. None of these stop the server from starting.

### Changed
- **`admin init` refuses to generate a TLS certificate on an implausible clock.** A certificate stamped from a clock that was never set (the epoch, for example) would be expired as soon as the clock was corrected and, with TLS required, would take the server with it. The error says to set the clock or supply your own certificate and key.

### Testing
- **Clock-skew tests for the edge.** Injected-clock tests pin how TOTP, the second-factor challenge guard, secret value reads, sessions, PATs and leases behave across forward and backward clock steps (including the limits an operator must know about), and an audit-chain test pins that timestamps going backwards do not affect verification while a rewritten timestamp still does.

### Documentation
- **Edge guide: no-NTP behaviour.** New §5a in `docs/edge-deployment.md`: what each kind of clock error does and the operator rule (set the clock before the service starts; restart it after stepping the clock backward).
