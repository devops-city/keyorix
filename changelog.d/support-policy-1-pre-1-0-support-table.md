### Documentation

- **Pre-1.0 security support is now stated by severity.** `SECURITY.md` has a table: every severity is fixed on the current minor, and Critical and High are also backported to the previous minor for a stated window (the later of the next-but-one minor, or 30 days after the immediate successor). Medium and Low on the previous minor need an upgrade. `SUPPORT.md` points to it, and ADR-104 records the decision in a dated amendment that supersedes its "latest release only" scoping.
