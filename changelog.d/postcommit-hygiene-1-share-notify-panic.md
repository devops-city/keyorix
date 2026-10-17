### Fixed

- Revoking or creating a share no longer answers 500 when the follow-up "access revoked/shared" notification panics after the change has already committed. The panic is now recovered and logged at `SECURITY: WARN`, and the committed result is reported as success (#3350).
