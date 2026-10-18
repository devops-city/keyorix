### Fixed

- Revoking or creating a share no longer answers 500 when the follow-up "access revoked/shared" notification panics after the change has already committed. The panic is now recovered and logged at `SECURITY: WARN`, and the committed result is reported as success (#3350).
- `scripts/check-closures.sh` prints each closure row's own verdict even when another test in the same package fails (a failing package used to hide the `ok` line of every healthy row sharing it), and `scripts/gen-security-closures-tsv.sh` now also refuses a fragment whose embedded newline is followed by `#` text.

### Removed

- The unused `RevertAccessReviewItemClaim` storage method (no caller, and no campaign-is-open condition) is deleted (#2803).
