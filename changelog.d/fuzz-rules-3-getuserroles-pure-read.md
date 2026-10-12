### Testing
- **Fuzz oracle (d) pure-read rule covers `GetUserRoles` (#3106).** REST `POST /auth/webauthn/login/finish` `GetUserRoles#1/effect-then-error` ends in the same reviewed state as its error kind, exactly as #3091 did for `GetUserPermissions`. The row opts in, the seed is committed, and the per-row guard drives both fault kinds and requires the same response and state.
