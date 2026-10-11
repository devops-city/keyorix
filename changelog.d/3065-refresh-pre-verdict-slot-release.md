### Security
- **A storage fault while looking up a session token no longer spends the per-IP
  login budget on `POST /auth/refresh`** (#2880). When the session lookup itself
  fails, no token was found or judged, so nothing was guessed and the request
  returns its slot instead of counting as a failed attempt (a client behind a
  flaky database could lock its own IP out of logging in). The refusal is the
  same 401 as before. Every fault after the token matched a live session (the
  owner read, the rotation, the reuse revocation) still keeps the slot, so a
  valid token is never cheaper than a wrong one; the rotation and owner-read
  cases are pinned by-design in the fault-injection oracle.
