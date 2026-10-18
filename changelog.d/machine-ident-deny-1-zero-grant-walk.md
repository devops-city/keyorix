### Security

- A credential with no role grant reads no tenant data on any REST GET route, now
  checked rather than assumed: a route walk over the live router (every GET route,
  every path parameter bound to canary objects, SQLite and Postgres) asserts it for a
  fresh machine identity, a user with every role removed and that user's PATs, and a
  machine identity whose only grant was just removed (cached token reused). No route
  leaked on main. A fresh machine identity listing projects gets 200 with an empty
  list (deliberate since #2780), not 403; the SDK contract suites that expect 403 are
  out of date (MACHINE-IDENT-DENY-1).
