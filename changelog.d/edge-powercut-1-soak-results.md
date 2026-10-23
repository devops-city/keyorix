### Documentation
- `docs/edge-deployment.md` §4 records the 2026-10-23 `kill -9` soak on SQLite (222 cycles, no lost acknowledged write, chain valid after every kill) and what it does not show: `kill -9` cannot distinguish `synchronous=NORMAL` from FULL, and a real power-cut run is still open.
