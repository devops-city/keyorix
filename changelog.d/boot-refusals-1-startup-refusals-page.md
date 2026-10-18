### Documentation
- **Start-up refusals page.** `docs/operator/startup-refusals.md` lists what an operator sees when `keyorix-server` refuses to start or an `admin` command stops (configuration, TLS, key and secret files, schema epoch and rollback, locks, single_writer, backup/restore): the message, the cause, the fix, and whether the fix is safe in place. Linked from the troubleshooting page, SELF_HOSTING and UPGRADING. `docs/operator/startup-refusals-inventory.md` records how the list was built and what the search could not see. The troubleshooting page's "known gap" about a server that fails to bind its port staying alive is corrected: it exits with status 1.

### Testing
- **Refusal docs guard.** `internal/refusaldocs` fails when a message text documented on the start-up refusals page no longer exists in the Go sources, and logs (does not fail) the refusals in the boot path that the page does not cover yet.
