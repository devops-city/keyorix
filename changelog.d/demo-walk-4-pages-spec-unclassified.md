### Testing
- **`check.sh` no longer reports NOT READY on a healthy demo.** The real-backend Compliance spec hardcoded `0 / 3` for the "Unclassified secrets" tile; the seed has 13 secrets, so the pre-demo readiness check failed (and skipped the rest of the UI walk) on a correct install. It now asserts zero unclassified whatever the seed total is.
