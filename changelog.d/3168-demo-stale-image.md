### Fixed
- **`scripts/demo/up.sh` no longer reuses a stale demo image.** The `keyorix-demo:airgap` image is
  labelled with a fingerprint of the source it was built from (HEAD commit, plus a hash of any
  uncommitted changes); a run reuses it only when that matches the checkout, and otherwise says so
  ("image is stale: built from X, this checkout is Y") and rebuilds, instead of starting an old
  server that dies with `unknown flag: --dev`. New `--no-build` fails fast with the fix when the
  image is missing or stale. A rebuild is refused while another container runs from the same tag
  (set `KEYORIX_DEMO_IMAGE` on a shared host), and a startup failure on a mismatched image names
  the mismatch. (#3149)
- **`scripts/demo/down.sh --wipe` refuses the default-named volume** (`keyorix-demo-data`) unless
  `--force-default` is also given, and always prints exactly what it will remove first, so a wipe
  without your `KEYORIX_DEMO_*` overrides can no longer delete another session's demo. (#3149)
