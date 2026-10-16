### Documentation
- **Broken links and stale file references in `docs/`.** `docs/README.md` no longer links the missing `DEPLOYMENT_GUIDE.md` (now `SELF_HOSTING.md`) and `COMPREHENSIVE_TEST_RESULTS.md`, and its API anchor works; `DAST.md` and `security/architecture.md` name the files that exist now.

### Internal
- **`scripts/check-doc-links.py`**: a manual check for broken relative links, missing heading anchors and (with `--refs`) backticked repo paths that no longer exist in `docs/`. Not wired into CI.
