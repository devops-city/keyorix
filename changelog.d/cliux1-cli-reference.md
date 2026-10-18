### Added
- **A generated CLI reference and man page.** `docs/cli-reference.md` (every command, flag, default and example) and `docs/man/keyorix.1` are produced from the command tree by the new `keyorix docs markdown` and `keyorix docs man`, so they cannot drift from `--help`; a test fails when they are stale (`make -C cli docs` regenerates them). `keyorix docs man | man -l -` reads the page without installing it.
- **Shell completion is tested.** `keyorix completion bash|zsh|fish|powershell` (already provided by cobra) now has tests that the scripts load in the shell and that completion offers this CLI's commands and flags; install steps are in the reference under `keyorix completion`.

### Changed
- `keyorix`'s one-line description is now "Command-line client for the Keyorix secrets manager" (it was "Keyorix CLI -- see ADR-108").
