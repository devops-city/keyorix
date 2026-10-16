### Added
- **`-o/--output table|json|yaml` on the CLI's report commands.** `secret list`, `secret versions`, `project stats`, `project health`, `usage show` and `billing report` now take the same `--output` flag, and `yaml` is new. A mistyped format is refused up front, naming the choices (`usage show` and `billing report` used to fall back to the table silently).

### Deprecated
- **`--format` on those six commands** keeps working as a hidden alias of `--output` and prints a deprecation notice on stderr. `project stats` and `project health` now print indented JSON instead of one compact line (same content).
