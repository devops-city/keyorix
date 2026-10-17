### Added
- **`--help` shows a runnable example on every CLI command.** Each leaf command now has an `Examples` section; `cli/cmd/help_examples_test.go` fails when a command has none, when an example uses a flag the command no longer has, or when an example puts a secret on the command line.
