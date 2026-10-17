### Fixed
- **Web e2e: the secrets CRUD smoke finds the environment tab again.** It matched the tab by its raw, lower-case name, but the page capitalises the label, so every test timed out on any PR that runs web e2e (regression from #3293). The test now matches the capitalised label exactly, without building a RegExp from runtime input. Test-only change (#3351).
