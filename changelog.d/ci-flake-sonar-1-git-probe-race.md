### Fixed
- **The SonarCloud analysis no longer fails intermittently with `NoSuchFileException: .git/.probe-<uuid>`.** The scanner's JGit timestamp probe (a transient file in `.git`) raced SonarPython's unfiltered walk of the project directory; the workflow now makes `.git` read-only for the duration of the scan so JGit does not probe. Analysis scope, coverage and blame are unchanged.
