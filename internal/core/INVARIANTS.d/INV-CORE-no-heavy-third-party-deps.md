- **INV-CORE-no-heavy-third-party-deps** `internal/core`'s production dependency closure
  (`go list -deps ./internal/core`, default build tags) contains no package under a registered
  heavy third-party prefix. Registered so far: `github.com/spf13/` (cobra, pflag) and
  `gopkg.in/yaml.v3`; each further decoupling cut registers its own prefixes. The only heavy
  library still allowed is `gorm.io/gorm` (`models` needs it; ask `core-decouple-gorm-models-split`).
  A library core does not use still reaches every package that imports core when some package core
  imports pulls it in: cobra came in through `internal/securefiles` (an unused `FilePermsCmd`),
  yaml.v3 through `internal/secrettemplate` (`EscapeYAMLString`/`RenderYAML`, now
  `internal/secrettemplate/yamlescape`, a leaf that imports `secrettemplate` and never the reverse).
  A change that needs one of the forbidden libraries puts it in a leaf package core does not import.
  Why: CORE-DECOUPLE-PLAN-1 (5.6 MB and 4 packages out of a 157.5 MB, 345-package closure);
  ADR-109 and INV-CORE-40 only cover `internal/*` integration packages.
  Guard: `internal/core/ports/heavy_deps_guard_test.go` (`TestCoreStaysLeanOfHeavyThirdParty`, which
  names the importing keyorix package and the import chain; `TestStillAllowedHeavy`, which keeps
  the allowed list exact; `TestForbiddenViolations_SelfTest`, red and green on a synthetic graph),
  with the prefixes registered one file per cut (`heavy_deps_lean_test.go` for this cut).
  Not covered: test-only imports (the core test binary links whatever any `_test.go` imports), a
  new heavy library that nobody has registered (the guard forbids by name; it cannot tell that an
  unlisted library is heavy), and build-tagged variants other than the default tags.
