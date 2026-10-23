### Security
- **Dev-tooling alert fixes.** The web test toolchain moves to vitest 4.1.12 (fixes the `@vitest/mocker` advisories, development scope only). `scripts/metrics/surfacewalk startup` now refuses a probe URL whose host is not loopback, because its readiness probe skips certificate verification.
