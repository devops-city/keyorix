# ADR-099: Master passphrase sourcing — fd, file, stdin, with env as fallback

## Status

**Accepted (2026-09-02).** Follow-up to the 2026-09 security review
(`docs/security-review-2026-09.md`), specifically its memory-zeroization
finding's second documented gap: "The master passphrase
(`KEYORIX_MASTER_PASSWORD`) is string-shaped from `os.Getenv` onward and,
like any Go string, structurally cannot be wiped at all." This ADR fixes the
*sourcing*, not the wiping — the passphrase still becomes a Go string at the
point `Service.Initialize`/`PasswordKeyProvider` consume it (see Scope below
for why that part is unchanged), but where it comes from no longer has to be
the process's own persistent environment.

## Summary

Both the server (`server/main.go`) and the CLI
(`internal/cli/main.go`/`internal/cli/common`/`internal/cli/encryption`) now
accept the master passphrase from three additional sources, in this order of
precedence, before falling back to `KEYORIX_MASTER_PASSWORD`:

1. **`--passphrase-fd <n>`** — read from an already-open file descriptor.
   The strongest option: the value never appears in argv, an environment
   variable, or a path this process opens by name. The usual answer for
   systemd's `LoadCredential=`: the unit's `ExecStart=` redirects the
   credential file to an inherited fd, e.g.
   `ExecStart=/bin/sh -c 'exec 3<"$CREDENTIALS_DIRECTORY/master-password"; exec /usr/bin/keyorix-server --passphrase-fd=3'`
   — the credential never touches a command-line argument or the process
   environment at any point.
2. **`--passphrase-file <path>`** — read from a file. Refused if the file is
   group- or world-readable (`mode & 0o077 != 0`), or owned by anyone but the
   running user or root (#3410: the owner can rewrite it); opened with `O_NOFOLLOW`
   so a symlink is refused rather than followed to an arbitrary target, and
   the permission check is done via `fstat` on the same fd used to read (not
   a separate `stat`-then-`open`), so there's no TOCTOU window for the file
   to be swapped between the check and the read.
3. **`--passphrase-stdin`** — read from stdin. No echo (via
   `golang.org/x/term`, matching every other secret-value prompt already in
   this CLI — `internal/cli/secret/create.go` and siblings) when stdin is an
   interactive terminal; a raw read until EOF when piped/redirected.
4. **`KEYORIX_MASTER_PASSWORD`** (env var) — unchanged, kept working, and
   documented as the weakest option (see below).

Implemented once in `internal/crypto.ResolvePassphrase`
(`internal/crypto/passphrase.go`). **Corrected 2026-09-07**: this section
previously named exactly three call sites, framing `internal/cli/encryption.
masterPassphrase` as *the* single chokepoint every command in that package
routes through. That undercounted even at the time — `migrate-provider` and
`rotate-kek` both call `ResolvePassphrase` directly, bypassing
`masterPassphrase`. All confirmed call sites wipe the resolved bytes
correctly regardless of which path they take, so this was a framing
inaccuracy, not a security gap — but a fixed count in prose goes stale the
next time a command is added. Don't re-derive a number here: run `grep -rn
"ResolvePassphrase(" internal/` for the current, authoritative call-site
list before relying on any claim about how many there are or which package
function is "the" chokepoint.

## Why the environment variable is the weakest option

An environment variable is a Go string from the moment `os.Getenv` returns
it — Go strings are immutable and cannot be wiped — and it persists in the
process's own environment block for the process's **entire lifetime**,
regardless of whether it's ever used again after startup. Anything that can
read `/proc/PID/environ` for that process (another process running as the
same user, a debugger, a core dump — see ADR-098) can read it at any point
during the process's life, not just at the moment it was consumed. It is
also the easiest to leak by accident: shell history (`export
KEYORIX_MASTER_PASSWORD=...` typed interactively), `ps -e -o command`
in some configurations, CI job logs that dump the environment for
debugging, or a child process that inherits the full parent environment
(see Corollary check below).

The three new sources avoid this by construction: each yields a `[]byte`
that the caller wipes (`crypto.WipeBytes`) once it has been consumed
(handed to `Service.Initialize`, which derives the KEK — see Scope), and
none of them ever touch the process's own persistent environment.

## Scope: what this closes and what it doesn't

This ADR closes the **sourcing** gap: where the raw bytes come from, and
whether they sit in a place that survives beyond their one legitimate use
(the environment does; a byte slice the caller wipes does not).

It does **not** close the **wiping** gap the security review documented
alongside it, and deliberately doesn't attempt to: `PasswordKeyProvider`
(`internal/crypto/password_provider.go`) holds the passphrase as a `string`
field for its own lifetime, because `KEK()` can legitimately be called more
than once on the same provider instance within a single process — at
`Initialize` time, and again later during `RotateDEKWithSweep` if a
key-rotation runs in the same still-live process
(`internal/encryption/keymanager_rotation.go`). Wiping the passphrase after
the *first* `KEK()` call would silently break the *second* one, turning a
security hardening step into a correctness bug (rotation would derive
against zeroed bytes and fail to unwrap the existing DEK). This was checked
directly by tracing every real caller of `deriveKEK`/`KEK()`, not assumed.

What this ADR *does* narrow: the window between "bytes read from their
source" and "handed to `Service.Initialize`, which converts them to the
`string` the existing provider API requires" is now wipeable — that raw
first-hop copy is a `[]byte` the caller (`initializeEncryption`,
`wireSecretEncryption`, `masterPassphrase`) explicitly zeroes via
`crypto.WipeBytes` immediately after conversion. Previously, with
`os.Getenv`, there was no such intermediate `[]byte` at all — the value was
a string from the very first read. Closing the deeper gap (threading
`[]byte`-only plaintext all the way through `PasswordKeyProvider` and
`Service.Initialize`, and abandoning string-based APIs there) is exactly
the "neither gap has a workable fix within this pass's scope" the review
already recorded, and stays out of scope here for the same reason.

## Corollary check: does the passphrase reach a child process, a log, or an error message?

Checked directly, not assumed:

- **Child process environment.** `internal/crypto/exec_provider.go`
  (`ExecKeyProvider`, used for the `exec` KMS provider) already builds an
  explicit minimal `cmd.Env` (`execAllowedEnv = []string{"PATH", "HOME"}`)
  instead of inheriting the full parent environment — its own comment names
  `KEYORIX_MASTER_PASSWORD` explicitly as the risk this defends against.
  `internal/cli/run/run.go`'s `filterSensitiveEnv` (`#103`) already strips
  every `KEYORIX_*` credential-shaped variable — including
  `KEYORIX_MASTER_PASSWORD` by name — before building a launched child's
  environment; `TestFilterSensitiveEnv` (`internal/cli/run/run_test.go`)
  asserts this directly and passes. A repo-wide search for every production
  `exec.Command`/`exec.CommandContext` call site found no other place that
  spawns a child process near key material. Both protections predate this
  ADR; this pass confirmed they're still correct and still tested, not that
  they needed fixing.
- **Diagnostic bundles / full-environment dumps.** A repo-wide search for
  `os.Environ()` found exactly one production call site — the same
  already-filtered `run.go` path above. No diagnostic-bundle generator
  captures the process environment.
- **Logs and error messages on a derivation failure.** Every error path in
  `ResolvePassphrase` and its callers names the *source* (`--passphrase-fd
  %d`, `--passphrase-file %q`, the env var *name*) but never the passphrase
  *value*. `pbkdf2.Key`'s own failure modes don't echo their input.
- **Live verification.** A throwaway program built against this repo's
  actual `internal/crypto` package, run in a fresh `golang:1.26-bookworm`
  container with `KEYORIX_MASTER_PASSWORD` deliberately unset, resolved a
  passphrase via `--passphrase-file`, wiped it, and read its own
  `/proc/self/environ`:
  ```
  resolved passphrase (len=23): file-sourced-passphrase
  after WipeBytes: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  /proc/self/environ: clean -- no MASTER_PASSWORD var, no passphrase value, present
  /proc/self/environ entry count: 7
  ```

## Verification

- `internal/crypto/passphrase_test.go`: precedence (fd > file > stdin > env),
  trailing-newline trimming, the file source's permission check (refuses
  group- and world-readable, accepts owner-only) and symlink refusal
  (`O_NOFOLLOW`), and the env fallback's error/trim behavior.
- End-to-end, through the real production chokepoints (not just
  `ResolvePassphrase` in isolation): `TestWireSecretEncryption_PassphraseFileSourceIsWhatActuallyDerivesTheKEK`
  seeds a DEK under a file-sourced passphrase, then proves
  `KEYORIX_MASTER_PASSWORD` holding a *different* value fails to unwrap that
  same DEK when the file source is absent — if the env var had been what
  was actually used the first time, that second call would have succeeded
  instead of failing. `TestWireSecretEncryption_PassphraseFDSource_ActuallyDerivesTheDEK`
  (corrected 2026-09-07 — previously named `..._PassphraseFDSource` and only
  asserted no error on first-time DEK creation, which succeeds under any
  passphrase and so didn't actually prove precedence; now reopens with the
  wrong file source afterward and asserts failure, the same shape as the
  file-source test above) and `TestMasterPassphrase_FDSourceTakesPrecedenceOverEnv`
  cover the fd source via a real `os.Pipe()`. `TestMasterPassphrase_FileSource`
  covers `internal/cli/encryption`'s chokepoint directly.
- `go build ./...`, `go vet ./...`, `gofmt -l` clean on every touched file.
- Full `internal/crypto`, `internal/cli/common`, `internal/cli/encryption`,
  and `server/...` test suites green.

## Alternatives considered

- **A `--passphrase <value>` flag.** Rejected outright: a value on the
  command line is visible to any other process on the host via `ps` and is
  written to shell history — strictly worse than the environment variable
  it would be replacing, not an improvement.
- **Threading `[]byte` all the way through `PasswordKeyProvider` and
  `Service.Initialize`.** Rejected for this pass — see Scope above; this is
  the deeper "wiping" gap the security review already scoped out, and doing
  it here would also have to solve the rotation re-derivation problem
  (`KEK()` called twice on one provider instance) as a prerequisite, which
  is its own design question independent of sourcing.
