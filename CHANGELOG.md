# Changelog

## 3.1.0 — End-to-end test harness

### Added
- **Mock macOS command set** (`tests/mocks/install-mocks.sh`): faithful
  emulations of `sysadminctl`, `dscl`, `profiles`, `sw_vers`, `diskutil` and
  `createhomedir` that enforce Apple's documented Secure Token semantics —
  including that `-secureTokenOn` without admin credentials does nothing (while
  exiting 0), and that a `-` password blocks awaiting a terminal.
- **Integration suite** (`tests/integration_test.sh`, 66 assertions): executes
  the real `securetoken.sh` end-to-end against the mocks — every action, every
  documented exit code, idempotency, orphan prevention, rollback, the watchdog
  (both the hang case and headless `stdin` secret mode), locking, hidden-account
  UIDs and strict JSON validity. Runs on Linux/CI; wired into the CI matrix.

### Fixed (found by the new integration tests)
- `resolve_config` stripped **all** whitespace from usernames, silently turning
  an invalid `"bad name"` into a valid `badname` instead of rejecting it. Values
  are now trimmed at the edges only (new `trim()` helper, unit-tested).
- `--require-immediate` with a deferred-only plan failed **after** account
  creation, leaving the orphan account the flag exists to prevent. The check now
  runs before anything is created (exit 23, no account).
- Swift: `String(UnicodeScalarView.filter(...))` in `sanitizeForLog` does not
  compile; mapped through `Character` instead.

---

## 3.0.0 — Corrected Secure Token architecture

### Fixed (critical)
- **The "credential-free Bootstrap Token grant" in v2 does not exist.** Apple's
  [Platform Deployment guide](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web)
  states that changing secure token status with `sysadminctl` *always* requires
  an existing secure token administrator's credentials, and that an escrowed
  Bootstrap Token instead causes macOS to grant the token **at the user's first
  login** (macOS 11+). v2 believed `sysadminctl` could spend the Bootstrap Token
  and *preferred* that path — so on exactly the MDM-enrolled fleet this tool
  targets, it ignored valid admin credentials and left every device with a
  tokenless account. That path has been removed.
- The tool now implements the two real mechanisms: plan **`admin`** (credentials
  supplied → immediate, verified grant) and plan **`deferred`** (no credentials +
  escrowed Bootstrap Token → account created, token granted at first login,
  reported as `tokenMethod: "deferred-login"`; exit 0, or 23 with
  `ST_REQUIRE_IMMEDIATE_TOKEN=1`).
- **Secret delivery default changed to `inline`.** `-password -` is Apple's
  *interactive prompt* option and reads the controlling terminal, so it cannot be
  fed by a pipe in a headless Intune/RMM session. `stdin` is now opt-in, and every
  `sysadminctl` call runs under a watchdog so a prompt can never hang a job.
- **Removed top-level `readonly`**, which is fatal on the bash 3.2 shipped with
  macOS when the file is re-sourced — it broke the documented library mode and
  the test suite on the target shell.
- Swift: `FileHandle.close()` is macOS 10.15+ while `Package.swift` declares
  10.13; switched to `closeFile()` so the target can compile.

### Added
- `delete-user` action, and opt-in `ST_ROLLBACK_ON_FAILURE` to remove a
  just-created account when the grant fails.
- Single-instance lock (exit 24) so two overlapping RMM runs cannot race.
- Per-call watchdog (`ST_TIMEOUT`, default 120s).
- `preflight`, `status` and `list` now emit their actual data as JSON
  (`firstLoginGrantAvailable`, `tokenHolders[]`, `hasSecureToken`, …).

### Changed / hardened
- Admin password verified with `dscl -authonly` **before** anything is created,
  so a stale credential cannot leave an orphaned tokenless account.
- New account's password verified post-create; a generated password is reported
  only once actually applied, and is still reported on later failures so the
  account is never left unreachable.
- `PATH` sanitised; `ST_NEW_PASSWORD`/`ST_ADMIN_PASSWORD` unset from the
  environment after resolution; secrets scrubbed from shell state after each call.
- `truthy()` trims whitespace/CR; `json_escape` escapes C0 controls as `\u00XX`;
  log values stripped of control characters; log opened once on fd 3 with
  symlink, hard-link and rotation checks.
- UID validated (numeric, in range, not already in use); passwords reject
  embedded newline/CR; `dscl` enumeration failure no longer reports "no holders".
- A value-taking flag in final position now fails with exit 2 and a message.
- Password generation reads bounded chunks (no reliance on a SIGPIPE quirk),
  guarantees exact length, and never starts with `-`.
- NinjaOne wrapper: propagates the core's exit code unchanged, forwards
  arguments, uses `ninjarmm-cli set --stdin`, and refuses a core that is not
  root-owned or is group/world-writable.

### Tests
- 46 → **69 assertions**, now covering `parse_args`/`resolve_config`,
  environment-secret scrubbing, CR/whitespace normalisation, control-character
  JSON escaping, and the generated-password reporting contract.

---

## 2.0.0 — Unattended RMM / Intune release

### Added
- **`scripts/securetoken.sh`** — new self-contained, fully non-interactive core
  designed to run as root from an RMM or Intune. Actions: `create-user`,
  `grant-token`, `status`, `list`, `preflight`.
- **Bootstrap Token support** — grants Secure Tokens credential-free on
  MDM-enrolled Macs (macOS 10.15+); falls back to an existing Secure Token admin
  only when no Bootstrap Token is escrowed.
- **`preflight`** assessment action (macOS version, arch, root, APFS, MDM,
  Bootstrap Token escrow, current token holders).
- **Three-layer configuration** (CLI flag → `ST_*` env var → CONFIG block) so the
  same file works for RMM env injection and single-file Intune uploads.
- **Stable exit-code contract** and optional **JSON result** (`--json`/`ST_JSON`)
  for RMM/Intune parsing.
- **Password generation** (`--generate-password`) with ambiguous characters
  excluded; returned in the JSON result.
- **Intune** guide (`scripts/intune/`), **RMM** guide + **NinjaOne** wrapper
  (`scripts/rmm/`), and `docs/DEPLOYMENT.md`.
- **`tests/securetoken_test.sh`** — 32 assertions over the shell core's pure
  logic; runs on any OS.

### Changed
- Swift CLI reworked for parity: `preflight`, env-driven non-interactive mode,
  JSON output, exit-code mapping, Bootstrap Token detection.
- `secure-token-transfer.sh` is now a thin deprecation shim forwarding to the
  core.

### Fixed
- **Critical:** `validate_username` returned non-zero for *valid* usernames
  (its last command was a failed reserved-name test), which under `set -e` would
  abort every run. Now returns explicit success.
- **Passwords no longer appear in `ps`** — secrets are streamed to `sysadminctl`
  via stdin instead of being passed as command-line arguments.
- **bash 3.2 compatibility** — removed bash-4-only `${var,,}` lowercase
  expansions (which fail on the `/bin/bash` shipped with macOS).
- Swift `@main` moved out of `main.swift` to avoid the top-level-code conflict.
