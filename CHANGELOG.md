# Changelog

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
