# SecureToken

Automate macOS **Secure Token** provisioning for new user accounts — with **zero
interactive prompts**, so it runs unattended from an **RMM** (NinjaOne, Datto,
Kaseya, Addigy, Mosyle, …) or **Microsoft Intune**.

The tool creates a local account (if needed) and ensures it holds a Secure
Token. It **prefers the escrowed Bootstrap Token** — the credential-free path
for MDM-managed Macs — and falls back to an existing Secure Token administrator
only when no Bootstrap Token is available.

## Why Secure Tokens (and Bootstrap Tokens) matter

On APFS Macs (macOS 10.13+), a **Secure Token** is what lets a user unlock
FileVault and authorise certain system operations. A new account created
non-interactively often has **no** Secure Token, which breaks FileVault unlock
for that user.

Historically, granting a token required typing an *existing* token-holder's
credentials — impossible to do "without manually having to do anything." The
modern answer is the **Bootstrap Token**: an MDM-escrowed key that lets macOS
(10.15+, and required behaviour on Apple Silicon) grant Secure Tokens
**without** any admin password. This tool is built around that path.

```
                 ┌─────────────────────────────┐
                 │   run securetoken.sh (root)  │
                 └──────────────┬──────────────┘
                                │
              Bootstrap Token escrowed to MDM?
                    │yes                    │no
                    ▼                       ▼
        grant token via Bootstrap    use existing Secure Token
        Token (NO credentials)       admin (ST_ADMIN_USER/PW)
                    │                       │
                    └───────────┬───────────┘
                                ▼
                    verify token ENABLED, exit 0
```

## What's in the box

| Path | Purpose |
|------|---------|
| `scripts/securetoken.sh` | **Primary deliverable.** Self-contained, non-interactive core. Deploy this from any RMM or Intune. |
| `scripts/intune/` | Intune portal steps + single-file config guidance. |
| `scripts/rmm/` | RMM `ST_*` interface + NinjaOne wrapper. |
| `scripts/secure-token-transfer.sh` | Deprecated v1 shim → forwards to the core. |
| `Sources/SecureToken/` | Optional Swift CLI (same behaviour) for local/hands-on use. |
| `tests/securetoken_test.sh` | Unit tests for the shell core (run on any OS). |
| `docs/DEPLOYMENT.md` | Step-by-step for Intune, NinjaOne, generic RMM. |

The shell core targets the **bash 3.2** that ships on every macOS and has **no
dependencies** — ideal for RMM/Intune. The Swift CLI is an optional convenience
you compile on macOS.

## Quick start

### Preflight (assess readiness — start here)

```bash
sudo ST_ACTION=preflight ST_JSON=1 /bin/bash securetoken.sh
```

Reports macOS version, MDM enrollment, whether a **Bootstrap Token is escrowed**,
and which users already hold tokens.

### From an RMM (Bootstrap Token, no passwords)

Set script variables and run the core:

```bash
ST_ACTION=create-user
ST_NEW_USER=itadmin
ST_NEW_FULLNAME="IT Admin"
ST_MAKE_ADMIN=1
ST_GENERATE_PASSWORD=1     # returns a strong password in the JSON result
ST_JSON=1
```

See [`scripts/rmm/README.md`](scripts/rmm/README.md) and the NinjaOne wrapper.

### From Intune

Edit the `CONFIG` block at the top of `securetoken.sh`, upload the single file,
and set it to run as **root**. See [`scripts/intune/README.md`](scripts/intune/README.md).

### Fallback (no Bootstrap Token — supply an admin)

```bash
sudo ST_NEW_USER=itadmin ST_NEW_PASSWORD='…' \
     ST_ADMIN_USER=localadmin ST_ADMIN_PASSWORD='…' \
     /bin/bash securetoken.sh create-user
```

## Configuration

Every option is a CLI flag **and** an `ST_*` environment variable **and** a
`CONFIG_*` line in the script's CONFIG block. Precedence: **flag → env → CONFIG
block → default**.

| Env var | Flag | Meaning |
|---------|------|---------|
| `ST_ACTION` | *(positional)* | `create-user` (default), `grant-token`, `status`, `list`, `preflight` |
| `ST_NEW_USER` | `--new-user` | Username to create/target |
| `ST_NEW_FULLNAME` | `--new-fullname` | Display name |
| `ST_NEW_PASSWORD` | `--new-password` | Password |
| `ST_GENERATE_PASSWORD` | `--generate-password` | Generate a strong password and return it |
| `ST_MAKE_ADMIN` | `--make-admin` | Create an administrator |
| `ST_HIDDEN` | `--hidden` | Hidden service account |
| `ST_UID` | `--uid` | Explicit UID |
| `ST_ADMIN_USER` | `--admin-user` | Existing Secure Token admin (fallback) |
| `ST_ADMIN_PASSWORD` | `--admin-password` | That admin's password |
| `ST_LOG_FILE` | `--log-file` | Log path (default `/var/log/securetoken.log`) |
| `ST_JSON` | `--json` | Emit one JSON result line on stdout |
| `ST_STDIN_SECRETS` | `--inline-secrets` (=0) | Feed passwords via stdin (default) vs inline |
| `ST_PREFER_BOOTSTRAP` | `--no-bootstrap` (=0) | Use the Bootstrap Token when available (default) |

## Exit codes (stable contract)

| Code | Meaning |
|------|---------|
| 0 | Success, or already in the desired state (idempotent — safe to re-run) |
| 2 | Invalid arguments / configuration |
| 10 | Not running as root |
| 11 | macOS / platform unsupported |
| 12 | Precondition failed (boot volume not APFS) |
| 20 | User creation failed |
| 21 | Secure Token grant failed |
| 22 | No Bootstrap Token **and** no valid Secure Token admin |
| 40 | Post-grant verification failed |

## Security model

- **No passwords in `ps`.** Passwords are streamed to `sysadminctl` over stdin
  (`-` placeholders), not passed as arguments. (`--inline-secrets` disables this
  only if a specific macOS build misbehaves.)
- **Prefer credential-free.** The Bootstrap Token path needs no stored secrets
  at all — the recommended posture.
- **Secrets stay out of logs.** stdout carries only the optional JSON result;
  human-readable progress goes to stderr and `/var/log/securetoken.log`. Neither
  ever contains a password (except `generatedPassword` in the JSON result when
  you explicitly ask the tool to generate one — treat that output as sensitive).
- **Least privilege.** Supply admin credentials through your RMM's *secure*
  custom fields, never inline in the policy body.

## Validation status

- `scripts/securetoken.sh`, the NinjaOne wrapper, and the shim are **shellcheck
  clean** and pass `bash -n`.
- `tests/securetoken_test.sh` covers the core's pure logic (32 assertions) and
  runs on any OS: `bash tests/securetoken_test.sh`.
- The Swift CLI mirrors the shell behaviour but must be **built and tested on
  macOS** (`swift build` / `swift test`); it is not compiled in CI on Linux.
- End-to-end behaviour (actual `sysadminctl` token grants, Bootstrap Token use)
  **must be validated on a test Mac** before fleet rollout — run `preflight`
  first, then a single-device pilot.

## License

MIT — see [LICENSE](LICENSE).
