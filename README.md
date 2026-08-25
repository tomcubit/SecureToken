# SecureToken

Automate macOS **Secure Token** provisioning for new user accounts — with **zero
interactive prompts**, so it runs unattended from an **RMM** (NinjaOne, Datto,
Kaseya, Addigy, Mosyle, …) or **Microsoft Intune**.

## Read this first: how Secure Tokens are actually granted

This is the part most scripts get wrong, so it drives the whole design. From
Apple's [Platform Deployment guide](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web):

> "Changing the secure token status of a user using `sysadminctl` **always
> requires** the user name and password of an existing secure token–enabled
> administrator, either interactively or through the appropriate flags."

> "For a Mac with macOS 11 or later, if macOS doesn't grant a secure token at
> creation, and if a bootstrap token is available from the device management
> service, it grants a secure token to the local user **when they log in**."

Two consequences:

1. **There is no credential-free `sysadminctl` grant.** A Bootstrap Token
   *cannot* be spent by `sysadminctl`. Any script claiming otherwise will fail.
2. **The Bootstrap Token is credential-free but deferred** — macOS grants the
   token at the user's **first login**, not at provisioning time.

So this tool implements exactly the two mechanisms that exist:

| Plan | Requires | When the token appears | Reported as |
|------|----------|------------------------|-------------|
| **admin** | An existing Secure Token holder's username + password | Immediately, and verified during the run | `tokenMethod: "admin"` |
| **deferred** | MDM-enrolled, macOS 11+, Bootstrap Token escrowed | At the user's **first login** | `tokenMethod: "deferred-login"` |

```
                    ┌──────────────────────────────┐
                    │  run securetoken.sh (root)   │
                    └───────────────┬──────────────┘
                                    │
              ST_ADMIN_USER + ST_ADMIN_PASSWORD supplied?
                    │yes                          │no
                    ▼                             ▼
   verify admin holds a token AND      Bootstrap Token escrowed
   the password authenticates          + MDM + macOS 11+ ?
   (dscl -authonly), THEN create             │yes          │no
                    │                        ▼             ▼
                    ▼                 create account,   exit 22
     sysadminctl -secureTokenOn        token granted   (no token
       -adminUser -adminPassword       at first login   source)
                    │                        │
                    ▼                        ▼
        verify ENABLED, exit 0      exit 0, tokenMethod=
                                       deferred-login
```

If you need the token to exist *before* first login, you must supply admin
credentials. Set `ST_REQUIRE_IMMEDIATE_TOKEN=1` to make a deferred outcome a
hard failure (exit 23) rather than a success.

## What's in the box

| Path | Purpose |
|------|---------|
| `scripts/securetoken.sh` | **Primary deliverable.** Self-contained, non-interactive core. Deploy from any RMM or Intune. |
| `scripts/intune/` | Intune portal steps + single-file config guidance. |
| `scripts/rmm/` | RMM `ST_*` interface + NinjaOne wrapper. |
| `scripts/secure-token-transfer.sh` | Deprecated v1 shim → forwards to the core. |
| `Sources/SecureToken/` | Optional Swift CLI (same behaviour) for local use. |
| `tests/securetoken_test.sh` | Unit tests for the shell core (run on any OS). |
| `docs/DEPLOYMENT.md` | Step-by-step for Intune, NinjaOne, generic RMM. |

The shell core targets the **bash 3.2** shipped with every macOS and has **no
dependencies**. The Swift CLI is an optional convenience you compile on macOS.

## Quick start

### 1. Preflight (always start here)

```bash
sudo ST_ACTION=preflight ST_JSON=1 /bin/bash securetoken.sh
```

Reports macOS version, MDM enrollment, whether a Bootstrap Token is escrowed,
whether a first-login grant is available, and which users already hold tokens —
as both human-readable log lines and a JSON payload.

### 2a. Immediate grant (admin credentials — recommended)

```bash
sudo ST_NEW_USER=itadmin ST_NEW_FULLNAME="IT Admin" ST_MAKE_ADMIN=1 \
     ST_GENERATE_PASSWORD=1 \
     ST_ADMIN_USER=localadmin ST_ADMIN_PASSWORD='…' \
     ST_JSON=1 /bin/bash securetoken.sh create-user
```

### 2b. Credential-free (token arrives at first login)

```bash
sudo ST_NEW_USER=itadmin ST_MAKE_ADMIN=1 ST_GENERATE_PASSWORD=1 \
     ST_JSON=1 /bin/bash securetoken.sh create-user
```

Succeeds with `tokenMethod: "deferred-login"` on an MDM-enrolled macOS 11+ Mac
with an escrowed Bootstrap Token. Verify after the user's first login with
`securetoken.sh status --new-user itadmin`.

## Configuration

Every option is a CLI flag **and** an `ST_*` environment variable **and** a
`CONFIG_*` line in the script's CONFIG block. Precedence: **flag → env → CONFIG
block → default**.

| Env var | Flag | Meaning |
|---------|------|---------|
| `ST_ACTION` | *(positional)* | `create-user` (default), `grant-token`, `delete-user`, `status`, `list`, `preflight` |
| `ST_NEW_USER` | `--new-user` | Username to create/target |
| `ST_NEW_FULLNAME` | `--new-fullname` | Display name |
| `ST_NEW_PASSWORD` | `--new-password` | Password |
| `ST_GENERATE_PASSWORD` | `--generate-password` | Generate a strong password and return it |
| `ST_MAKE_ADMIN` | `--make-admin` | Create an administrator |
| `ST_HIDDEN` | `--hidden` | Hidden service account |
| `ST_UID` | `--uid` | Explicit UID (validated: numeric, in range, unused) |
| `ST_ADMIN_USER` | `--admin-user` | Existing Secure Token holder (enables the immediate grant) |
| `ST_ADMIN_PASSWORD` | `--admin-password` | That admin's password |
| `ST_LOG_FILE` | `--log-file` | Log path (default `/var/log/securetoken.log`) |
| `ST_JSON` | `--json` | Emit one JSON result line on stdout |
| `ST_SECRET_MODE` | `--secret-mode` | `inline` (default) or `stdin` — see Security |
| `ST_REQUIRE_IMMEDIATE_TOKEN` | `--require-immediate` | Treat a deferred grant as failure |
| `ST_ROLLBACK_ON_FAILURE` | `--rollback-on-failure` | Delete a just-created account if the grant fails |
| `ST_TIMEOUT` | `--timeout` | Per-`sysadminctl` watchdog, default 120s |

## Exit codes (stable contract)

| Code | Meaning |
|------|---------|
| 0 | Success, or already in the desired state (idempotent — safe to re-run) |
| 2 | Invalid arguments / configuration |
| 10 | Not running as root |
| 11 | macOS / platform unsupported |
| 12 | Precondition failed (boot volume not APFS, no randomness) |
| 20 | User creation failed |
| 21 | Secure Token grant failed |
| 22 | No admin credentials **and** no Bootstrap Token first-login grant available |
| 23 | Token deferred to first login, but `ST_REQUIRE_IMMEDIATE_TOKEN=1` was set |
| 24 | Another instance is already running |
| 40 | Post-grant verification failed |

## Security model

- **Secret delivery.** `sysadminctl`'s `-password -` form is Apple's
  **interactive prompt** option: it reads the controlling terminal, so it cannot
  be fed by a pipe in a headless RMM/Intune session. The default is therefore
  `inline` (credentials as arguments — the path Apple documents for scripting),
  which is **briefly visible in `ps`** to local users. `stdin` mode is available
  (`ST_SECRET_MODE=stdin`) for interactive/TTY use. Every `sysadminctl` call runs
  under a watchdog (`ST_TIMEOUT`) so an unexpected prompt can never hang a job.
- **Credentials are verified before anything is created** with `dscl -authonly`,
  so a stale admin password cannot leave an orphaned tokenless account.
- **Generated passwords** are returned in the JSON result **only once actually
  applied** to the account — and are still returned if a later step fails, so an
  account is never left unreachable. Treat that output as sensitive.
- **Secrets are removed from the environment** after they are read, so child
  processes do not inherit them, and are scrubbed from shell state after use.
- **Logs**: `PATH` is sanitised; the log is opened once, refused if it is a
  symlink or hard-linked, created mode `0600`, rotated past 1 MB, and every
  logged value is stripped of control characters. Passwords are never logged.
- **Single-instance lock** prevents two overlapping runs from racing.

## Validation status

- `scripts/securetoken.sh`, the NinjaOne wrapper and the shim are **shellcheck
  clean** and pass `bash -n`.
- **Unit tests** — `tests/securetoken_test.sh`, 75 assertions over the core's
  pure logic, argument/config resolution, the JSON contract and secret
  scrubbing. Runs on any OS: `bash tests/securetoken_test.sh`.
- **End-to-end integration tests** — `tests/integration_test.sh`, 66 assertions
  that execute the real script against a **mock macOS command set**
  (`tests/mocks/`) which faithfully enforces Apple's Secure Token rules: no
  credential-free `sysadminctl` grants, `-` passwords block awaiting a terminal,
  `sysadminctl` exiting 0 on failure. Covers every action, every documented exit
  code, idempotency, fail-fast/orphan prevention, rollback, the watchdog, the
  lock and JSON validity. Linux + root only:
  `sudo bash tests/mocks/install-mocks.sh && sudo bash tests/integration_test.sh`
  (disposable machines only — it installs mock commands into `/usr/bin`).
- **CI** (`.github/workflows/ci.yml`): shellcheck + both suites on Linux, the
  unit suite under **real bash 3.2 on a macOS runner**, and `swift build` /
  `swift test` on macOS. Check the repo's **Actions** tab for results — this
  container has no Swift toolchain or macOS, so those two jobs are the compile
  and 3.2-compatibility proof.
- **A real-Mac pilot is still required** before fleet rollout: mocks encode
  Apple's *documented* behaviour, not any given macOS build's quirks. Run
  `preflight`, then a single-device pilot — see the checklist in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## License

MIT — see [LICENSE](LICENSE).
