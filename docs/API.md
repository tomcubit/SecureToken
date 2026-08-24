# API & Interface Reference

Covers the shell core (`scripts/securetoken.sh`) — the primary interface — and
the optional Swift library. For deployment walkthroughs see
[DEPLOYMENT.md](DEPLOYMENT.md).

## Actions

| Action | Description |
|--------|-------------|
| `create-user` (default) | Create the user if absent, then ensure it gets a Secure Token. Idempotent. |
| `grant-token` | Grant a Secure Token to an **existing** user. |
| `delete-user` | Delete a local user account. |
| `status` | Report token status for a user (`hasSecureToken` in JSON). |
| `list` | List all users holding a Secure Token (`tokenHolders` in JSON). |
| `preflight` | Report readiness: macOS, arch, root, APFS, MDM, Bootstrap Token, holders. |

Select via the positional argument, `ST_ACTION`, or `CONFIG_ACTION`.

## Token plans

| `tokenMethod` | Meaning |
|---------------|---------|
| `admin` | Granted immediately using a supplied Secure Token administrator, then verified. |
| `deferred-login` | No credentials supplied; macOS will grant the token at the user's **first login** via the escrowed Bootstrap Token (macOS 11+). No token exists yet. |
| `existing` | The user already held a Secure Token. |
| `none` | No token, and none arranged. |

`sysadminctl` cannot spend a Bootstrap Token — see the
[README](../README.md#read-this-first-how-secure-tokens-are-actually-granted).

## Configuration precedence

**CLI flag → `ST_*` env var → `CONFIG_*` block → built-in default.** See the
table in the [README](../README.md#configuration).

## Output contract

- **stdout**: nothing, unless JSON mode is on (`--json` / `ST_JSON=1`), in which
  case exactly one JSON object is printed as the final line:

  ```json
  {"tool":"securetoken","version":"3.0.0","status":"ok","exitCode":0,
   "action":"create-user","user":"itadmin","tokenMethod":"admin",
   "message":"user created and secure token granted"}
  ```

  Additional fields by action:

  | Action | Extra fields |
  |--------|--------------|
  | `preflight` | `macosVersion`, `arch`, `isRoot`, `bootIsAPFS`, `mdmEnrolled`, `bootstrapTokenEscrowed`, `firstLoginGrantAvailable`, `userEnumerationOk`, `tokenHolders[]` |
  | `status` | `userExists`, `hasSecureToken` |
  | `list` | `tokenHolders[]` |
  | any | `generatedPassword` — present **only** when a generated password was actually applied to the account (including on later failures, so the account is never unreachable) |

  All string values are JSON-escaped, including C0 control characters as
  `\u00XX`, so the line parses in `jq`, Python and PowerShell.

- **stderr + `/var/log/securetoken.log`**: timestamped, human-readable progress,
  stripped of control characters. Never contains passwords.

- **exit code**: the stable contract in the
  [README](../README.md#exit-codes-stable-contract).

## macOS commands used

| Command | Use |
|---------|-----|
| `sysadminctl -addUser … -password …` | Create a user. |
| `sysadminctl -secureTokenOn … -adminUser … -adminPassword …` | Grant a token (requires an existing token holder). |
| `sysadminctl -secureTokenStatus <user>` | Read token status (authoritative check after a grant). |
| `sysadminctl -deleteUser <user>` | Delete a user (`delete-user`, rollback). |
| `dscl . -authonly <user> <pass>` | Verify a password actually authenticates. |
| `dscl . -list/-read/-create /Users` | Enumerate/inspect/modify accounts. |
| `profiles status -type enrollment` | Detect MDM enrollment. |
| `profiles status -type bootstraptoken` | Detect Bootstrap Token escrow. |
| `diskutil info /` | Confirm APFS boot volume. |
| `createhomedir -c -u <user>` | Ensure the home directory exists. |
| `sw_vers -productVersion`, `uname -m` | Version / architecture. |

### Secret delivery

`ST_SECRET_MODE=inline` (default) passes credentials as arguments — the path
Apple documents for scripting, and the only one that works headless. It is
briefly visible in `ps`.

`ST_SECRET_MODE=stdin` substitutes `-` placeholders, which makes `sysadminctl`
**prompt interactively** on the controlling terminal. It is not a stdin protocol,
so it needs a TTY and is unsuitable for Intune/RMM. Every call runs under a
watchdog (`ST_TIMEOUT`, default 120s, exit path logged) so a prompt cannot hang a
job forever.

## Shell library (for tests / extension)

Source the core without executing it by setting `ST_LIB_ONLY=1`:

```bash
ST_LIB_ONLY=1 . scripts/securetoken.sh
truthy yes            # -> 1
version_ge 14.0 10.13 # exit 0
generate_password 20  # random 20-char password
```

Note this also applies `set -euo pipefail` to your shell.

Key pure functions: `truthy`, `version_ge`, `json_escape`, `sanitize_for_log`,
`pick`, `generate_password`, `validate_username`, `validate_password`,
`validate_uid`, `first_unused_uid`, `build_sysadminctl_args`, `emit_result`,
`parse_args`, `resolve_config`.

Platform functions (`token_status`, `user_exists`, `password_authenticates`,
`bootstrap_login_grant_available`, `create_user`, `grant_token`, …) call macOS
binaries and only work on macOS.

## Swift library

`SecureTokenManager` mirrors the shell behaviour for the optional CLI.

| Member | Description |
|--------|-------------|
| `init(logFile:)` | Construct; `stdinSecrets` / `preferBootstrap` are toggles. |
| `isRoot()` / `supportsSecureToken()` / `isAppleSilicon()` / `bootIsAPFS()` | Platform probes. |
| `mdmEnrolled()` / `bootstrapTokenEscrowed()` / `bootstrapLoginGrantAvailable()` | MDM / Bootstrap Token detection. |
| `userExists(_:)` / `hasSecureToken(_:)` / `localUsers()` / `tokenHolders()` | Directory queries. |
| `passwordAuthenticates(_:_:)` | Verify a credential via `dscl -authonly`. |
| `validateUsername(_:)` / `validatePassword(_:)` | Throw `SecureTokenError` on invalid input. |
| `generatePassword(length:)` | Strong password, ambiguous characters excluded. |
| `resolveTokenPlan(adminUser:adminPassword:)` | Admin (immediate) vs deferred-login decision. |
| `createUser(...)` | Create an account and verify the password authenticates. |
| `ensureToken(user:password:adminUser:adminPassword:)` | Idempotently grant + verify, or arrange a deferred grant. |

`SecureTokenError` carries an `ExitStatus` whose `rawValue` matches the shell
exit-code contract. `OperationResult.jsonLine(version:)` emits the same JSON
shape as the shell core.

> The Swift target is **not built in CI here** (Linux, no toolchain). Build and
> test on macOS with `swift build` / `swift test` before relying on it.
