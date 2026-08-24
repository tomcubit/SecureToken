# API & Interface Reference

Covers the shell core (`scripts/securetoken.sh`) — the primary interface — and
the optional Swift library. For deployment walkthroughs see
[DEPLOYMENT.md](DEPLOYMENT.md).

## Actions

| Action | Description |
|--------|-------------|
| `create-user` (default) | Create the user if absent, then ensure it holds a Secure Token. Idempotent. |
| `grant-token` | Grant a Secure Token to an **existing** user. |
| `status` | Report token status for a user. |
| `list` | List all users holding a Secure Token. |
| `preflight` | Report readiness: macOS version, arch, root, APFS, MDM, Bootstrap Token, token holders. |

Select an action via the positional argument (`securetoken.sh create-user`),
`ST_ACTION`, or `CONFIG_ACTION`.

## Configuration precedence

For every setting: **CLI flag → `ST_*` environment variable → `CONFIG_*` block →
built-in default**. See the table in the [README](../README.md#configuration).

## Output contract

- **stdout**: nothing, unless JSON mode is on (`--json` / `ST_JSON=1`), in which
  case exactly one JSON object is printed as the final line:

  ```json
  {"tool":"securetoken","version":"2.0.0","status":"ok","exitCode":0,
   "action":"create-user","user":"itadmin","tokenMethod":"bootstrap",
   "message":"user created and secure token granted"}
  ```

  `generatedPassword` is present only when `--generate-password` produced one.
  `tokenMethod` is one of `bootstrap`, `admin`, `existing`, `none`.

- **stderr + `/var/log/securetoken.log`**: timestamped, human-readable progress.
  Never contains passwords.

- **exit code**: the stable contract in the [README](../README.md#exit-codes-stable-contract).

## macOS commands used

| Command | Use |
|---------|-----|
| `sysadminctl -addUser … -password -` | Create a user (password via stdin). |
| `sysadminctl -secureTokenOn … -password -` | Grant token (Bootstrap Token path, no admin creds). |
| `sysadminctl -secureTokenOn … -adminUser … -adminPassword -` | Grant token via existing admin. |
| `sysadminctl -secureTokenStatus <user>` | Read token status. |
| `dscl . -list/-read/-create /Users` | Enumerate/inspect/modify accounts. |
| `profiles status -type enrollment` | Detect MDM enrollment. |
| `profiles status -type bootstraptoken` | Detect Bootstrap Token escrow. |
| `diskutil info /` | Confirm APFS boot volume. |
| `createhomedir -c -u <user>` | Ensure the home directory exists. |
| `sw_vers -productVersion`, `uname -m` | Version / architecture. |

The `-` after `-password` / `-adminPassword` tells `sysadminctl` to read that
secret from stdin, keeping it out of the process table. Set `ST_STDIN_SECRETS=0`
to pass secrets inline instead (fallback only).

## Shell library (for tests / extension)

Source the core without executing it by setting `ST_LIB_ONLY=1`:

```bash
ST_LIB_ONLY=1 . scripts/securetoken.sh
truthy yes            # -> 1
version_ge 14.0 10.13 # exit 0
generate_password 20  # random 20-char password
```

Key pure functions: `truthy`, `version_ge`, `json_escape`, `pick`,
`generate_password`, `validate_username`, `validate_password`, `emit_result`.
Platform functions (`token_status`, `user_exists`, `bootstrap_token_escrowed`,
`create_user`, `grant_token`, …) call macOS binaries and only work on macOS.

## Swift library

`SecureTokenManager` mirrors the shell behaviour for the optional CLI.

| Member | Description |
|--------|-------------|
| `init(logFile:)` | Construct; `stdinSecrets` / `preferBootstrap` are toggles. |
| `isRoot()` / `supportsSecureToken()` / `isAppleSilicon()` / `bootIsAPFS()` | Platform probes. |
| `mdmEnrolled()` / `bootstrapTokenEscrowed()` | MDM / Bootstrap Token detection. |
| `userExists(_:)` / `hasSecureToken(_:)` / `localUsers()` / `tokenHolders()` | Directory queries. |
| `validateUsername(_:)` / `validatePassword(_:)` | Throw `SecureTokenError` on invalid input. |
| `generatePassword(length:)` | Strong password, ambiguous characters excluded. |
| `resolveTokenMethod(adminUser:adminPassword:)` | Bootstrap vs admin decision. |
| `createUser(...)` | Create an account via stdin-fed `sysadminctl`. |
| `ensureToken(user:password:adminUser:adminPassword:)` | Idempotently grant + verify. |

`SecureTokenError` carries an `ExitStatus` whose `rawValue` matches the shell
exit-code contract. `OperationResult.jsonLine(version:)` emits the same JSON
shape as the shell core.
