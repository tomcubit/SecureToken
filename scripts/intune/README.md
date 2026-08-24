# Deploying SecureToken with Microsoft Intune

Intune runs a **single** shell script on macOS, as root, with no way to inject
per-run variables. So the Intune model is: **edit the CONFIG block at the top of
`securetoken.sh` and upload that one file.**

## First: which credential model?

`sysadminctl` **cannot** grant a Secure Token without an existing token holder's
credentials ([Apple Platform Deployment guide](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web)).
Choose one:

- **Deferred (no secrets in the script).** On an MDM-enrolled Mac running macOS
  11+ with an escrowed Bootstrap Token, the account is created and macOS grants
  the Secure Token at the user's **first login**. The run exits 0 with
  `tokenMethod: "deferred-login"` and **no token is present yet** — that is
  expected, not a failure.
- **Immediate (stores a secret).** Supply `CONFIG_ADMIN_USER` /
  `CONFIG_ADMIN_PASSWORD` for a token holder. The token is granted and verified
  during the run. The credential lives inside the uploaded script — Intune
  encrypts it at rest, but anyone who can read the policy can read it.

Upload a copy with `CONFIG_ACTION="preflight"` first to see which applies; the
JSON result reports `firstLoginGrantAvailable` and `tokenHolders`.

## 1. Prepare the script

Edit the **CONFIG BLOCK** near the top of `scripts/securetoken.sh`:

```sh
CONFIG_ACTION="create-user"
CONFIG_NEW_USER="itadmin"
CONFIG_NEW_FULLNAME="IT Admin"
CONFIG_NEW_PASSWORD=""            # left blank on purpose
CONFIG_GENERATE_PASSWORD="1"      # generate a strong password
CONFIG_MAKE_ADMIN="1"
CONFIG_HIDDEN="1"
CONFIG_JSON="1"                   # JSON result line in the Intune log
```

For an immediate grant, add:

```sh
CONFIG_ADMIN_USER="localadmin"
CONFIG_ADMIN_PASSWORD="…"
```

## 2. Create the Intune policy

**Intune admin center → Devices → macOS → Shell scripts → Add**

| Setting | Value |
|---------|-------|
| Upload script | your edited `securetoken.sh` |
| Run script as signed-in user | **No** (must run as **root**) |
| Hide script notifications | Yes (optional) |
| Script frequency | Not configured (run once) — it is idempotent, so a repeating schedule is also safe |
| Max number of times to retry | 3 |

Assign to a device group and save.

## 3. Read the result

- Intune surfaces the **exit code** as success (0) or failure per device under
  **Monitor → Device status**. See the exit-code table in the
  [root README](../../README.md).
- Captured output includes the JSON result line and the human-readable log. The
  same log is written on-device to `/var/log/securetoken.log`.
- With `CONFIG_GENERATE_PASSWORD="1"`, the password appears in the result's
  `generatedPassword` field (only once actually applied to the account). Treat
  the Intune log as sensitive, or rotate the password out of band.

## 4. Verify a deferred grant

If the result said `deferred-login`, the token appears only after the user logs
in. Confirm with a second policy:

```sh
CONFIG_ACTION="status"
CONFIG_NEW_USER="itadmin"
CONFIG_JSON="1"
```

The JSON reports `hasSecureToken: true|false`.

## Requirements & notes

- macOS 10.13+ for Secure Tokens; the first-login grant needs macOS 11+ and an
  escrowed Bootstrap Token (escrow itself needs 10.15.4+).
- The script begins with `#!/bin/bash` and targets the bash 3.2 that ships with
  macOS — no external dependencies.
- Re-running is safe: an already-provisioned user yields exit 0 with no changes.
- Full detail: [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md).
