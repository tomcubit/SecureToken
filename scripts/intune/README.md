# Deploying SecureToken with Microsoft Intune

Intune runs a **single** shell script on macOS, as root, with no way to inject
per-run variables. So the Intune model is: **edit the CONFIG block at the top of
`securetoken.sh` and upload that one file.**

> **Strongly recommended:** use the **Bootstrap Token** path so the uploaded
> script contains **no passwords**. Intune-enrolled Macs escrow a Bootstrap
> Token automatically when supervised (ADE/Automated Device Enrollment), which
> is exactly the credential-free path `securetoken.sh` prefers.

## 1. Prepare the script

1. Open `scripts/securetoken.sh`.
2. Edit the **CONFIG BLOCK** near the top. For a Bootstrap-Token deployment
   that creates a hidden admin with a generated password:

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

   No admin credentials are needed — the Bootstrap Token grants the token.

   If the fleet is **not** Bootstrap-Token-escrowed, you must instead set
   `CONFIG_ADMIN_USER` / `CONFIG_ADMIN_PASSWORD` to an existing token-holding
   admin. Only do this if you accept storing that credential inside the
   uploaded script (Intune stores it encrypted at rest, but anyone who can read
   the policy can read the value). Prefer the Bootstrap Token.

3. (Optional) Confirm readiness first by uploading a copy with
   `CONFIG_ACTION="preflight"` — the Intune script log will show macOS version,
   MDM enrollment, `bootstrap tok : yes/no`, and current token holders.

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

- Intune surfaces the script's **exit code** as success (0) or failure
  (non-zero) per device under **Monitor → Device status**.
- The captured output includes the JSON result line (from `CONFIG_JSON="1"`) and
  the human-readable log. The same log is written on-device to
  `/var/log/securetoken.log`.
- If you used `CONFIG_GENERATE_PASSWORD="1"`, the generated password appears in
  the JSON result's `generatedPassword` field. Treat the Intune log as
  sensitive, or rotate/retrieve the password out of band.

## Requirements & notes

- macOS 10.13+ (Bootstrap Token path needs 10.15+).
- The script begins with `#!/bin/bash` and is written for the bash 3.2 that
  ships on macOS — no external dependencies.
- Exit codes are documented in the root [README](../../README.md) and
  [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md).
- Re-running is safe: an already-provisioned user yields exit `0` with no
  changes.
