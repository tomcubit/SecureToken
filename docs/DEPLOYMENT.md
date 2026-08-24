# Deployment Guide

How to run `securetoken.sh` unattended from Intune and common RMMs. Read the
[root README](../README.md) first — especially **how Secure Tokens are actually
granted**, which determines whether you need admin credentials.

---

## 0. Decide your credential model, then preflight

`sysadminctl` **cannot** grant a Secure Token without an existing token holder's
credentials. You therefore have two options:

| | Immediate grant | Deferred (first-login) grant |
|---|---|---|
| Needs | `ST_ADMIN_USER` + `ST_ADMIN_PASSWORD` (a token holder) | MDM-enrolled, macOS 11+, Bootstrap Token escrowed |
| Token exists | at end of the run, verified | after the user's first login |
| Stores a secret? | yes — use a secure field | no |
| Result | `tokenMethod: "admin"` | `tokenMethod: "deferred-login"` |

Run the read-only assessment on a representative device first:

```bash
sudo ST_ACTION=preflight ST_JSON=1 /bin/bash securetoken.sh
```

Key JSON fields: `bootstrapTokenEscrowed`, `firstLoginGrantAvailable`,
`tokenHolders`, `bootIsAPFS`. If `firstLoginGrantAvailable` is `false` and you
have no admin credentials, provisioning will exit **22** — fix one of those
first.

### Making a Bootstrap Token available

Escrow happens automatically when a supervised (ADE) Mac on macOS 10.15.4+ has a
Secure Token holder log in. To check or force it from a token-holding session:

```bash
sudo profiles status -type bootstraptoken
sudo profiles install -type bootstraptoken   # prompts for a token-holder credential
```

Note that `profiles status` only tells you the token reached the **server**.

---

## 1. Microsoft Intune

Intune runs one script, as root, with no per-run variables — so configure via the
CONFIG block at the top of the file and upload that single file.

1. **Edit** `scripts/securetoken.sh` CONFIG block. Deferred (no secrets in file):

   ```sh
   CONFIG_ACTION="create-user"
   CONFIG_NEW_USER="itadmin"
   CONFIG_NEW_FULLNAME="IT Admin"
   CONFIG_GENERATE_PASSWORD="1"
   CONFIG_MAKE_ADMIN="1"
   CONFIG_JSON="1"
   ```

   For an **immediate** grant, also set `CONFIG_ADMIN_USER` / `CONFIG_ADMIN_PASSWORD`.
   Only do this if you accept that the credential lives inside the uploaded
   script (Intune encrypts it at rest, but anyone who can read the policy can
   read the value).

2. **Intune admin center → Devices → macOS → Shell scripts → Add.**

   | Setting | Value |
   |---------|-------|
   | Upload script | your edited `securetoken.sh` |
   | Run script as signed-in user | **No** (must run as **root**) |
   | Script frequency | Not configured (once) — it is idempotent, so a repeat schedule is also safe |
   | Max retries | 3 |

3. **Assign** to a device group.

4. **Monitor → Device status** shows the exit code per device, plus captured
   output including the JSON result line. On-device log: `/var/log/securetoken.log`.

5. If you used `CONFIG_GENERATE_PASSWORD="1"`, the password is in the JSON
   result's `generatedPassword` field. Treat the Intune log as sensitive, or
   rotate the password out of band.

> **Deferred grants and Intune:** with no admin credentials the run exits 0 with
> `tokenMethod: "deferred-login"` and the account has **no token yet**. That is
> expected. Confirm after first login with a second policy running
> `CONFIG_ACTION="status"`.

---

## 2. NinjaOne

Deploy `scripts/rmm/ninjaone-wrapper.sh` **together with** `scripts/securetoken.sh`
(same directory), or set `ST_CORE` to where you staged the core.

1. Stage both files, e.g. to `/usr/local/cubit/`. The wrapper **refuses to run a
   core that is not root-owned or that is group/world-writable**, so ensure:
   ```bash
   sudo chown root:wheel /usr/local/cubit/securetoken.sh
   sudo chmod 755 /usr/local/cubit/securetoken.sh
   ```
2. Create a **Mac Script** policy running `ninjaone-wrapper.sh` as root.
3. Add **Script Variables**: `ST_NEW_USER`, `ST_NEW_FULLNAME`, `ST_MAKE_ADMIN=1`,
   `ST_GENERATE_PASSWORD=1`, `ST_JSON=1`.
4. For an **immediate** grant, create a **secure custom field** for the admin
   password and set `CUSTOM_FIELD_ADMIN_PW` in the wrapper to that field's name.
   The wrapper reads it at runtime via `ninjarmm-cli get`, so it never sits in
   the policy body. Also set `ST_ADMIN_USER`.
5. (Optional) Set `CUSTOM_FIELD_RESULT` to write the JSON outcome back to a
   device field for reporting.

The wrapper forwards any arguments to the core (so a Preset Parameter such as
`preflight` works), streams progress to the activity feed, and **propagates the
core's exit code unchanged** so pass/fail is accurate.

---

## 3. Generic RMM (Datto, Kaseya, Addigy, Mosyle, Level, Syncro, Automox, …)

1. Deploy `securetoken.sh` to the device (or paste it into the script body).
2. Set the `ST_*` variables using the RMM's script-variable feature (admin
   password in a **secure/masked** field).
3. Run as root:
   ```bash
   /bin/bash /path/to/securetoken.sh
   ```
4. Branch on the exit code (see README). With `ST_JSON=1`, parse the **last
   stdout line** as JSON.

For platforms that pass arguments rather than environment variables:

```bash
/bin/bash securetoken.sh create-user \
  --new-user itadmin --make-admin --generate-password --json \
  --admin-user localadmin --admin-password '…'
```

---

## 3.5 Verify script integrity before deploying

This script runs **as root** on every device you send it to, so treat it as a
supply-chain artefact rather than a snippet to paste around.

Record the digest once, at packaging time, from a copy you trust:

```bash
shasum -a 256 scripts/securetoken.sh
# e.g. 9f2c…  scripts/securetoken.sh
```

Then verify on the device (or in the staging step of your RMM policy) before it
is executed:

```bash
echo "<expected-digest>  /usr/local/cubit/securetoken.sh" | shasum -a 256 --check
```

Also ensure the staged copy cannot be modified by a non-root user — the NinjaOne
wrapper enforces this and refuses to run a core that is not root-owned or is
group/world-writable:

```bash
sudo chown root:wheel /usr/local/cubit/securetoken.sh
sudo chmod 755 /usr/local/cubit/securetoken.sh
```

For Intune the uploaded script is delivered by the MDM channel, so the digest
check is mainly for confirming that what you uploaded is what you reviewed.

## 4. Rollout checklist

- [ ] Script digest verified against the reviewed copy (§3.5).
- [ ] `preflight` passes on a pilot device; note `firstLoginGrantAvailable`.
- [ ] Provision **one** pilot device.
- [ ] If `tokenMethod` was `admin`: confirm immediately with
      `sudo sysadminctl -secureTokenStatus <user>` → `ENABLED`.
- [ ] If `tokenMethod` was `deferred-login`: log in as the new user once, then
      confirm the token appeared.
- [ ] Confirm the new user can unlock FileVault (restart and unlock as them).
- [ ] Confirm exit-code handling/reporting in your RMM or Intune console.
- [ ] Capture or rotate any `generatedPassword` from the result securely.
- [ ] Roll out to a small ring, then the fleet.

---

## 5. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Exit 10 | Not root — enable "run as root" in the policy. |
| Exit 11 | macOS < 10.13, or not macOS. |
| Exit 12 | Boot volume not APFS. Secure Tokens require APFS. |
| Exit 22 | No admin credentials and no first-login grant available. Supply `ST_ADMIN_USER`/`ST_ADMIN_PASSWORD` (must already hold a token), or fix Bootstrap Token escrow. |
| Exit 23 | Token deferred to first login while `ST_REQUIRE_IMMEDIATE_TOKEN=1`. Supply admin credentials, or drop the flag. |
| Exit 24 | Another run is in progress. Check for an overlapping schedule; stale locks from dead processes are reaped automatically. |
| Exit 20 with "password does not authenticate" | The secret was not delivered as intended. Ensure `ST_SECRET_MODE` is `inline` (the default) — `stdin` needs a TTY. |
| Exit 21 / 40 | Grant or verification failed. Check `/var/log/securetoken.log`. On Apple Silicon confirm a volume owner exists (`diskutil apfs listUsers /`). |
| Job hangs, then times out | An interactive prompt in a headless session. Use the default `inline` secret mode; the watchdog (`ST_TIMEOUT`) caps each call. |
| Grant fails for a pre-existing user | The supplied password must match that account's real password; the tool cannot know it. |
