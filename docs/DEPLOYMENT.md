# Deployment Guide

How to run `securetoken.sh` unattended from Intune and common RMMs. Read the
[root README](../README.md) first for the configuration table and exit codes.

---

## 0. Preflight everywhere first

Before provisioning, run the assessment action on a representative device. It is
read-only and safe:

```bash
sudo ST_ACTION=preflight ST_JSON=1 /bin/bash securetoken.sh
```

Look for:

- `secure token  : supported`
- `bootstrap tok : yes` → you can provision **credential-free**.
- `bootstrap tok : no`  → you must supply `ST_ADMIN_USER` / `ST_ADMIN_PASSWORD`
  (an existing Secure Token holder), or fix Bootstrap Token escrow first.

### Making the Bootstrap Token available

A Bootstrap Token is generated and escrowed to your MDM automatically when a
supervised Mac (ADE/Automated Device Enrollment) has a Secure Token holder log
in, on macOS 10.15+. To (re)escrow manually on a token-holding admin session:

```bash
sudo profiles install -type bootstraptoken
sudo profiles status  -type bootstraptoken   # confirm "escrowed to server: YES"
```

---

## 1. Microsoft Intune

Intune runs one script, as root, with no per-run variables — so configure via
the script's CONFIG block and upload the single file.

1. **Edit** `scripts/securetoken.sh` CONFIG block (top of file). Bootstrap-Token
   example (no secrets in the file):

   ```sh
   CONFIG_ACTION="create-user"
   CONFIG_NEW_USER="itadmin"
   CONFIG_NEW_FULLNAME="IT Admin"
   CONFIG_GENERATE_PASSWORD="1"
   CONFIG_MAKE_ADMIN="1"
   CONFIG_JSON="1"
   ```

2. **Intune admin center → Devices → macOS → Shell scripts → Add.**
   - Upload the edited `securetoken.sh`.
   - **Run script as signed-in user: No** (runs as root).
   - Script frequency: *Not configured* (once) — it is idempotent, so a repeat
     schedule is also safe.
   - Max retries: 3.

3. **Assign** to a device group.

4. **Monitor → Device status** shows success (exit 0) / failure per device, plus
   the captured output (including the JSON result line). On-device log:
   `/var/log/securetoken.log`.

Full notes: [`scripts/intune/README.md`](../scripts/intune/README.md).

---

## 2. NinjaOne

Deploy `scripts/rmm/ninjaone-wrapper.sh` **with** `scripts/securetoken.sh`
(place them together, or set `ST_CORE` to the staged path).

1. Copy both files to the device (e.g. via a NinjaOne "File" deployment to
   `/usr/local/cubit/`), or paste `securetoken.sh` and reference it.
2. Create a **Mac Script** policy that runs `ninjaone-wrapper.sh` as root.
3. Add **Script Variables** named `ST_NEW_USER`, `ST_NEW_FULLNAME`,
   `ST_MAKE_ADMIN=1`, `ST_GENERATE_PASSWORD=1`, `ST_JSON=1`.
4. Only if you have **no** Bootstrap Token: create a **secure custom field**
   for the admin password and set `CUSTOM_FIELD_ADMIN_PW` (and optionally
   `CUSTOM_FIELD_NEW_PW`) in the wrapper to that field's name. The wrapper reads
   it at runtime with `ninjarmm-cli get`, so it is never stored in the policy
   body.
5. (Optional) Set `CUSTOM_FIELD_RESULT` to write the JSON outcome back to a
   device field for reporting.

The wrapper echoes the JSON result to the NinjaOne activity feed and exits with
the core's exit code so the policy shows pass/fail correctly.

---

## 3. Generic RMM (Datto, Kaseya, Addigy, Mosyle, Level, Syncro, Automox, …)

Any RMM that runs a root shell script works:

1. Deploy `securetoken.sh` to the device (or paste it into the script body).
2. Set the `ST_*` variables using the RMM's environment-variable / script-
   variable feature (store the admin password in a **secure** field).
3. Run:

   ```bash
   /bin/bash /path/to/securetoken.sh
   ```

4. Branch on the exit code (see README). Parse the last stdout line as JSON when
   `ST_JSON=1`.

For platforms that manage a **script + arguments** rather than env vars, pass
flags instead:

```bash
/bin/bash securetoken.sh create-user \
  --new-user itadmin --make-admin --generate-password --json
```

---

## 4. Rollout checklist

- [ ] `preflight` passes on a pilot device; note bootstrap-token availability.
- [ ] Provision **one** pilot device; confirm the new user can unlock FileVault
      (log out / restart and unlock with the new account).
- [ ] Verify `sudo sysadminctl -secureTokenStatus <user>` shows `ENABLED`.
- [ ] Confirm exit code handling / reporting in your RMM or Intune console.
- [ ] Roll out to a small ring, then the fleet.
- [ ] If you used `ST_GENERATE_PASSWORD`, capture/rotate the generated password
      from the JSON result securely.

---

## 5. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Exit 10 | Not root — enable "run as root" in the RMM/Intune policy. |
| Exit 11 | macOS < 10.13, or not macOS. |
| Exit 12 | Boot volume not APFS — Secure Tokens require APFS. |
| Exit 22 | No Bootstrap Token and no valid admin. Escrow a Bootstrap Token, or supply `ST_ADMIN_USER`/`ST_ADMIN_PASSWORD` (must already hold a token). |
| Exit 21/40 | Grant/verify failed. Check `/var/log/securetoken.log`. On a given macOS build, try `ST_STDIN_SECRETS=0` to rule out a stdin-feeding quirk. On Apple Silicon confirm a volume owner exists (`diskutil apfs listUsers /`). |
| Grant fails only for a pre-existing user | The supplied password must match that account's real password; the tool cannot know an existing user's password. |
