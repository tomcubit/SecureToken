# Running SecureToken from an RMM

`securetoken.sh` is self-contained and fully non-interactive. Any RMM that can
run a shell script **as root** on macOS can deploy it: NinjaOne, Datto RMM,
Kaseya VSA, Addigy, Mosyle, Level, Syncro, Automox, ConnectWise Automate, etc.

## The interface: `ST_*` environment variables

Point your RMM's script-variable / custom-field feature at these names. Every
option has an `ST_`-prefixed environment variable (see the table in the root
[README](../../README.md) and full details in
[docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)).

| Variable | Purpose | Example |
|----------|---------|---------|
| `ST_ACTION` | `create-user` (default), `grant-token`, `status`, `list`, `preflight` | `create-user` |
| `ST_NEW_USER` | Username to create/target | `itadmin` |
| `ST_NEW_FULLNAME` | Display name | `IT Admin` |
| `ST_NEW_PASSWORD` | Password (omit + `ST_GENERATE_PASSWORD=1` to auto-generate) | `••••••` |
| `ST_GENERATE_PASSWORD` | `1` to generate and return a strong password | `1` |
| `ST_MAKE_ADMIN` | `1` for an administrator account | `1` |
| `ST_HIDDEN` | `1` for a hidden service account | `1` |
| `ST_ADMIN_USER` | Existing Secure Token admin (only if **no** Bootstrap Token) | `localadmin` |
| `ST_ADMIN_PASSWORD` | That admin's password (use a **secure** field) | `••••••` |
| `ST_JSON` | `1` to emit one JSON result line on stdout for parsing | `1` |

## Two credential models

### 1. Bootstrap Token (recommended — no passwords)

If the Mac is MDM-enrolled and has escrowed a Bootstrap Token, you need **no
admin credentials at all**. Set only the new-user fields and run. `securetoken.sh`
detects the Bootstrap Token and grants the Secure Token with it.

```
ST_ACTION=create-user
ST_NEW_USER=itadmin
ST_MAKE_ADMIN=1
ST_GENERATE_PASSWORD=1
ST_JSON=1
```

Run `ST_ACTION=preflight` first to confirm `bootstrap tok : yes`.

### 2. Existing Secure Token admin (fallback)

Without a Bootstrap Token, supply an existing token-holding admin. Store the
password in a **secure/masked custom field**, never in the script body.

```
ST_ACTION=create-user
ST_NEW_USER=itadmin
ST_NEW_PASSWORD=<secure field>
ST_ADMIN_USER=localadmin
ST_ADMIN_PASSWORD=<secure field>
ST_JSON=1
```

## Reading the result

With `ST_JSON=1`, the **last stdout line** is a JSON object:

```json
{"tool":"securetoken","version":"2.0.0","status":"ok","exitCode":0,"action":"create-user","user":"itadmin","tokenMethod":"bootstrap","message":"user created and secure token granted"}
```

Human-readable, timestamped progress goes to **stderr** and to
`/var/log/securetoken.log`. Branch your RMM policy on the **exit code**:

| Code | Meaning |
|------|---------|
| 0 | Success (or already in desired state — safe to re-run) |
| 2 | Invalid arguments/configuration |
| 10 | Not running as root |
| 11 | macOS/platform unsupported |
| 12 | Precondition failed (boot volume not APFS) |
| 20 | User creation failed |
| 21 | Secure Token grant failed |
| 22 | No Bootstrap Token and no valid Secure Token admin |
| 40 | Post-grant verification failed |

The tool is **idempotent** — re-running against an already-provisioned user
exits `0` without changes, so it is safe on a recurring schedule.

## NinjaOne

`ninjaone-wrapper.sh` in this folder maps NinjaOne Script Variables and Secure
Custom Fields onto the `ST_*` contract, runs the core, and (optionally) writes
the JSON result back to a device custom field. Deploy it alongside
`securetoken.sh` (or set `ST_CORE` to the staged path). See the header comments
for the field names to configure.
