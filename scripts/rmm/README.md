# Running SecureToken from an RMM

`securetoken.sh` is self-contained and fully non-interactive. Any RMM that can
run a shell script **as root** on macOS can deploy it: NinjaOne, Datto RMM,
Kaseya VSA, Addigy, Mosyle, Level, Syncro, Automox, ConnectWise Automate, etc.

## First: which credential model?

`sysadminctl` **cannot** grant a Secure Token without an existing token holder's
credentials ([Apple Platform Deployment guide](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web)).

| | Immediate grant | Deferred (first-login) grant |
|---|---|---|
| Needs | `ST_ADMIN_USER` + `ST_ADMIN_PASSWORD` (a token holder) | MDM-enrolled, macOS 11+, Bootstrap Token escrowed |
| Token exists | at end of run, verified | after the user's first login |
| Stores a secret? | yes — use a **secure** custom field | no |
| Result | `tokenMethod: "admin"` | `tokenMethod: "deferred-login"` |

Run `ST_ACTION=preflight ST_JSON=1` first; it reports
`firstLoginGrantAvailable` and `tokenHolders`.

## The interface: `ST_*` environment variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `ST_ACTION` | `create-user` (default), `grant-token`, `delete-user`, `status`, `list`, `preflight` | `create-user` |
| `ST_NEW_USER` | Username to create/target | `itadmin` |
| `ST_NEW_FULLNAME` | Display name | `IT Admin` |
| `ST_NEW_PASSWORD` | Password (omit + `ST_GENERATE_PASSWORD=1` to auto-generate) | `••••••` |
| `ST_GENERATE_PASSWORD` | `1` to generate and return a strong password | `1` |
| `ST_MAKE_ADMIN` | `1` for an administrator account | `1` |
| `ST_HIDDEN` | `1` for a hidden service account | `1` |
| `ST_ADMIN_USER` | Existing Secure Token holder (immediate grant) | `localadmin` |
| `ST_ADMIN_PASSWORD` | That admin's password — use a **secure** field | `••••••` |
| `ST_REQUIRE_IMMEDIATE_TOKEN` | `1` = a deferred grant is a failure (exit 23) | `1` |
| `ST_ROLLBACK_ON_FAILURE` | `1` = delete a just-created account if the grant fails | `1` |
| `ST_JSON` | `1` to emit one JSON result line on stdout | `1` |

Full option list in the [root README](../../README.md#configuration).

## Reading the result

With `ST_JSON=1`, the **last stdout line** is a JSON object:

```json
{"tool":"securetoken","version":"3.0.0","status":"ok","exitCode":0,"action":"create-user","user":"itadmin","tokenMethod":"admin","message":"user created and secure token granted"}
```

Human-readable, timestamped progress goes to **stderr** and to
`/var/log/securetoken.log`. Branch your policy on the **exit code**:

| Code | Meaning |
|------|---------|
| 0 | Success (or already in desired state — safe to re-run) |
| 2 | Invalid arguments/configuration |
| 10 | Not running as root |
| 11 | macOS/platform unsupported |
| 12 | Precondition failed (boot volume not APFS) |
| 20 | User creation failed |
| 21 | Secure Token grant failed |
| 22 | No admin credentials and no first-login grant available |
| 23 | Deferred to first login while `ST_REQUIRE_IMMEDIATE_TOKEN=1` |
| 24 | Another instance already running |
| 40 | Post-grant verification failed |

The tool is **idempotent** — re-running against an already-provisioned user exits
`0` without changes, so it is safe on a recurring schedule. A single-instance
lock prevents two overlapping runs from racing.

> A `deferred-login` result means the account exists but has **no token yet**.
> That is success, not failure. Verify after first login with `ST_ACTION=status`
> (the JSON reports `hasSecureToken`).

## NinjaOne

`ninjaone-wrapper.sh` maps NinjaOne Script Variables and Secure Custom Fields
onto the `ST_*` contract, forwards any arguments to the core, streams progress to
the activity feed, propagates the core's exit code unchanged, and can write the
JSON result back to a device custom field (`CUSTOM_FIELD_RESULT`).

Because it runs the core as root, it **refuses a core that is not root-owned or
that is group/world-writable**. Stage it accordingly:

```bash
sudo chown root:wheel /usr/local/cubit/securetoken.sh
sudo chmod 755 /usr/local/cubit/securetoken.sh
```

See the header comments in the wrapper for the field names to configure, and
[docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md) for the full walkthrough.
