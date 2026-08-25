# SecureToken — Engineer Test Handover

| | |
|---|---|
| **Project** | SecureToken — unattended macOS Secure Token provisioning for RMM / Intune |
| **Repo / branch** | `tomcubit/SecureToken` → `claude/automate-mac-token-transfer-HU7CC` |
| **Version under test** | **3.1.0** (shell core and Swift CLI, kept in lockstep) |
| **Commit under test** | `00c3848` — re-record this if you pull a newer commit |
| **Status** | All automated tests green (75 unit + 66 integration on Linux). **Not yet piloted on a real Mac** — that is the main job of this handover. |
| **Owner** | Tom Cubit (tom@cubittech.com) |

---

## 1. What this tool does (60-second version)

Creates a local macOS account and ensures it ends up holding a **Secure Token**
(required to unlock FileVault), with zero prompts, so it can run from NinjaOne
or Intune as root.

The design is driven by two facts from Apple's
[Platform Deployment guide](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web)
— read these before testing, because they define "correct":

1. `sysadminctl` **always requires an existing Secure Token admin's username and
   password** to change token status. There is no credential-free grant.
2. On macOS 11+ with an MDM-escrowed **Bootstrap Token**, macOS grants the token
   itself **at the user's first login** — not at provisioning time.

So the tool has exactly two paths, and every test below exercises one of them:

| Path | You supply | Token appears | JSON `tokenMethod` |
|---|---|---|---|
| **admin** | `ST_ADMIN_USER` + `ST_ADMIN_PASSWORD` (a token holder) | during the run, verified | `"admin"` |
| **deferred** | nothing (Mac must be MDM-enrolled, macOS 11+, Bootstrap Token escrowed) | at the user's first login | `"deferred-login"` |

> **History note:** v2 of this tool believed `sysadminctl` could spend the
> Bootstrap Token credential-free at provisioning time. That is impossible and
> was removed in v3. The mock test suite contains a regression tripwire for it.

---

## 2. File inventory (everything you need is in the repo)

```
SecureToken/
├── scripts/
│   ├── securetoken.sh              ← THE deliverable. Self-contained bash 3.2 core.
│   ├── secure-token-transfer.sh    ← deprecated v1 shim; forwards to the core
│   ├── rmm/
│   │   ├── ninjaone-wrapper.sh     ← NinjaOne wrapper (custom fields, exit-code passthrough)
│   │   └── README.md               ← RMM interface + credential models
│   └── intune/
│       └── README.md               ← Intune portal walkthrough (CONFIG-block model)
├── tests/
│   ├── securetoken_test.sh         ← 75 unit assertions (pure logic; any OS)
│   ├── integration_test.sh         ← 66 end-to-end assertions (Linux + root + mocks)
│   └── mocks/
│       └── install-mocks.sh        ← installs the mock macOS command set (Linux only)
├── Sources/SecureToken/
│   ├── SecureTokenCLI.swift        ← optional Swift CLI (@main lives here)
│   └── SecureTokenManager.swift    ← Swift core (near-parity: no delete-user;
│                                      adds an interactive mode the shell lacks)
├── Tests/SecureTokenTests/
│   └── SecureTokenTests.swift      ← Swift unit tests (swift test, macOS)
├── docs/
│   ├── HANDOVER.md                 ← this document
│   ├── DEPLOYMENT.md               ← Intune / NinjaOne / generic-RMM deployment guide
│   └── API.md                      ← actions, JSON contract, exit codes, library refs
├── .github/workflows/ci.yml        ← 4 CI jobs (see §7)
├── Package.swift                   ← SwiftPM manifest (macOS 10.13 target)
├── README.md                       ← start here for concepts + config table
├── CHANGELOG.md                    ← 3.1.0 / 3.0.0 / 2.0.0 history incl. bugs found
├── LICENSE                         ← MIT
└── .gitignore
```

**The shell core is the supported RMM/Intune path.** The Swift CLI is an
optional local convenience and has never been exercised on a real Mac.

---

## 3. The contract you are testing against

### Exit codes (stable; RMM policies branch on these)

| Code | Meaning |
|---|---|
| 0 | Success, **or already in desired state** (idempotent) |
| 2 | Invalid arguments / configuration |
| 10 | Not root |
| 11 | Platform unsupported (not macOS / < 10.13 / preflight found blockers) |
| 12 | Precondition failed (boot volume not APFS, no randomness) |
| 20 | User creation failed (incl. "password did not authenticate after create"; also a failed `delete-user`, and a watchdog timeout during the **create** call) |
| 21 | Token grant failed (incl. a watchdog timeout during the **grant** call) |
| 22 | No viable token source: admin credentials missing, wrong, for a non-existent admin, or for an admin without a token — and no Bootstrap Token first-login grant available |
| 23 | Deferred grant while `ST_REQUIRE_IMMEDIATE_TOKEN=1` — **no account is created** |
| 24 | Another instance already running (lock at `/var/run/securetoken.lock`) |
| 40 | Post-operation verification failed (`sysadminctl` claimed success but the token is absent; also: user still present after `delete-user`) |

> Exit 12 also covers `mktemp` failure and a `dscl` enumeration failure during
> `list`. One caveat for parsers: usage errors caught **before** configuration is
> resolved — unknown option, a value-taking flag with no value, an invalid
> `--secret-mode` — exit 2 with usage on **stderr and no JSON line**. Treat
> "exit 2 + no JSON" as a configuration error in RMM logic.

### JSON result (with `--json` / `ST_JSON=1`: one line on stdout — shown wrapped here)

```json
{"tool":"securetoken","version":"3.1.0","status":"ok","exitCode":0,
 "action":"create-user","user":"itadmin","tokenMethod":"admin",
 "message":"user created and secure token granted"}
```

- `tokenMethod` ∈ `admin` | `deferred-login` | `existing` | `none`
- `preflight` adds `macosVersion, arch, isRoot, bootIsAPFS, mdmEnrolled,
  bootstrapTokenEscrowed, firstLoginGrantAvailable, userEnumerationOk, tokenHolders[]`
- `status` adds `userExists, hasSecureToken`; `list` adds `tokenHolders[]`
- `generatedPassword` appears **only after it was actually applied** to the
  account — including on later failures (so the credential is never lost).
  Treat any log containing it as sensitive.

Human-readable progress goes to **stderr** and `/var/log/securetoken.log`
(created 0600; symlink/hard-link refused; rotated past 1 MB). Passwords are
never logged.

### Configuration precedence

`CLI flag → ST_* env var → CONFIG_* block (top of script) → default`.
Full variable table: [README.md §Configuration](../README.md#configuration).

---

## 4. Test campaign overview

Run the phases **in order**. Each phase gates the next.

| Phase | Where | Time | Proves |
|---|---|---|---|
| A. Static + unit | any machine | 2 min | script integrity, pure logic |
| B. Integration vs mock macOS | disposable Linux (VM/container) | 5 min | end-to-end behaviour vs Apple's documented rules |
| C. CI review | GitHub Actions tab | 5 min | Swift compiles; suite passes on real bash 3.2 |
| D. Swift on a Mac | any Mac with Xcode CLT | 10 min | Swift CLI builds and unit-tests locally |
| E. **Real-Mac pilot** | dedicated test Mac | 1–2 h | real `sysadminctl` behaviour — **the critical phase** |
| F. RMM / Intune pilot | NinjaOne + Intune, 1 device each | 1 h | delivery, exit-code reporting, secure fields |

---

## 5. Phase A — static checks + unit tests (any machine)

```bash
git clone https://github.com/tomcubit/SecureToken.git
cd SecureToken
git checkout claude/automate-mac-token-transfer-HU7CC

# Syntax + lint (shellcheck ≥ 0.9; brew install shellcheck / apt install shellcheck)
bash -n scripts/securetoken.sh
shellcheck -s bash scripts/securetoken.sh scripts/rmm/ninjaone-wrapper.sh \
    scripts/secure-token-transfer.sh tests/securetoken_test.sh \
    tests/integration_test.sh tests/mocks/install-mocks.sh

# Unit suite — no root needed, runs on macOS or Linux
bash tests/securetoken_test.sh
```

**Expected:** shellcheck reports nothing; suite ends `RESULT: 75 passed, 0 failed`
and exits 0. On a Mac, also run it under the system shell explicitly —
`/bin/bash tests/securetoken_test.sh` — to prove bash 3.2 compatibility yourself.

---

## 6. Phase B — integration tests against the mock macOS (disposable Linux only)

The mocks emulate `sysadminctl`/`dscl`/`profiles`/`sw_vers`/`diskutil` with
Apple's documented semantics (credential-free grants refused; `-` passwords
block like a real headless prompt; `sysadminctl` exiting 0 on failure).

> ⚠️ **Disposable machines only** (throwaway VM, container, CI runner): the
> installer writes mock commands into `/usr/bin` and `/usr/sbin` and wraps
> `uname`. Never run it on a workstation you care about. It refuses to run on
> macOS.

```bash
sudo bash tests/mocks/install-mocks.sh
sudo bash tests/integration_test.sh
```

**Expected:** `RESULT: 66 passed, 0 failed`, exit 0, ~1 minute (two watchdog
tests deliberately wait a few seconds each). The suite covers: every action;
exit codes 0, 2, 11, 12, 21, 22, 23, 24 and 40 (10 not-root and 20
create-failed are exercised by the unit suite and the real-Mac pilot instead);
strict JSON parsing; idempotent re-runs; orphan
prevention (bad admin password / tokenless admin / `--require-immediate` all
fail **before** an account exists); the silent-`sysadminctl`-lie → exit 40 path;
watchdog kills of blocking prompts; rollback; generated-password recovery after
late failures; hidden-account UID range (200–499); lock liveness and staleness;
system-account filtering.

---

## 7. Phase C — review the CI run (GitHub Actions)

Open the repo's **Actions** tab for the latest run on this branch. Four jobs:

| Job | Runner | Proves |
|---|---|---|
| `Shell — shellcheck + unit tests` | ubuntu | Phase A, automated |
| `Shell — end-to-end against mock macOS` | ubuntu | Phase B, automated |
| `Swift — build + test (macOS)` | macos | **the Swift package compiles** and its unit tests pass — this is currently the only place Swift has ever been built |
| `Shell — run tests on macOS bash 3.2` | macos | unit suite under the real `/bin/bash` 3.2, plus `--help`/`--version` smoke |

**If the Swift job is red:** the shell deliverable is unaffected (it has no
build step). Capture the compiler output into an issue; the Swift CLI must not
be used until it is green.

Note: the Linux CI job lints the two scripts and two of the test files; the
Phase A command above shellchecks all **six** shell files — run it manually at
least once rather than relying on CI alone.

---

## 8. Phase D — Swift build on a Mac (optional CLI)

```bash
xcode-select --install   # if Command Line Tools are missing
cd SecureToken
swift build 2>&1 | tee /tmp/st-swift-build.log
swift test  2>&1 | tee /tmp/st-swift-test.log

# Smoke the binary (no root needed for these two)
.build/debug/securetoken --version        # → 3.1.0
.build/debug/securetoken --help
```

**Expected:** clean build; all tests pass; version prints `3.1.0`.
Known risk: this code was written without a compiler available — minor compile
fixes may be needed. Anything beyond trivial: file an issue rather than
diverging from the shell core's behaviour.

---

## 9. Phase E — real-Mac pilot (THE critical phase)

### 9.1 Test machine requirements

- A **dedicated, disposable test Mac** (or a fresh macOS VM — see caveats
  below). Never a production machine or your own workstation.
- macOS 13+ recommended (contract supports 10.13+), APFS boot volume (default).
- One admin account created via Setup Assistant — it holds a Secure Token
  automatically. This is your `ST_ADMIN_USER` ("`testadmin`" below).
- For the **deferred-path** tests only: the Mac must be MDM-enrolled
  (ADE/supervised) with a Bootstrap Token escrowed. Without MDM you can still
  fully test the admin path — the deferred path will correctly refuse (exit 22).

> **VM caveats:** an Apple-silicon macOS VM works for the admin path. Bootstrap
> Token behaviour requires real MDM enrollment; only test the deferred path on
> an enrolled device. FileVault-unlock verification (step 9.4) is only
> meaningful with FileVault turned on.

### 9.2 Stage the tool

```bash
# On the test Mac
git clone https://github.com/tomcubit/SecureToken.git && cd SecureToken
git checkout claude/automate-mac-token-transfer-HU7CC
sudo cp scripts/securetoken.sh /usr/local/bin/securetoken.sh
sudo chown root:wheel /usr/local/bin/securetoken.sh
sudo chmod 755 /usr/local/bin/securetoken.sh
shasum -a 256 /usr/local/bin/securetoken.sh   # record this digest in your notes
```

### 9.3 Scripted scenarios — run in this order

Record for every step: **exit code** (`echo $?`), the **JSON line**, and any
surprise in `/var/log/securetoken.log`. Expected values are the contract;
any deviation on real macOS is exactly what this pilot exists to find.

```bash
cd /usr/local/bin

# E1. Preflight (read-only)                                    → exit 0 (or 11 if not ready)
sudo ST_JSON=1 ./securetoken.sh preflight; echo "rc=$?"
#   Check: macosVersion/arch correct; tokenHolders lists testadmin;
#   firstLoginGrantAvailable matches your MDM reality.

# E2. Create user, ADMIN path, generated password              → exit 0, tokenMethod=admin
sudo ST_JSON=1 ./securetoken.sh create-user \
  --new-user stpilot1 --new-fullname "ST Pilot One" --make-admin \
  --generate-password \
  --admin-user testadmin --admin-password 'THE-REAL-PW'; echo "rc=$?"
#   SAVE the generatedPassword from the JSON. Then verify independently:
sudo sysadminctl -secureTokenStatus stpilot1            # → ENABLED
dscl . -authonly stpilot1 '<generatedPassword>'         # → silent success

# E3. Idempotent re-run                                        → exit 0, "already provisioned"
sudo ST_JSON=1 ./securetoken.sh create-user \
  --new-user stpilot1 --new-password anything123 \
  --admin-user testadmin --admin-password 'THE-REAL-PW'; echo "rc=$?"

# E4. Wrong admin password — MUST NOT create an account        → exit 22
sudo ST_JSON=1 ./securetoken.sh create-user \
  --new-user stpilot2 --new-password 'Pilot2pw!' \
  --admin-user testadmin --admin-password 'WRONG'; echo "rc=$?"
dscl . -read /Users/stpilot2 && echo "FAIL: orphan created" || echo "OK: no orphan"

# E5. status / list                                            → exit 0
sudo ST_JSON=1 ./securetoken.sh status --new-user stpilot1; echo "rc=$?"   # hasSecureToken:true
sudo ST_JSON=1 ./securetoken.sh list; echo "rc=$?"                          # holders incl. stpilot1

# E6. grant-token to a pre-existing tokenless user
sudo sysadminctl -addUser stplain -password 'Plainpw1!'     # create WITHOUT token, directly
sudo ST_JSON=1 ./securetoken.sh grant-token \
  --new-user stplain --new-password 'Plainpw1!' \
  --admin-user testadmin --admin-password 'THE-REAL-PW'; echo "rc=$?"       # → 0
sudo sysadminctl -secureTokenStatus stplain                                  # → ENABLED

# E7. Hidden service account                                   → exit 0, UID 200–499
sudo ST_JSON=1 ./securetoken.sh create-user \
  --new-user sthidden --new-password 'Hidden1pw!' --hidden \
  --admin-user testadmin --admin-password 'THE-REAL-PW'; echo "rc=$?"
dscl . -read /Users/sthidden UniqueID IsHidden
#   Log out once: sthidden must NOT appear at the login window.

# E8. DEFERRED path (MDM-enrolled Macs only)                   → exit 0, tokenMethod=deferred-login
sudo ST_JSON=1 ./securetoken.sh create-user \
  --new-user stdefer --generate-password; echo "rc=$?"
sudo sysadminctl -secureTokenStatus stdefer                  # → DISABLED (expected — no login yet)
#   Log in once as stdefer (fast user switching is fine), then:
sudo sysadminctl -secureTokenStatus stdefer                  # → ENABLED  ← the key macOS behaviour
#   On an UNenrolled Mac instead expect: exit 22, no account created.

# E9. require-immediate refuses a deferred-only plan           → exit 23, NO account
sudo ST_JSON=1 ./securetoken.sh create-user \
  --new-user stnope --generate-password --require-immediate; echo "rc=$?"
dscl . -read /Users/stnope && echo "FAIL: orphan" || echo "OK"
#   (On an unenrolled Mac with no creds this is exit 22 instead — also correct.)

# E10. Lock                                                     → second run exits 24
sudo mkdir /var/run/securetoken.lock && echo $$ | sudo tee /var/run/securetoken.lock/pid
sudo ST_JSON=1 ./securetoken.sh create-user --new-user stlock --new-password 'x1234' \
  --admin-user testadmin --admin-password 'THE-REAL-PW'; echo "rc=$?"        # → 24
sudo rm -rf /var/run/securetoken.lock

# E11. Log hygiene
sudo ls -l /var/log/securetoken.log        # → -rw------- root (0600)
# The log may mention the WORD "password"; the VALUES must never appear:
sudo grep -c 'THE-REAL-PW' /var/log/securetoken.log          # → 0
sudo grep -c '<generatedPassword from E2>' /var/log/securetoken.log   # → 0

# E12. Cleanup                                                  → exit 0 each
for u in stpilot1 stplain sthidden stdefer; do
  sudo ST_JSON=1 ./securetoken.sh delete-user --new-user "$u"; echo "$u rc=$?"
done
```

### 9.4 FileVault verification (the business outcome)

On a FileVault-enabled test Mac, after E2: **restart** and confirm `stpilot1`
can unlock the disk at the pre-boot screen with the generated password. This is
the end-goal the token exists for.

### 9.5 Also worth probing on real macOS

- `--secret-mode stdin` from an SSH session (has a TTY): should prompt. From a
  `launchd`/RMM context it should time out at `ST_TIMEOUT` — use **`grant-token`**
  for this probe and expect exit **21**; with `create-user` the timeout hits the
  create call first and reports exit **20**. Either confirms the watchdog.
- The `ps` window: while E2 runs, `ps aux | grep sysadminctl` from another
  shell — you should see the password briefly (documented `inline` trade-off).
  This is accepted behaviour, not a bug; note it for the security review.
- macOS 26.x device if available (version-parsing sanity).

---

## 10. Phase F — RMM / Intune pilots (one device each)

Follow **[docs/DEPLOYMENT.md](DEPLOYMENT.md)** step-by-step — it is the
authoritative guide. Summary of what to verify:

**NinjaOne** (`scripts/rmm/ninjaone-wrapper.sh` + core staged together):
- Script Variables map through (`ST_NEW_USER` etc.); admin password arrives via
  a **secure custom field** (`CUSTOM_FIELD_ADMIN_PW` → `ninjarmm-cli get`).
- Activity feed shows stderr progress live; last stdout line is the JSON.
- Policy pass/fail matches the exit code exactly (the wrapper propagates it).
- `CUSTOM_FIELD_RESULT` (if configured) receives the JSON via `--stdin`.
- The wrapper **refuses** a core that isn't root-owned / is group-writable —
  test that guard once by `chmod 777` on the staged core (then fix it back).

**Intune** (single-file CONFIG-block model):
- Edit CONFIG block → upload → **Run as signed-in user: No** → assign to a
  one-device group.
- Device status shows success/failure per the exit code; captured output
  contains the JSON line; `generatedPassword` present → treat log as sensitive.
- Re-run frequency safe (idempotency proven in E3).

---

## 11. Known limitations & open items (read before signing off)

1. **The Swift CLI has never run on a real Mac.** Compile status comes from CI
   (§7). It is optional; the shell core is the deliverable.
2. **`inline` secret mode exposes the password in `ps` for the duration of the
   `sysadminctl` call.** This is Apple's documented scripting path; the
   alternative (`stdin`) prompts a TTY and cannot work headless. Accepted
   trade-off — confirm your security stance.
3. **Mocks encode documented behaviour, not build quirks.** Real macOS output
   strings for `sysadminctl`/`profiles` vary by version; if a pilot step fails
   on string-matching (e.g. token shows ENABLED but the tool says otherwise),
   capture the raw command output — that's a parsing bug to file.
4. **Deferred path ≠ token now.** `deferred-login` + exit 0 means "account
   ready, token at first login". If your workflow needs the token before any
   login (e.g. escrowing FileVault recovery via that account immediately), use
   the admin path or `ST_REQUIRE_IMMEDIATE_TOKEN=1`.
5. **`generatedPassword` lands in RMM/Intune logs.** By design (it must be
   recoverable). Decide retention/rotation policy before fleet rollout.
6. **Reserved usernames** (`root`, `admin`, `daemon`, …) and non-ASCII
   usernames are rejected by validation — expected, not a bug.

---

## 12. Sign-off checklist

| # | Item | Result / initials |
|---|---|---|
| 1 | Phase A: shellcheck clean + 75/75 unit (incl. under macOS `/bin/bash`) | |
| 2 | Phase B: 66/66 integration on disposable Linux | |
| 3 | Phase C: all 4 CI jobs green (link the run) | |
| 4 | Phase D: `swift build` + `swift test` clean on a Mac | |
| 5 | E1–E7, E10–E12 pass on a real Mac (admin path) | |
| 6 | E8–E9 pass on an MDM-enrolled Mac (deferred path) — or waived with reason | |
| 7 | 9.4 FileVault pre-boot unlock confirmed with provisioned account | |
| 8 | NinjaOne one-device pilot: variables, secure field, exit-code reporting | |
| 9 | Intune one-device pilot: CONFIG model, device status, log sensitivity noted | |
| 10 | Security review of §11 items 2 & 5 accepted | |
| 11 | Staged-script SHA-256 recorded; ownership/perms locked (root:wheel, 755) | |

**Rollout only after every row is initialled.** Suggested ring plan:
1 pilot → 5-device ring → fleet.

---

## 13. If something fails

1. Grab the **exit code**, the **JSON line**, `/var/log/securetoken.log`, and
   (for grant issues) the raw output of
   `sudo sysadminctl -secureTokenStatus <user>` and
   `sudo profiles status -type bootstraptoken`.
2. Check the troubleshooting table in [DEPLOYMENT.md §5](DEPLOYMENT.md).
3. File an issue on the repo with the above; tag the commit hash you tested.

Quick references: [README.md](../README.md) · [DEPLOYMENT.md](DEPLOYMENT.md) ·
[API.md](API.md) · [CHANGELOG.md](../CHANGELOG.md)
