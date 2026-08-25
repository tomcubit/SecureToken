#!/bin/bash
#
# tests/integration_test.sh — END-TO-END tests of scripts/securetoken.sh against
# the mock macOS command set from tests/mocks/install-mocks.sh.
#
# Unlike tests/securetoken_test.sh (pure functions), this executes the real
# script binary-style — argument parsing, config resolution, locking, the
# sysadminctl/dscl call sequence, JSON emission and process exit codes — with
# the mocks faithfully enforcing Apple's actual Secure Token rules.
#
# Requirements: Linux, root, mocks installed. Skips itself otherwise.
#
# Run:  sudo bash tests/mocks/install-mocks.sh && sudo bash tests/integration_test.sh
#
# shellcheck disable=SC2015  # `cond && ok || bad` is safe: ok/bad always return 0.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CORE="$HERE/../scripts/securetoken.sh"

# ---- preconditions -----------------------------------------------------------
if [ "$(uname -s)" != "Linux" ]; then
    echo "SKIP: integration tests only run on Linux (with mocks)"; exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: integration tests must run as root"; exit 0
fi
if ! grep -q ST_MOCK_DARWIN /usr/bin/uname 2>/dev/null; then
    echo "SKIP: mocks not installed (run tests/mocks/install-mocks.sh first)"; exit 0
fi

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; }

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then ok "$desc"; else
        bad "$desc (expected='$expected' actual='$actual')"
    fi
}

STATE=$(mktemp -d /tmp/st-int-state.XXXXXX)
LOGF=$(mktemp /tmp/st-int-log.XXXXXX)
OUT=""
RC=0

cleanup() { rm -rf "$STATE" "$LOGF" /var/run/securetoken.lock 2>/dev/null; }
trap cleanup EXIT

# reset_state [version] — a healthy, MDM-enrolled, bootstrap-escrowed Mac with
# one Secure Token admin (localadmin/adminpw) and one tokenless user
# (plainuser/userpw).
reset_state() {
    rm -rf "$STATE"; mkdir -p "$STATE/users"
    printf '%s' "${1:-14.5}" > "$STATE/macos_version"
    printf '1' > "$STATE/mdm_enrolled"
    printf '1' > "$STATE/bootstrap_escrowed"
    printf '1' > "$STATE/apfs"
    mkdir -p "$STATE/users/localadmin" "$STATE/users/plainuser"
    printf 'adminpw' > "$STATE/users/localadmin/password"
    printf '1'       > "$STATE/users/localadmin/token"
    printf '1'       > "$STATE/users/localadmin/admin"
    printf '502'     > "$STATE/users/localadmin/uid"
    printf 'userpw'  > "$STATE/users/plainuser/password"
    printf '0'       > "$STATE/users/plainuser/token"
    printf '0'       > "$STATE/users/plainuser/admin"
    printf '503'     > "$STATE/users/plainuser/uid"
    rm -rf /var/run/securetoken.lock
}

# run_st <args...> — run the real script; captures stdout in OUT, rc in RC.
run_st() {
    OUT=$(ST_MOCK_DARWIN=1 ST_MOCK_STATE="$STATE" \
          /bin/bash "$CORE" --log-file "$LOGF" --json "$@" 2>/dev/null)
    RC=$?
}

# json_field <field> — extract a field from the LAST stdout line via python3.
json_field() {
    printf '%s\n' "$OUT" | tail -1 | python3 -c "
import json,sys
try:
    print(json.load(sys.stdin).get('$1', '<absent>'))
except Exception:
    print('<unparseable>')"
}

json_valid() {
    printf '%s\n' "$OUT" | tail -1 | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null
}

user_exists_in_state()  { [ -d "$STATE/users/$1" ]; }
user_has_token_in_state() { [ "$(cat "$STATE/users/$1/token" 2>/dev/null)" = "1" ]; }

# ==============================================================================
echo "preflight:"
reset_state
run_st preflight
assert_eq "exit 0"                     "0"     "$RC"
json_valid && ok "JSON parses" || bad "JSON parses"
assert_eq "firstLoginGrantAvailable"   "True"  "$(json_field firstLoginGrantAvailable)"
assert_eq "bootstrapTokenEscrowed"     "True"  "$(json_field bootstrapTokenEscrowed)"
assert_eq "stdout is exactly one line" "1"     "$(printf '%s\n' "$OUT" | wc -l | tr -d ' ')"
case "$(json_field tokenHolders)" in
    *localadmin*) ok "tokenHolders includes localadmin" ;;
    *) bad "tokenHolders includes localadmin ($(json_field tokenHolders))" ;;
esac

reset_state
printf '0' > "$STATE/bootstrap_escrowed"
run_st preflight
assert_eq "no bootstrap + no creds -> exit 11" "11" "$RC"
assert_eq "firstLoginGrantAvailable false" "False" "$(json_field firstLoginGrantAvailable)"

echo "create-user (admin path):"
reset_state
run_st create-user --new-user svcadmin --new-fullname "Svc Admin" \
       --new-password 'S3cret!x' --make-admin \
       --admin-user localadmin --admin-password adminpw
assert_eq "exit 0"                "0"      "$RC"
assert_eq "tokenMethod"           "admin"  "$(json_field tokenMethod)"
user_exists_in_state svcadmin     && ok "user created in DS" || bad "user created in DS"
user_has_token_in_state svcadmin  && ok "token ENABLED"      || bad "token ENABLED"

run_st create-user --new-user svcadmin --new-password 'S3cret!x' \
       --admin-user localadmin --admin-password adminpw
assert_eq "idempotent re-run exit 0" "0" "$RC"
assert_eq "idempotent message" "already provisioned" "$(json_field message)"

echo "create-user (deferred path — the Bootstrap Token reality):"
reset_state
run_st create-user --new-user defuser --generate-password
assert_eq "exit 0"      "0"               "$RC"
assert_eq "tokenMethod" "deferred-login"  "$(json_field tokenMethod)"
user_exists_in_state defuser && ok "user created" || bad "user created"
user_has_token_in_state defuser && bad "no token yet (deferred)" || ok "no token yet (deferred)"
GP="$(json_field generatedPassword)"
[ "$GP" != "<absent>" ] && [ "${#GP}" -eq 20 ] && ok "generatedPassword surfaced (20 chars)" || bad "generatedPassword surfaced (got '$GP')"
assert_eq "generated pw authenticates in DS" "$GP" "$(cat "$STATE/users/defuser/password")"

reset_state
run_st create-user --new-user defuser2 --generate-password --require-immediate
assert_eq "require-immediate -> exit 23" "23" "$RC"
user_exists_in_state defuser2 && bad "NO orphan account created" || ok "NO orphan account created"

reset_state
printf '0' > "$STATE/bootstrap_escrowed"
run_st create-user --new-user nosrc --new-password 'abcd1234'
assert_eq "no token source -> exit 22" "22" "$RC"
user_exists_in_state nosrc && bad "NO account created on exit 22" || ok "NO account created on exit 22"

echo "create-user fail-fast (stale credentials cannot orphan):"
reset_state
printf '0' > "$STATE/bootstrap_escrowed"   # force the admin path
run_st create-user --new-user orphan1 --new-password 'abcd1234' \
       --admin-user localadmin --admin-password WRONGPW
assert_eq "bad admin pw -> exit 22" "22" "$RC"
user_exists_in_state orphan1 && bad "NO account on bad admin pw" || ok "NO account on bad admin pw"

reset_state
printf '0' > "$STATE/bootstrap_escrowed"
printf '0' > "$STATE/users/localadmin/token"   # admin lost their token
run_st create-user --new-user orphan2 --new-password 'abcd1234' \
       --admin-user localadmin --admin-password adminpw
assert_eq "tokenless admin -> exit 22" "22" "$RC"
user_exists_in_state orphan2 && bad "NO account on tokenless admin" || ok "NO account on tokenless admin"

echo "regression guard: a credential-free sysadminctl grant must never work:"
reset_state
# Simulate the v2 bug directly against the mock: secureTokenOn with no admin.
/usr/sbin/sysadminctl -secureTokenOn plainuser -password userpw >/dev/null 2>&1
user_has_token_in_state plainuser && bad "mock refuses credential-free grant" || ok "mock refuses credential-free grant"

echo "grant-token:"
reset_state
run_st grant-token --new-user plainuser --new-password userpw \
       --admin-user localadmin --admin-password adminpw
assert_eq "exit 0" "0" "$RC"
user_has_token_in_state plainuser && ok "token granted" || bad "token granted"

run_st grant-token --new-user plainuser --new-password userpw
assert_eq "already-tokened re-run exit 0" "0" "$RC"
assert_eq "tokenMethod existing" "existing" "$(json_field tokenMethod)"

run_st grant-token --new-user ghost --new-password x1234
assert_eq "missing user -> exit 2" "2" "$RC"

echo "verification catches a silent sysadminctl lie (exit 0, no token):"
reset_state
touch "$STATE/fail_tokenon_silently"
run_st grant-token --new-user plainuser --new-password userpw \
       --admin-user localadmin --admin-password adminpw
assert_eq "silent failure -> exit 40" "40" "$RC"

echo "watchdog: a blocking interactive prompt cannot hang the run:"
reset_state
touch "$STATE/hang_tokenon"
START=$(date +%s)
run_st grant-token --new-user plainuser --new-password userpw \
       --admin-user localadmin --admin-password adminpw --timeout 3
ELAPSED=$(( $(date +%s) - START ))
assert_eq "hang -> exit 21" "21" "$RC"
[ "$ELAPSED" -le 30 ] && ok "killed by watchdog in ${ELAPSED}s" || bad "killed by watchdog (took ${ELAPSED}s)"

echo "watchdog: stdin secret-mode blocks headless (as on real macOS):"
reset_state
run_st grant-token --new-user plainuser --new-password userpw \
       --admin-user localadmin --admin-password adminpw \
       --secret-mode stdin --timeout 3
assert_eq "stdin mode headless -> exit 21 (timed out at prompt)" "21" "$RC"
user_has_token_in_state plainuser && bad "no token from a timed-out prompt" || ok "no token from a timed-out prompt"

echo "status / list:"
reset_state
run_st status --new-user localadmin
assert_eq "holder: exit 0" "0" "$RC"
assert_eq "hasSecureToken true" "True" "$(json_field hasSecureToken)"
run_st status --new-user plainuser
assert_eq "non-holder: exit 0" "0" "$RC"
assert_eq "hasSecureToken false" "False" "$(json_field hasSecureToken)"
run_st status --new-user ghost
assert_eq "missing user: exit 2" "2" "$RC"
run_st list
assert_eq "list exit 0" "0" "$RC"
case "$(json_field tokenHolders)" in
    *localadmin*) ok "list includes localadmin" ;;
    *) bad "list includes localadmin" ;;
esac
case "$(json_field tokenHolders)" in
    *_mbsetupuser*|*_spotlight*) bad "list excludes system accounts" ;;
    *) ok "list excludes system accounts" ;;
esac

echo "delete-user:"
reset_state
run_st delete-user --new-user plainuser
assert_eq "exit 0" "0" "$RC"
user_exists_in_state plainuser && bad "user removed" || ok "user removed"
run_st delete-user --new-user plainuser
assert_eq "idempotent delete exit 0" "0" "$RC"

echo "rollback-on-failure removes a just-created account:"
reset_state
touch "$STATE/fail_tokenon_silently"
printf '0' > "$STATE/bootstrap_escrowed"
run_st create-user --new-user rbuser --new-password 'abcd1234' \
       --admin-user localadmin --admin-password adminpw --rollback-on-failure
assert_eq "grant failed -> exit 40" "40" "$RC"
user_exists_in_state rbuser && bad "rollback deleted the account" || ok "rollback deleted the account"

echo "generated password still surfaced when a late step fails (no rollback):"
reset_state
touch "$STATE/fail_tokenon_silently"
printf '0' > "$STATE/bootstrap_escrowed"
run_st create-user --new-user lateuser --generate-password \
       --admin-user localadmin --admin-password adminpw
assert_eq "exit 40" "40" "$RC"
GP2="$(json_field generatedPassword)"
[ "$GP2" != "<absent>" ] && [ -n "$GP2" ] && ok "password recoverable from failure JSON" || bad "password recoverable from failure JSON"
assert_eq "matches the account's real password" "$GP2" "$(cat "$STATE/users/lateuser/password")"

echo "hidden accounts get a low UID and the IsHidden marker:"
reset_state
run_st create-user --new-user hidsvc --new-password 'abcd1234' --hidden \
       --admin-user localadmin --admin-password adminpw
assert_eq "exit 0" "0" "$RC"
HUID=$(cat "$STATE/users/hidsvc/uid" 2>/dev/null || echo 0)
[ "$HUID" -ge 200 ] && [ "$HUID" -lt 500 ] && ok "UID $HUID in 200-499" || bad "UID in 200-499 (got $HUID)"
[ -e "$STATE/users/hidsvc/hidden" ] && ok "IsHidden set" || bad "IsHidden set"

echo "single-instance lock:"
reset_state
mkdir -p /var/run/securetoken.lock && printf '%s' "$$" > /var/run/securetoken.lock/pid
run_st create-user --new-user locked --new-password 'abcd1234' \
       --admin-user localadmin --admin-password adminpw
assert_eq "live lock -> exit 24" "24" "$RC"
rm -rf /var/run/securetoken.lock
mkdir -p /var/run/securetoken.lock && printf '999999999' > /var/run/securetoken.lock/pid
run_st create-user --new-user locked --new-password 'abcd1234' \
       --admin-user localadmin --admin-password adminpw
assert_eq "stale lock reaped -> exit 0" "0" "$RC"
[ -d /var/run/securetoken.lock ] && bad "lock released after run" || ok "lock released after run"

echo "usage errors:"
reset_state
run_st create-user --new-user 'bad name' --new-password 'abcd1234'
assert_eq "invalid username -> exit 2" "2" "$RC"
run_st bogus-action
assert_eq "unknown action -> exit 2" "2" "$RC"
run_st create-user --new-user
assert_eq "trailing flag -> exit 2" "2" "$RC"

echo "unsupported platforms:"
reset_state "10.12.6"
run_st preflight
assert_eq "macOS 10.12 -> exit 11" "11" "$RC"
reset_state
printf '0' > "$STATE/apfs"
run_st grant-token --new-user plainuser --new-password userpw \
       --admin-user localadmin --admin-password adminpw
assert_eq "non-APFS grant -> exit 12" "12" "$RC"

echo
echo "-----------------------------------------"
printf 'RESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
