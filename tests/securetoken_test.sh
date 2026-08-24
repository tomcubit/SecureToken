#!/bin/bash
#
# tests/securetoken_test.sh — unit tests for securetoken.sh pure functions.
#
# These source the core in library mode (ST_LIB_ONLY=1) so main() is not run,
# and exercise the platform-independent logic. They run on any OS with bash;
# macOS-only paths (sysadminctl/dscl) are not exercised here.
#
# Run:  bash tests/securetoken_test.sh
#
# shellcheck disable=SC1090  # core path is dynamic ($CORE); intentional.
# shellcheck disable=SC2034  # some globals are read indirectly (pick/emit_result).
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CORE="$HERE/../scripts/securetoken.sh"

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

# expect_true <desc> <cmd...> : cmd should return 0
expect_true()  { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
# expect_false <desc> <cmd...> : cmd should return non-zero
expect_false() { local d="$1"; shift; if "$@"; then bad "$d"; else ok "$d"; fi; }

# Validate a username in an isolated subshell (validate_username may exit).
run_validate() { ( ST_LIB_ONLY=1 . "$CORE"; validate_username "$1" ) >/dev/null 2>&1; }

# Source the library into this shell for the pure-function tests.
ST_LIB_ONLY=1 . "$CORE"

echo "truthy():"
assert_eq "1 -> 1"    "1" "$(truthy 1)"
assert_eq "yes -> 1"  "1" "$(truthy yes)"
assert_eq "TRUE -> 1" "1" "$(truthy TRUE)"
assert_eq "On -> 1"   "1" "$(truthy On)"
assert_eq "0 -> 0"    "0" "$(truthy 0)"
assert_eq "no -> 0"   "0" "$(truthy no)"
assert_eq "empty->0"  "0" "$(truthy '')"
assert_eq "junk->0"   "0" "$(truthy banana)"

echo "version_ge():"
expect_true  "14.5.0 >= 10.13.0"  version_ge 14.5.0 10.13.0
expect_true  "10.13.0 >= 10.13.0" version_ge 10.13.0 10.13.0
expect_true  "11.0.1 >= 10.15.0"  version_ge 11.0.1 10.15.0
expect_false "10.12.6 < 10.13.0"  version_ge 10.12.6 10.13.0
expect_false "9.9 < 10.0"         version_ge 9.9 10.0
expect_true  "15 >= 10.13.0"      version_ge 15 10.13.0

echo "json_escape():"
assert_eq 'quotes'    'he \"q\"' "$(json_escape 'he "q"')"
assert_eq 'backslash' 'a\\b'      "$(json_escape 'a\b')"
assert_eq 'tab'       'a\tb'      "$(json_escape "$(printf 'a\tb')")"

echo "pick() precedence:"
assert_eq "flag wins"    "flagv" "$(pick flagv NONEXISTENT_XYZ cfg def)"
assert_eq "config used"  "cfg"   "$(pick '' NONEXISTENT_XYZ cfg def)"
assert_eq "default used" "def"   "$(pick '' NONEXISTENT_XYZ '' def)"
PICKENV=envv
assert_eq "env over config" "envv" "$(pick '' PICKENV cfg def)"

echo "generate_password():"
GP="$(generate_password 24)"
assert_eq "length 24" "24" "${#GP}"
GP2="$(generate_password 24)"
if [ "$GP" != "$GP2" ]; then ok "two generations differ"; else bad "two generations differ"; fi

echo "validate_username():"
expect_true  "valid 'jsmith'"            run_validate "jsmith"
expect_true  "valid 'a_b-c1'"            run_validate "a_b-c1"
expect_false "reject '1abc'"             run_validate "1abc"
expect_false "reject 'has space'"        run_validate "has space"
expect_false "reject 'root' (reserved)"  run_validate "root"
expect_false "reject 'ROOT' (reserved)"  run_validate "ROOT"
expect_false "reject empty"              run_validate ""

echo "emit_result() JSON shape:"
JSON_MODE=1 ACTION=create-user NEW_USER=itadmin TOKEN_METHOD=bootstrap
OUT="$(emit_result ok 0 'done')"
case "$OUT" in
    *'"tool":"securetoken"'*'"status":"ok"'*'"user":"itadmin"'*'"tokenMethod":"bootstrap"'*) ok "JSON contains expected fields" ;;
    *) bad "JSON shape ($OUT)" ;;
esac
JSON_MODE=0
assert_eq "silent when JSON off" "" "$(emit_result ok 0 'done')"

echo
echo "-----------------------------------------"
printf 'RESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
