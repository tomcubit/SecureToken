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

expect_true()  { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
expect_false() { local d="$1"; shift; if "$@"; then bad "$d"; else ok "$d"; fi; }

# Run a validator in an isolated subshell (validators may exit).
run_validate()     { ( ST_LIB_ONLY=1 . "$CORE"; validate_username "$1" ) >/dev/null 2>&1; }
run_validate_pw()  { ( ST_LIB_ONLY=1 . "$CORE"; validate_password "$1" "pw" ) >/dev/null 2>&1; }

# Source the library into this shell for the pure-function tests.
ST_LIB_ONLY=1 . "$CORE"

# Sourcing twice must not fail — the documented library mode and this suite both
# re-source. (Top-level `readonly` would make this fatal on bash 3.2.)
echo "library mode:"
if ( ST_LIB_ONLY=1 . "$CORE"; ST_LIB_ONLY=1 . "$CORE" ) >/dev/null 2>&1; then
    ok "core can be sourced twice (no top-level readonly)"
else
    bad "core can be sourced twice (no top-level readonly)"
fi

echo "truthy():"
assert_eq "1 -> 1"        "1" "$(truthy 1)"
assert_eq "yes -> 1"      "1" "$(truthy yes)"
assert_eq "TRUE -> 1"     "1" "$(truthy TRUE)"
assert_eq "On -> 1"       "1" "$(truthy On)"
assert_eq "0 -> 0"        "0" "$(truthy 0)"
assert_eq "no -> 0"       "0" "$(truthy no)"
assert_eq "empty->0"      "0" "$(truthy '')"
assert_eq "junk->0"       "0" "$(truthy banana)"
# RMM consoles routinely append whitespace / CR to variables.
assert_eq "' 1 ' -> 1"    "1" "$(truthy ' 1 ')"
assert_eq "'1\\r' -> 1"    "1" "$(truthy "$(printf '1\r')")"
assert_eq "'yes\\n' -> 1"  "1" "$(truthy "$(printf 'yes\n')")"

echo "version_ge():"
expect_true  "14.5.0 >= 10.13.0"  version_ge 14.5.0 10.13.0
expect_true  "10.13.0 >= 10.13.0" version_ge 10.13.0 10.13.0
expect_true  "11.0.1 >= 10.15.0"  version_ge 11.0.1 10.15.0
expect_false "10.12.6 < 10.13.0"  version_ge 10.12.6 10.13.0
expect_false "9.9 < 10.0"         version_ge 9.9 10.0
expect_true  "15 >= 10.13.0"      version_ge 15 10.13.0
expect_true  "26.1 >= 11.0.0"     version_ge 26.1 11.0.0
expect_false "10.15.4 < 11.0.0"   version_ge 10.15.4 11.0.0

echo "json_escape():"
assert_eq 'quotes'    'he \"q\"' "$(json_escape 'he "q"')"
assert_eq 'backslash' 'a\\b'      "$(json_escape 'a\b')"
assert_eq 'tab'       'a\tb'      "$(json_escape "$(printf 'a\tb')")"
# C0 control characters must become \u00XX or strict parsers reject the line.
assert_eq 'bell -> u0007' 'a\u0007b' "$(json_escape "$(printf 'a\007b')")"
assert_eq 'esc  -> u001b' 'a\u001bb' "$(json_escape "$(printf 'a\033b')")"

echo "sanitize_for_log():"
assert_eq "strips newline" "abc" "$(sanitize_for_log "$(printf 'a\nb\nc')" | tr -d '\n')"
assert_eq "strips CR"      "ab"  "$(sanitize_for_log "$(printf 'a\rb')")"

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
# Must never start with '-' (sysadminctl would parse it as a flag).
LEADING_DASH=0
for _i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    case "$(generate_password 12)" in -*) LEADING_DASH=1 ;; esac
done
assert_eq "never starts with '-'" "0" "$LEADING_DASH"
# Exact length must hold for many sizes (bounded-read loop, no SIGPIPE reliance).
LEN_OK=1
for n in 4 8 16 32 64; do
    got="$(generate_password "$n")"
    [ "${#got}" -eq "$n" ] || LEN_OK=0
done
assert_eq "exact length across sizes" "1" "$LEN_OK"

echo "validate_username():"
expect_true  "valid 'jsmith'"            run_validate "jsmith"
expect_true  "valid 'a_b-c1'"            run_validate "a_b-c1"
expect_false "reject '1abc'"             run_validate "1abc"
expect_false "reject 'has space'"        run_validate "has space"
expect_false "reject 'root' (reserved)"  run_validate "root"
expect_false "reject 'ROOT' (reserved)"  run_validate "ROOT"
expect_false "reject empty"              run_validate ""

echo "validate_password():"
expect_true  "valid 'abcd'"        run_validate_pw "abcd"
expect_false "reject 'abc' (short)" run_validate_pw "abc"
expect_false "reject embedded newline" run_validate_pw "$(printf 'ab\ncd')"
expect_false "reject embedded CR"      run_validate_pw "$(printf 'ab\rcd')"

echo "emit_result() JSON shape:"
JSON_MODE=1 ACTION=create-user NEW_USER=itadmin TOKEN_METHOD=admin
EXTRA_JSON="" GENERATED_PASSWORD="" PASSWORD_APPLIED=0
OUT="$(emit_result ok 0 'done')"
case "$OUT" in
    *'"tool":"securetoken"'*'"status":"ok"'*'"user":"itadmin"'*'"tokenMethod":"admin"'*) ok "JSON contains expected fields" ;;
    *) bad "JSON shape ($OUT)" ;;
esac
# A generated password that was NEVER applied must not be reported.
GENERATED_PASSWORD="secret123"; PASSWORD_APPLIED=0
case "$(emit_result ok 0 'x')" in
    *generatedPassword*) bad "must omit unapplied generated password" ;;
    *) ok "omits generated password when not applied" ;;
esac
# Once applied it MUST be reported, including on a failure result.
PASSWORD_APPLIED=1
case "$(emit_result error 21 'grant failed')" in
    *'"generatedPassword":"secret123"'*) ok "reports applied password even on failure" ;;
    *) bad "reports applied password even on failure" ;;
esac
GENERATED_PASSWORD=""; PASSWORD_APPLIED=0
JSON_MODE=0
assert_eq "silent when JSON off" "" "$(emit_result ok 0 'done')"

echo "build_sysadminctl_args():"
SYS_ARGS=( -addUser foo -fullName "Foo Bar" -password @@ST_SECRET@@ )
SYS_SECRETS=( "s3cr3t pw" )
SECRET_MODE=stdin
build_sysadminctl_args
assert_eq "stdin: arg count"        "6"          "${#BUILT_ARGS[@]}"
assert_eq "stdin: spaced fullname"  "Foo Bar"    "${BUILT_ARGS[3]}"
assert_eq "stdin: placeholder -> -" "-"          "${BUILT_ARGS[5]}"
assert_eq "stdin: fed count"        "1"          "${#BUILT_FED[@]}"
assert_eq "stdin: fed value"        "s3cr3t pw"  "${BUILT_FED[0]}"

SECRET_MODE=inline
build_sysadminctl_args
assert_eq "inline: secret in argv"  "s3cr3t pw"  "${BUILT_ARGS[5]}"
assert_eq "inline: nothing fed"     "0"          "${#BUILT_FED[@]}"

SYS_ARGS=( -secureTokenOn foo -password @@ST_SECRET@@ -adminUser bar -adminPassword @@ST_SECRET@@ )
SYS_SECRETS=( "userpw" "adminpw" )
SECRET_MODE=stdin
build_sysadminctl_args
assert_eq "order: fed count"  "2"        "${#BUILT_FED[@]}"
assert_eq "order: first fed"  "userpw"   "${BUILT_FED[0]}"
assert_eq "order: second fed" "adminpw"  "${BUILT_FED[1]}"

echo "first_unused_uid():"
assert_eq "empty list -> floor"   "200" "$(printf '' | first_unused_uid 200 500)"
assert_eq "skips used from floor" "202" "$(printf '200\n201\n501\n' | first_unused_uid 200 500)"
assert_eq "gap in middle"         "201" "$(printf '200\n202\n' | first_unused_uid 200 500)"
if printf '200\n201\n' | first_unused_uid 200 202 >/dev/null; then
    bad "exhausted range should fail"
else
    ok "exhausted range returns non-zero"
fi

echo "parse_args() / resolve_config():"
# Flag beats env; env beats CONFIG block; booleans normalise; defaults apply.
CFG_TEST=$( ST_LIB_ONLY=1 bash -c '
  . '"$CORE"'
  export ST_NEW_USER=envuser ST_MAKE_ADMIN=true ST_JSON=yes
  parse_args create-user --new-user flaguser --hidden
  resolve_config
  printf "%s|%s|%s|%s|%s|%s" "$ACTION" "$NEW_USER" "$MAKE_ADMIN" "$HIDDEN" "$JSON" "$SECRET_MODE"
' 2>/dev/null )
assert_eq "flag>env>config + defaults" "create-user|flaguser|1|1|1|inline" "$CFG_TEST"

# Default action when none supplied.
DEF_ACT=$( ST_LIB_ONLY=1 bash -c '
  . '"$CORE"'
  parse_args --new-user u1
  resolve_config
  printf "%s" "$ACTION"
' 2>/dev/null )
assert_eq "default action" "create-user" "$DEF_ACT"

# NOTE: sourcing the core enables `set -e` in this shell, so a bare failing
# command would abort the suite. Capture rc with `|| rc=$?`, which is exempt.

# A value-taking flag in final position must fail cleanly (exit 2), not bare 1.
RC=0
( ST_LIB_ONLY=1 bash -c '. '"$CORE"'; parse_args --new-user' ) >/dev/null 2>&1 || RC=$?
assert_eq "trailing flag -> exit 2" "2" "$RC"

# An invalid secret-mode must be rejected.
RC=0
( ST_LIB_ONLY=1 bash -c '. '"$CORE"'; parse_args --secret-mode bogus; resolve_config' ) >/dev/null 2>&1 || RC=$?
assert_eq "bad secret-mode -> exit 2" "2" "$RC"

# Secrets must be scrubbed from the environment after resolution.
LEAK=$( ST_LIB_ONLY=1 bash -c '
  . '"$CORE"'
  export ST_ADMIN_PASSWORD=topsecret ST_NEW_PASSWORD=alsosecret
  parse_args status --new-user u1
  resolve_config
  printenv ST_ADMIN_PASSWORD 2>/dev/null || true
  printenv ST_NEW_PASSWORD 2>/dev/null || true
  printf "CLEAN"
' 2>/dev/null )
assert_eq "secrets unset from environment" "CLEAN" "$LEAK"

echo
echo "-----------------------------------------"
printf 'RESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
