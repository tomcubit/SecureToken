#!/bin/bash
#
# securetoken.sh — Unattended macOS Secure Token provisioning
# ============================================================
#
# Creates a local user account and ensures it holds a Secure Token, with ZERO
# interactive prompts, so it can be deployed from an RMM (NinjaOne, Datto,
# Kaseya, Addigy, Mosyle, Level, Syncro, ...) or Microsoft Intune.
#
# It prefers the escrowed **Bootstrap Token** (the credential-free path for
# MDM-managed Macs) and falls back to an existing Secure Token administrator's
# credentials only when no Bootstrap Token is available.
#
# ---------------------------------------------------------------------------
# COMPATIBILITY
#   * Targets /bin/bash 3.2 (the version shipped on every macOS). No bash-4+
#     features (no ${x,,}, no associative arrays, no mapfile) are used.
#   * macOS 10.13+ for Secure Tokens; Bootstrap Token path needs macOS 10.15+.
#   * Runs as root (required).
#
# CONFIGURATION (three layers, highest priority first)
#   1. Command-line flags        (e.g. --new-user jsmith)
#   2. Environment variables     (e.g. ST_NEW_USER=jsmith) — RMM/Intune inject here
#   3. The CONFIG block below    (edit for single-file Intune uploads)
#
# QUICK START
#   RMM:    set ST_* variables as secure script variables, run this file.
#   Intune: edit the CONFIG block below, upload this single file (run as root).
#
# See docs/DEPLOYMENT.md for step-by-step platform instructions.
#
# License: MIT
#
set -euo pipefail

# ===========================================================================
# CONFIG BLOCK — edit these for single-file (Intune) deployments.
# Leave blank to drive everything from environment variables / CLI flags.
# Anything set here is used ONLY when the matching env var / flag is absent.
# ===========================================================================
CONFIG_ACTION=""            # create-user | grant-token | status | list | preflight
CONFIG_NEW_USER=""          # username to create / target
CONFIG_NEW_FULLNAME=""      # full (display) name
CONFIG_NEW_PASSWORD=""      # password (leave blank + CONFIG_GENERATE_PASSWORD=1 to auto-generate)
CONFIG_GENERATE_PASSWORD="" # 1 = generate a strong random password
CONFIG_MAKE_ADMIN=""        # 1 = administrator, 0 = standard
CONFIG_HIDDEN=""            # 1 = hidden account (UID<500, hidden from login window)
CONFIG_UID=""               # explicit UID (optional)
CONFIG_ADMIN_USER=""        # existing Secure Token admin (fallback when no Bootstrap Token)
CONFIG_ADMIN_PASSWORD=""    # that admin's password
CONFIG_LOG_FILE=""          # default: /var/log/securetoken.log
CONFIG_JSON=""              # 1 = emit a machine-readable JSON result line on stdout
CONFIG_STDIN_SECRETS=""     # 1 (default) = feed passwords via stdin (not visible in ps); 0 = inline
CONFIG_PREFER_BOOTSTRAP=""  # 1 (default) = use Bootstrap Token when available
# ===========================================================================

readonly ST_VERSION="2.0.0"

# ---- Exit codes (stable contract for RMM/Intune result parsing) -----------
readonly EX_OK=0             # success, or already in desired state
readonly EX_USAGE=2          # invalid arguments / configuration
readonly EX_NOT_ROOT=10      # not running as root
readonly EX_UNSUPPORTED=11   # macOS version / platform unsupported
readonly EX_PRECOND=12       # precondition failed (e.g. boot volume not APFS)
readonly EX_CREATE_FAILED=20 # user creation failed
readonly EX_GRANT_FAILED=21  # secure token grant failed
readonly EX_NO_TOKEN_SOURCE=22 # no Bootstrap Token and no valid token admin
readonly EX_VERIFY_FAILED=40 # post-operation verification failed

# ---- Runtime state --------------------------------------------------------
LOG_FILE=""
JSON_MODE=0
GENERATED_PASSWORD=""   # set if we auto-generated (surfaced in JSON result)
TOKEN_METHOD=""         # bootstrap | admin | none — how the token was granted

# ===========================================================================
# Configuration resolution: flag  >  env  >  CONFIG block  >  default
# ===========================================================================
# Resolved values live in these globals.
ACTION="" NEW_USER="" NEW_FULLNAME="" NEW_PASSWORD="" GENERATE_PASSWORD=0
MAKE_ADMIN=0 HIDDEN=0 NEW_UID="" ADMIN_USER="" ADMIN_PASSWORD=""
JSON=0 STDIN_SECRETS=1 PREFER_BOOTSTRAP=1

# pick <flag_value> <env_name> <config_value> <default>
# Echoes the first non-empty of flag/env/config, else the default.
pick() {
    local flag="$1" env_name="$2" config="$3" default="$4"
    if [ -n "$flag" ]; then printf '%s' "$flag"; return; fi
    # Indirect env lookup, bash 3.2-safe.
    local env_val=""
    eval "env_val=\${$env_name:-}"
    if [ -n "$env_val" ]; then printf '%s' "$env_val"; return; fi
    if [ -n "$config" ]; then printf '%s' "$config"; return; fi
    printf '%s' "$default"
}

# Normalize a truthy string to 1/0. Accepts 1/true/yes/on (any case).
truthy() {
    local v
    v=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')
    case "$v" in
        1|true|yes|on|y) printf '1' ;;
        *) printf '0' ;;
    esac
}

# ===========================================================================
# Logging — file + stderr. stdout is reserved for the JSON result line so RMM
# "output" parsing stays clean. Secrets are NEVER logged.
# ===========================================================================
_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

_log() {
    local level="$1"; shift
    local line
    line="$(_ts) [$level] $*"
    printf '%s\n' "$line" >&2
    if [ -n "$LOG_FILE" ]; then
        printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null || true
    fi
}
log_info()  { _log "INFO"  "$@"; }
log_warn()  { _log "WARN"  "$@"; }
log_error() { _log "ERROR" "$@"; }
log_debug() { if [ "${ST_DEBUG:-0}" = "1" ]; then _log "DEBUG" "$@"; fi; }

# ===========================================================================
# JSON result emission (no jq dependency; macOS has none by default).
# ===========================================================================
json_escape() {
    # Escapes a string for embedding in a JSON double-quoted value.
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

# emit_result <status> <exit_code> <message>
# Prints a single-line JSON object to stdout when JSON mode is on.
emit_result() {
    local status="$1" code="$2" message="$3"
    [ "$JSON_MODE" = "1" ] || return 0
    local pw_field=""
    if [ -n "$GENERATED_PASSWORD" ]; then
        pw_field=",\"generatedPassword\":\"$(json_escape "$GENERATED_PASSWORD")\""
    fi
    printf '{"tool":"securetoken","version":"%s","status":"%s","exitCode":%s,"action":"%s","user":"%s","tokenMethod":"%s","message":"%s"%s}\n' \
        "$ST_VERSION" \
        "$(json_escape "$status")" \
        "$code" \
        "$(json_escape "$ACTION")" \
        "$(json_escape "$NEW_USER")" \
        "$(json_escape "$TOKEN_METHOD")" \
        "$(json_escape "$message")" \
        "$pw_field"
}

# die <exit_code> <message>
die() {
    local code="$1"; shift
    log_error "$*"
    emit_result "error" "$code" "$*"
    exit "$code"
}

# ===========================================================================
# Platform / environment probes
# ===========================================================================
is_root() { [ "$(id -u)" -eq 0 ]; }

macos_product_version() { /usr/bin/sw_vers -productVersion 2>/dev/null || printf '0.0.0'; }

# version_ge <a> <b> : true if version a >= b (dotted numeric compare)
version_ge() {
    local a="$1" b="$2"
    local IFS=.
    # shellcheck disable=SC2206  # deliberate word-split on dots
    local av=($a) bv=($b)
    local i
    for i in 0 1 2; do
        local an="${av[i]:-0}" bn="${bv[i]:-0}"
        # strip any non-numeric suffix (e.g. beta build tags)
        an=$(printf '%s' "$an" | tr -cd '0-9'); an=${an:-0}
        bn=$(printf '%s' "$bn" | tr -cd '0-9'); bn=${bn:-0}
        if [ "$an" -gt "$bn" ]; then return 0; fi
        if [ "$an" -lt "$bn" ]; then return 1; fi
    done
    return 0
}

is_apple_silicon() {
    local arch
    arch=$(/usr/bin/uname -m 2>/dev/null || printf 'unknown')
    [ "$arch" = "arm64" ]
}

boot_is_apfs() {
    /usr/sbin/diskutil info / 2>/dev/null | /usr/bin/grep -qi "Type (Bundle):.*apfs" \
        || /usr/sbin/diskutil info / 2>/dev/null | /usr/bin/grep -qi "File System Personality:.*APFS"
}

# Is the Mac MDM-enrolled?
mdm_enrolled() {
    /usr/bin/profiles status -type enrollment 2>/dev/null \
        | /usr/bin/grep -qi "MDM enrollment: Yes"
}

# Is a Bootstrap Token escrowed to the MDM server?
bootstrap_token_escrowed() {
    /usr/bin/profiles status -type bootstraptoken 2>/dev/null \
        | /usr/bin/grep -qi "Bootstrap Token escrowed to server: YES"
}

# ===========================================================================
# Directory-service helpers
# ===========================================================================
user_exists() {
    /usr/bin/dscl . -read "/Users/$1" >/dev/null 2>&1
}

# token_status <user> : return 0 if the user has an ENABLED secure token.
token_status() {
    local user="$1" out
    out=$(/usr/sbin/sysadminctl -secureTokenStatus "$user" 2>&1 || true)
    printf '%s' "$out" | /usr/bin/grep -qi "ENABLED"
}

list_local_users() {
    /usr/bin/dscl . -list /Users 2>/dev/null \
        | /usr/bin/grep -vE '^_' \
        | /usr/bin/grep -vxE 'daemon|nobody|root'
}

# Next free UID at or above a floor (used for hidden accounts / explicit ranges).
# first_unused_uid <floor> <ceiling> : reads a newline list of used UIDs on
# stdin and prints the first UID in [floor, ceiling) that is NOT in the list.
# Returns 1 (no output) if the range is exhausted. Pure — unit-testable.
first_unused_uid() {
    local floor="$1" ceiling="$2" used candidate
    used=$(cat)
    candidate="$floor"
    while [ "$candidate" -lt "$ceiling" ]; do
        if ! printf '%s\n' "$used" | /usr/bin/grep -qx "$candidate"; then
            printf '%s' "$candidate"; return 0
        fi
        candidate=$((candidate + 1))
    done
    return 1
}

# Pick the first free UID in a low, hidden-friendly range [floor, ceiling).
# For hidden service accounts we want a UID < 500 so the login window hides it,
# rather than one above the existing interactive users.
next_free_uid() {
    local floor="$1" ceiling="${2:-500}"
    /usr/bin/dscl . -list /Users UniqueID 2>/dev/null | /usr/bin/awk '{print $2}' \
        | first_unused_uid "$floor" "$ceiling"
}

# ===========================================================================
# Validation
# ===========================================================================
RESERVED_USERS="root daemon nobody admin wheel kmem sys tty staff"

validate_username() {
    local u="$1"
    [ -n "$u" ] || die "$EX_USAGE" "Username is required"
    if [ "${#u}" -gt 244 ]; then die "$EX_USAGE" "Username too long (max 244 chars)"; fi
    case "$u" in
        [a-zA-Z]*) ;;
        *) die "$EX_USAGE" "Username must start with a letter: '$u'" ;;
    esac
    case "$u" in
        *[!a-zA-Z0-9_-]*) die "$EX_USAGE" "Username may contain only letters, digits, '-' and '_': '$u'" ;;
    esac
    local lower r
    lower=$(printf '%s' "$u" | tr '[:upper:]' '[:lower:]')
    for r in $RESERVED_USERS; do
        if [ "$lower" = "$r" ]; then die "$EX_USAGE" "Username '$u' is reserved"; fi
    done
    # Explicit success: without this the loop's final failed test would make the
    # function return non-zero on a VALID name, aborting the caller under set -e.
    return 0
}

validate_password() {
    local p="$1"
    if [ "${#p}" -lt 4 ]; then die "$EX_USAGE" "Password must be at least 4 characters"; fi
    return 0
}

# Generate a strong random password (letters+digits+symbols), no ambiguous chars.
generate_password() {
    local len="${1:-20}"
    LC_ALL=C /usr/bin/tr -dc 'A-HJ-NP-Za-km-z2-9!@#%^&*_-' < /dev/urandom 2>/dev/null \
        | /usr/bin/head -c "$len"
    printf '\n'
}

# ===========================================================================
# Secure sysadminctl invocation.
#
# Passwords are fed on stdin using '-' placeholders so they never appear in the
# process table (ps). Order of the fed secrets MUST match the order of '-'
# placeholders in the argument list. Set STDIN_SECRETS=0 to fall back to inline
# arguments (accepts ps exposure) if a given macOS build misbehaves with stdin.
#
# Usage:
#   SYS_ARGS=( -addUser foo -fullName "Foo" -password @@ST_SECRET@@ ... )
#   SYS_SECRETS=( "$thepassword" )
#   run_sysadminctl   # reads the two arrays; sets SYS_OUT and returns rc
# ===========================================================================
SYS_OUT=""
BUILT_ARGS=()
BUILT_FED=()

# build_sysadminctl_args — pure transform of SYS_ARGS/SYS_SECRETS into the arrays
# BUILT_ARGS (the argv passed to sysadminctl) and BUILT_FED (secrets to stream on
# stdin, in placeholder order). Separated from execution so it is unit-testable
# on any OS. Element order and embedded spaces are preserved exactly.
build_sysadminctl_args() {
    BUILT_ARGS=()
    BUILT_FED=()
    local a secret si=0
    for a in ${SYS_ARGS[@]+"${SYS_ARGS[@]}"}; do
        if [ "$a" = "@@ST_SECRET@@" ]; then
            secret="${SYS_SECRETS[si]:-}"
            si=$((si + 1))
            if [ "$STDIN_SECRETS" = "1" ]; then
                BUILT_ARGS+=( "-" )
                BUILT_FED+=( "$secret" )
            else
                BUILT_ARGS+=( "$secret" )
            fi
        else
            BUILT_ARGS+=( "$a" )
        fi
    done
}

run_sysadminctl() {
    build_sysadminctl_args
    local rc=0
    if [ "$STDIN_SECRETS" = "1" ] && [ "${#BUILT_FED[@]}" -gt 0 ]; then
        SYS_OUT=$(printf '%s\n' ${BUILT_FED[@]+"${BUILT_FED[@]}"} \
                    | /usr/sbin/sysadminctl ${BUILT_ARGS[@]+"${BUILT_ARGS[@]}"} 2>&1) || rc=$?
    else
        SYS_OUT=$(/usr/sbin/sysadminctl ${BUILT_ARGS[@]+"${BUILT_ARGS[@]}"} 2>&1) || rc=$?
    fi
    # Scrub secrets from lingering globals as soon as the call returns.
    SYS_SECRETS=()
    BUILT_FED=()
    log_debug "sysadminctl rc=$rc"
    return "$rc"
}

# ===========================================================================
# Core operations
# ===========================================================================

# Secure Tokens are an APFS/FileVault concept; refuse to operate on a non-APFS
# boot volume where the grant cannot succeed. Apple Silicon additionally
# requires a volume owner (satisfied by the Bootstrap Token or an existing
# token-holding admin, both handled by resolve_token_method).
require_token_preconditions() {
    if ! boot_is_apfs; then
        die "$EX_PRECOND" "Boot volume is not APFS; Secure Tokens are unavailable on this system"
    fi
    if is_apple_silicon; then
        log_debug "Apple Silicon detected — a volume owner is required to grant tokens"
    fi
}

# Decide how a token can be granted on this Mac, and validate the admin path.
# Sets TOKEN_METHOD to "bootstrap" or "admin"; dies with EX_NO_TOKEN_SOURCE if
# neither is viable.
resolve_token_method() {
    # Idempotent: if a method was already resolved this run, don't re-log/re-check.
    if [ -n "$TOKEN_METHOD" ] && [ "$TOKEN_METHOD" != "existing" ]; then
        return 0
    fi
    if [ "$PREFER_BOOTSTRAP" = "1" ] \
       && version_ge "$(macos_product_version)" "10.15.0" \
       && mdm_enrolled && bootstrap_token_escrowed; then
        TOKEN_METHOD="bootstrap"
        log_info "Bootstrap Token is escrowed — will grant token without admin credentials"
        return 0
    fi

    # Fall back to an existing Secure Token administrator.
    if [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASSWORD" ]; then
        if ! user_exists "$ADMIN_USER"; then
            die "$EX_NO_TOKEN_SOURCE" "Token admin '$ADMIN_USER' does not exist"
        fi
        if ! token_status "$ADMIN_USER"; then
            die "$EX_NO_TOKEN_SOURCE" "Token admin '$ADMIN_USER' does not hold a Secure Token"
        fi
        TOKEN_METHOD="admin"
        log_info "Will grant token using Secure Token admin '$ADMIN_USER'"
        return 0
    fi

    die "$EX_NO_TOKEN_SOURCE" \
        "No Bootstrap Token escrowed and no valid Secure Token admin supplied (set ST_ADMIN_USER/ST_ADMIN_PASSWORD, or MDM-escrow a Bootstrap Token)"
}

create_user() {
    local user="$1" fullname="$2" password="$3"

    if user_exists "$user"; then
        log_info "User '$user' already exists — skipping creation"
        return 0
    fi

    local uid="$NEW_UID"
    if [ "$HIDDEN" = "1" ] && [ -z "$uid" ]; then
        # Best-effort low UID; if none free in 200-499, fall back to auto-assign.
        uid=$(next_free_uid 200 500) || uid=""
    fi

    log_info "Creating user '$user' (admin=$MAKE_ADMIN hidden=$HIDDEN uid=${uid:-auto})"

    SYS_ARGS=( -addUser "$user" -fullName "$fullname" -password @@ST_SECRET@@ )
    SYS_SECRETS=( "$password" )
    if [ -n "$uid" ]; then SYS_ARGS+=( -UID "$uid" ); fi
    if [ "$MAKE_ADMIN" = "1" ]; then SYS_ARGS+=( -admin ); fi
    # When creating via an admin (no bootstrap), sysadminctl can take the
    # admin credentials here too, but user creation itself does not require a
    # token; we keep creation and token-grant as separate, verifiable steps.

    if ! run_sysadminctl; then
        die "$EX_CREATE_FAILED" "Failed to create user '$user': $SYS_OUT"
    fi
    if ! user_exists "$user"; then
        die "$EX_CREATE_FAILED" "User '$user' not present after creation: $SYS_OUT"
    fi

    # Ensure home directory exists (belt-and-suspenders; modern macOS does this).
    /usr/sbin/createhomedir -c -u "$user" >/dev/null 2>&1 || true

    if [ "$HIDDEN" = "1" ]; then
        /usr/bin/dscl . -create "/Users/$user" IsHidden 1 >/dev/null 2>&1 || true
    fi

    log_info "User '$user' created"
}

# grant_token <user> <password> — ensures the user holds a Secure Token.
grant_token() {
    local user="$1" password="$2"

    if token_status "$user"; then
        log_info "User '$user' already holds a Secure Token — nothing to do"
        TOKEN_METHOD="${TOKEN_METHOD:-existing}"
        return 0
    fi

    require_token_preconditions
    resolve_token_method

    if [ "$TOKEN_METHOD" = "bootstrap" ]; then
        # macOS 11+ with an escrowed Bootstrap Token grants the token when
        # -secureTokenOn is run as root without admin credentials.
        SYS_ARGS=( -secureTokenOn "$user" -password @@ST_SECRET@@ )
        SYS_SECRETS=( "$password" )
    else
        SYS_ARGS=( -secureTokenOn "$user" -password @@ST_SECRET@@ \
                   -adminUser "$ADMIN_USER" -adminPassword @@ST_SECRET@@ )
        SYS_SECRETS=( "$password" "$ADMIN_PASSWORD" )
    fi

    if ! run_sysadminctl; then
        die "$EX_GRANT_FAILED" "Failed to grant Secure Token to '$user' via $TOKEN_METHOD: $SYS_OUT"
    fi

    if ! token_status "$user"; then
        die "$EX_VERIFY_FAILED" "Secure Token not ENABLED for '$user' after grant: $SYS_OUT"
    fi

    log_info "Secure Token granted to '$user' via $TOKEN_METHOD"
}

# ===========================================================================
# Actions
# ===========================================================================
do_preflight() {
    log_info "securetoken $ST_VERSION preflight"
    local ok=1
    local mv arch
    mv=$(macos_product_version); arch=$(/usr/bin/uname -m 2>/dev/null || printf '?')

    log_info "macOS version : $mv"
    log_info "architecture  : $arch"

    if is_root; then log_info "root          : yes"; else log_info "root          : NO"; ok=0; fi

    if version_ge "$mv" "10.13.0"; then
        log_info "secure token  : supported"
    else
        log_info "secure token  : UNSUPPORTED (needs 10.13+)"; ok=0
    fi

    if boot_is_apfs; then log_info "boot volume   : APFS"; else log_info "boot volume   : NOT APFS"; fi

    if mdm_enrolled; then log_info "mdm enrolled  : yes"; else log_info "mdm enrolled  : no"; fi

    local bt="no"
    if bootstrap_token_escrowed; then bt="yes"; fi
    log_info "bootstrap tok : $bt"

    log_info "token holders :"
    local u
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        if token_status "$u"; then log_info "   - $u"; fi
    done <<EOF
$(list_local_users)
EOF

    if [ "$bt" = "yes" ]; then
        log_info "readiness     : READY (credential-free via Bootstrap Token)"
    else
        log_info "readiness     : needs a Secure Token admin (ST_ADMIN_USER/ST_ADMIN_PASSWORD)"
    fi

    if [ "$ok" = "1" ]; then
        emit_result "ok" "$EX_OK" "preflight passed"
        return "$EX_OK"
    fi
    emit_result "error" "$EX_UNSUPPORTED" "preflight found blocking issues"
    return "$EX_UNSUPPORTED"
}

do_status() {
    validate_username "$NEW_USER"
    if ! user_exists "$NEW_USER"; then
        log_warn "User '$NEW_USER' does not exist"
        emit_result "error" "$EX_USAGE" "user does not exist"
        return "$EX_USAGE"
    fi
    if token_status "$NEW_USER"; then
        log_info "User '$NEW_USER' HAS a Secure Token"
        emit_result "ok" "$EX_OK" "secure token enabled"
        return "$EX_OK"
    fi
    log_info "User '$NEW_USER' does NOT have a Secure Token"
    emit_result "ok" "$EX_OK" "secure token disabled"
    # status is a query; report cleanly but signal state via message, not failure
    return "$EX_OK"
}

do_list() {
    log_info "Users with a Secure Token:"
    local u found=0
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        if token_status "$u"; then log_info "  - $u"; found=1; fi
    done <<EOF
$(list_local_users)
EOF
    [ "$found" = "0" ] && log_info "  (none)"
    emit_result "ok" "$EX_OK" "listed token holders"
    return "$EX_OK"
}

do_grant_token() {
    validate_username "$NEW_USER"
    if ! user_exists "$NEW_USER"; then
        die "$EX_USAGE" "User '$NEW_USER' does not exist (use create-user to create it)"
    fi
    [ -n "$NEW_PASSWORD" ] || die "$EX_USAGE" "Target user's password is required to grant a Secure Token (set ST_NEW_PASSWORD)"
    grant_token "$NEW_USER" "$NEW_PASSWORD"
    emit_result "ok" "$EX_OK" "secure token ensured for $NEW_USER"
    return "$EX_OK"
}

do_create_user() {
    validate_username "$NEW_USER"

    # Resolve password: explicit, or generated on request.
    if [ -z "$NEW_PASSWORD" ]; then
        if [ "$GENERATE_PASSWORD" = "1" ]; then
            NEW_PASSWORD=$(generate_password 20)
            GENERATED_PASSWORD="$NEW_PASSWORD"
            log_info "Generated a random password for '$NEW_USER' (surfaced in JSON result)"
        else
            die "$EX_USAGE" "No password supplied (set ST_NEW_PASSWORD or ST_GENERATE_PASSWORD=1)"
        fi
    fi
    validate_password "$NEW_PASSWORD"

    [ -n "$NEW_FULLNAME" ] || NEW_FULLNAME="$NEW_USER"

    # Idempotency: if the user already exists AND already has a token, we are done.
    if user_exists "$NEW_USER" && token_status "$NEW_USER"; then
        log_info "User '$NEW_USER' already exists and holds a Secure Token — nothing to do"
        TOKEN_METHOD="existing"
        emit_result "ok" "$EX_OK" "already provisioned"
        return "$EX_OK"
    fi

    # If the user already exists, we do NOT know their real password, so a
    # caller-supplied password can only work if it matches. Warn loudly.
    if user_exists "$NEW_USER"; then
        log_warn "User '$NEW_USER' already exists; token grant will use the supplied password and will fail if it does not match the account's real password"
    fi

    # Fail fast: confirm a token source is viable BEFORE creating the account, so
    # an invalid admin credential never leaves a tokenless orphan user behind.
    require_token_preconditions
    resolve_token_method

    create_user "$NEW_USER" "$NEW_FULLNAME" "$NEW_PASSWORD"
    grant_token "$NEW_USER" "$NEW_PASSWORD"

    log_info "SUCCESS: '$NEW_USER' created and holds a Secure Token (method=$TOKEN_METHOD)"
    emit_result "ok" "$EX_OK" "user created and secure token granted"
    return "$EX_OK"
}

# ===========================================================================
# Usage
# ===========================================================================
usage() {
    cat <<EOF
securetoken.sh $ST_VERSION — unattended macOS Secure Token provisioning

USAGE
  sudo ./securetoken.sh <action> [options]

ACTIONS
  create-user     Create a user (if needed) and ensure it holds a Secure Token
  grant-token     Grant a Secure Token to an existing user
  status          Report Secure Token status for a user
  list            List all users that hold a Secure Token
  preflight       Report system readiness (macOS, MDM, Bootstrap Token, holders)

OPTIONS (env var equivalents in parentheses)
  --new-user NAME         Username             (ST_NEW_USER)
  --new-fullname NAME     Full/display name    (ST_NEW_FULLNAME)
  --new-password PASS     Password             (ST_NEW_PASSWORD)
  --generate-password     Auto-generate a password (ST_GENERATE_PASSWORD=1)
  --make-admin            Administrator account (ST_MAKE_ADMIN=1)
  --hidden                Hidden account        (ST_HIDDEN=1)
  --uid N                 Explicit UID          (ST_UID)
  --admin-user NAME       Secure Token admin (fallback) (ST_ADMIN_USER)
  --admin-password PASS   Admin password        (ST_ADMIN_PASSWORD)
  --log-file PATH         Log file (default /var/log/securetoken.log) (ST_LOG_FILE)
  --json                  Emit JSON result on stdout (ST_JSON=1)
  --inline-secrets        Pass passwords as args instead of stdin (ST_STDIN_SECRETS=0)
  --no-bootstrap          Do not use the Bootstrap Token (ST_PREFER_BOOTSTRAP=0)
  -h, --help              This help
  -v, --version           Print version

EXIT CODES
  0 ok/idempotent  2 usage  10 not-root  11 unsupported  12 precondition
  20 create-failed  21 grant-failed  22 no-token-source  40 verify-failed

Prefers the escrowed Bootstrap Token (no credentials). Falls back to an
existing Secure Token admin only when required. See docs/DEPLOYMENT.md.
EOF
}

# ===========================================================================
# Argument parsing
# ===========================================================================
FLAG_ACTION="" FLAG_NEW_USER="" FLAG_NEW_FULLNAME="" FLAG_NEW_PASSWORD=""
FLAG_GENERATE_PASSWORD="" FLAG_MAKE_ADMIN="" FLAG_HIDDEN="" FLAG_UID=""
FLAG_ADMIN_USER="" FLAG_ADMIN_PASSWORD="" FLAG_LOG_FILE="" FLAG_JSON=""
FLAG_STDIN_SECRETS="" FLAG_PREFER_BOOTSTRAP=""

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            create-user|grant-token|status|list|preflight)
                FLAG_ACTION="$1" ;;
            --new-user)        FLAG_NEW_USER="${2:-}"; shift ;;
            --new-fullname)    FLAG_NEW_FULLNAME="${2:-}"; shift ;;
            --new-password)    FLAG_NEW_PASSWORD="${2:-}"; shift ;;
            --generate-password) FLAG_GENERATE_PASSWORD="1" ;;
            --make-admin)      FLAG_MAKE_ADMIN="1" ;;
            --hidden)          FLAG_HIDDEN="1" ;;
            --uid)             FLAG_UID="${2:-}"; shift ;;
            --admin-user)      FLAG_ADMIN_USER="${2:-}"; shift ;;
            --admin-password)  FLAG_ADMIN_PASSWORD="${2:-}"; shift ;;
            --log-file)        FLAG_LOG_FILE="${2:-}"; shift ;;
            --json)            FLAG_JSON="1" ;;
            --inline-secrets)  FLAG_STDIN_SECRETS="0" ;;
            --no-bootstrap)    FLAG_PREFER_BOOTSTRAP="0" ;;
            -h|--help)         usage; exit "$EX_OK" ;;
            -v|--version)      printf 'securetoken.sh %s\n' "$ST_VERSION"; exit "$EX_OK" ;;
            *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit "$EX_USAGE" ;;
        esac
        shift
    done
}

resolve_config() {
    ACTION=$(pick "$FLAG_ACTION" "ST_ACTION" "$CONFIG_ACTION" "")
    NEW_USER=$(pick "$FLAG_NEW_USER" "ST_NEW_USER" "$CONFIG_NEW_USER" "")
    NEW_FULLNAME=$(pick "$FLAG_NEW_FULLNAME" "ST_NEW_FULLNAME" "$CONFIG_NEW_FULLNAME" "")
    NEW_PASSWORD=$(pick "$FLAG_NEW_PASSWORD" "ST_NEW_PASSWORD" "$CONFIG_NEW_PASSWORD" "")
    GENERATE_PASSWORD=$(truthy "$(pick "$FLAG_GENERATE_PASSWORD" "ST_GENERATE_PASSWORD" "$CONFIG_GENERATE_PASSWORD" "0")")
    MAKE_ADMIN=$(truthy "$(pick "$FLAG_MAKE_ADMIN" "ST_MAKE_ADMIN" "$CONFIG_MAKE_ADMIN" "0")")
    HIDDEN=$(truthy "$(pick "$FLAG_HIDDEN" "ST_HIDDEN" "$CONFIG_HIDDEN" "0")")
    NEW_UID=$(pick "$FLAG_UID" "ST_UID" "$CONFIG_UID" "")
    ADMIN_USER=$(pick "$FLAG_ADMIN_USER" "ST_ADMIN_USER" "$CONFIG_ADMIN_USER" "")
    ADMIN_PASSWORD=$(pick "$FLAG_ADMIN_PASSWORD" "ST_ADMIN_PASSWORD" "$CONFIG_ADMIN_PASSWORD" "")
    LOG_FILE=$(pick "$FLAG_LOG_FILE" "ST_LOG_FILE" "$CONFIG_LOG_FILE" "/var/log/securetoken.log")
    JSON=$(truthy "$(pick "$FLAG_JSON" "ST_JSON" "$CONFIG_JSON" "0")")
    STDIN_SECRETS=$(truthy "$(pick "$FLAG_STDIN_SECRETS" "ST_STDIN_SECRETS" "$CONFIG_STDIN_SECRETS" "1")")
    PREFER_BOOTSTRAP=$(truthy "$(pick "$FLAG_PREFER_BOOTSTRAP" "ST_PREFER_BOOTSTRAP" "$CONFIG_PREFER_BOOTSTRAP" "1")")

    JSON_MODE="$JSON"
    ACTION=$(pick "$ACTION" "_none_" "" "create-user")  # default action

    # Best-effort log setup; disable file logging rather than failing the run.
    local dir
    dir=$(dirname "$LOG_FILE")
    if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
        LOG_FILE=""
    elif [ -L "$LOG_FILE" ]; then
        # Refuse to write through a symlink at the predictable path (a planted
        # symlink could otherwise redirect our root-owned writes elsewhere).
        LOG_FILE=""
    elif [ ! -e "$LOG_FILE" ]; then
        # Create it non-world-readable up front.
        ( umask 077; : >>"$LOG_FILE" ) 2>/dev/null || LOG_FILE=""
    fi
}

# ===========================================================================
# Main
# ===========================================================================
main() {
    parse_args "$@"
    resolve_config

    # macOS-only tool. Guard so accidental runs elsewhere fail clearly.
    if [ "$(uname -s)" != "Darwin" ]; then
        die "$EX_UNSUPPORTED" "This tool runs on macOS only (uname=$(uname -s))"
    fi

    if ! is_root; then
        die "$EX_NOT_ROOT" "Must run as root (use sudo, or an RMM/Intune 'run as root' policy)"
    fi

    if ! version_ge "$(macos_product_version)" "10.13.0"; then
        die "$EX_UNSUPPORTED" "Secure Tokens require macOS 10.13+ (found $(macos_product_version))"
    fi

    log_info "securetoken $ST_VERSION action=$ACTION user=${NEW_USER:-<none>} stdin_secrets=$STDIN_SECRETS"

    case "$ACTION" in
        preflight)   do_preflight ;;
        status)      do_status ;;
        list)        do_list ;;
        grant-token) do_grant_token ;;
        create-user) do_create_user ;;
        *) die "$EX_USAGE" "Unknown action '$ACTION'" ;;
    esac
}

# Allow tests to source this file without executing main.
if [ "${ST_LIB_ONLY:-0}" != "1" ]; then
    main "$@"
fi
