#!/bin/bash
#
# securetoken.sh — Unattended macOS Secure Token provisioning
# ============================================================
#
# Creates a local user account and ensures it ends up holding a Secure Token,
# with ZERO interactive prompts, so it can be deployed from an RMM (NinjaOne,
# Datto, Kaseya, Addigy, Mosyle, Level, Syncro, ...) or Microsoft Intune.
#
# ---------------------------------------------------------------------------
# HOW SECURE TOKENS ARE ACTUALLY GRANTED (read this before changing the logic)
#
# Per Apple's Platform Deployment guide ("Use secure token, bootstrap token, and
# volume ownership in deployments", support.apple.com/guide/deployment/dep24dbdcf9e):
#
#   1. "Changing the secure token status of a user using sysadminctl ALWAYS
#      requires the user name and password of an existing secure token-enabled
#      administrator, either interactively or through the appropriate flags."
#
#      => There is NO credential-free sysadminctl grant. A Bootstrap Token
#         cannot be spent by sysadminctl.
#
#   2. "For a Mac with macOS 11 or later, if macOS doesn't grant a secure token
#      at creation, and if a bootstrap token is available from the device
#      management service, it grants a secure token to the local user WHEN THEY
#      LOG IN."
#
#      => The Bootstrap Token IS credential-free, but the grant happens at the
#         user's FIRST LOGIN, not at provisioning time.
#
# This tool therefore supports exactly those two real mechanisms:
#
#   PLAN "admin"    — a Secure Token administrator's credentials are supplied.
#                     The token is granted immediately and verified. Preferred,
#                     because the result is confirmable during the run.
#
#   PLAN "deferred" — no admin credentials, but the Mac is MDM-enrolled with an
#                     escrowed Bootstrap Token (macOS 11+). The account is
#                     created and macOS grants the token at first login. The run
#                     reports tokenMethod="deferred-login" and (by default)
#                     succeeds; set ST_REQUIRE_IMMEDIATE_TOKEN=1 to treat this
#                     as a failure instead.
#
# ---------------------------------------------------------------------------
# COMPATIBILITY
#   * Targets /bin/bash 3.2 (the version shipped on every macOS). No bash-4+
#     features (no ${x,,}, no associative arrays, no mapfile) are used.
#   * macOS 10.13+ for Secure Tokens. Bootstrap Token escrow needs 10.15.4+;
#     the grant-at-login behaviour for scripted local users needs macOS 11+.
#   * Runs as root (required).
#
# CONFIGURATION (three layers, highest priority first)
#   1. Command-line flags        (e.g. --new-user jsmith)
#   2. Environment variables     (e.g. ST_NEW_USER=jsmith) — RMM/Intune inject here
#   3. The CONFIG block below    (edit for single-file Intune uploads)
#
# See docs/DEPLOYMENT.md for step-by-step platform instructions.
#
# License: MIT
#
set -euo pipefail

# Sanitise PATH before invoking any helper: this script runs as root, and an
# inherited PATH from an RMM agent could otherwise resolve tr/grep/awk to an
# attacker-controlled binary.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

# ===========================================================================
# CONFIG BLOCK — edit these for single-file (Intune) deployments.
# Leave blank to drive everything from environment variables / CLI flags.
# Anything set here is used ONLY when the matching env var / flag is absent.
# ===========================================================================
CONFIG_ACTION=""            # create-user | grant-token | status | list | preflight | delete-user
CONFIG_NEW_USER=""          # username to create / target
CONFIG_NEW_FULLNAME=""      # full (display) name
CONFIG_NEW_PASSWORD=""      # password (leave blank + CONFIG_GENERATE_PASSWORD=1 to auto-generate)
CONFIG_GENERATE_PASSWORD="" # 1 = generate a strong random password
CONFIG_MAKE_ADMIN=""        # 1 = administrator, 0 = standard
CONFIG_HIDDEN=""            # 1 = hidden account (low UID, hidden from login window)
CONFIG_UID=""               # explicit UID (optional)
CONFIG_ADMIN_USER=""        # existing Secure Token admin (enables the immediate grant)
CONFIG_ADMIN_PASSWORD=""    # that admin's password
CONFIG_LOG_FILE=""          # default: /var/log/securetoken.log
CONFIG_JSON=""              # 1 = emit a machine-readable JSON result line on stdout
CONFIG_SECRET_MODE=""       # inline (default) | stdin  — see run_sysadminctl notes
CONFIG_REQUIRE_IMMEDIATE="" # 1 = a deferred (first-login) grant is a FAILURE
CONFIG_ROLLBACK=""          # 1 = delete a just-created account if the grant fails
CONFIG_TIMEOUT=""           # seconds per sysadminctl call (default 120)
# ===========================================================================

# NOTE: deliberately NOT 'readonly'. The documented library mode
# (ST_LIB_ONLY=1 . securetoken.sh) and the test suite source this file more than
# once per shell; on bash 3.2 re-assigning a readonly variable is a fatal error.
ST_VERSION="3.1.0"

# ---- Exit codes (stable contract for RMM/Intune result parsing) -----------
EX_OK=0                # success, or already in desired state
EX_USAGE=2             # invalid arguments / configuration
EX_NOT_ROOT=10         # not running as root
EX_UNSUPPORTED=11      # macOS version / platform unsupported
EX_PRECOND=12          # precondition failed (e.g. boot volume not APFS)
EX_CREATE_FAILED=20    # user creation failed
EX_GRANT_FAILED=21     # secure token grant failed
EX_NO_TOKEN_SOURCE=22  # no admin credentials and no Bootstrap Token
EX_TOKEN_DEFERRED=23   # token deferred to first login, but caller demanded immediate
EX_LOCKED=24           # another instance is already running
EX_VERIFY_FAILED=40    # post-operation verification failed

# ---- Runtime state --------------------------------------------------------
LOG_FILE=""
LOG_FD_OPEN=0
JSON_MODE=0
GENERATED_PASSWORD=""   # generated password, ONLY surfaced once actually applied
PASSWORD_APPLIED=0      # 1 once the account exists with the password we set
TOKEN_METHOD=""         # admin | deferred-login | existing | none
TOKEN_PLAN=""           # admin | deferred
USER_WAS_CREATED=0      # for rollback
LOCK_DIR=""
EXTRA_JSON=""           # additional JSON fields for the current action

# ===========================================================================
# Configuration resolution: flag  >  env  >  CONFIG block  >  default
# ===========================================================================
ACTION="" NEW_USER="" NEW_FULLNAME="" NEW_PASSWORD="" GENERATE_PASSWORD=0
MAKE_ADMIN=0 HIDDEN=0 NEW_UID="" ADMIN_USER="" ADMIN_PASSWORD=""
JSON=0 SECRET_MODE="inline" REQUIRE_IMMEDIATE=0 ROLLBACK=0 SYS_TIMEOUT=120

# pick <flag_value> <env_name> <config_value> <default>
pick() {
    local flag="$1" env_name="$2" config="$3" default="$4"
    if [ -n "$flag" ]; then printf '%s' "$flag"; return 0; fi
    local env_val=""
    eval "env_val=\${$env_name:-}"
    if [ -n "$env_val" ]; then printf '%s' "$env_val"; return 0; fi
    if [ -n "$config" ]; then printf '%s' "$config"; return 0; fi
    printf '%s' "$default"
}

# Normalize a truthy string to 1/0. Trims surrounding whitespace and CR first —
# RMM consoles and Windows-authored variables routinely append them, and an
# invisible trailing CR must not silently mean "false".
truthy() {
    local v
    v=$(printf '%s' "${1:-}" | tr -d '\r\n\t ' | tr '[:upper:]' '[:lower:]')
    case "$v" in
        1|true|yes|on|y) printf '1' ;;
        *) printf '0' ;;
    esac
}

# Strip C0 control characters from a value destined for the log, so a crafted
# username cannot forge extra log lines.
sanitize_for_log() {
    printf '%s' "${1:-}" | tr -d '\000-\037'
}

# Trim LEADING/TRAILING whitespace (incl. CR) only — RMM consoles append it, but
# interior whitespace must survive so an invalid value like "bad name" is
# REJECTED by validation rather than silently rewritten to "badname".
trim() {
    local s="${1:-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# ===========================================================================
# Logging — file + stderr. stdout is reserved for the JSON result line so RMM
# "output" parsing stays clean. Secrets are NEVER logged.
# ===========================================================================
_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

_log() {
    local level="$1"; shift
    local line
    line="$(_ts) [$level] $(sanitize_for_log "$*")"
    printf '%s\n' "$line" >&2
    if [ "$LOG_FD_OPEN" = "1" ]; then
        printf '%s\n' "$line" >&3 2>/dev/null || true
    fi
}
log_info()  { _log "INFO"  "$@"; }
log_warn()  { _log "WARN"  "$@"; }
log_error() { _log "ERROR" "$@"; }
log_debug() { if [ "${ST_DEBUG:-0}" = "1" ]; then _log "DEBUG" "$@"; fi; }

# ===========================================================================
# JSON result emission (no jq dependency; macOS ships none).
# ===========================================================================
json_escape() {
    local s="${1:-}"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    # Escape any remaining C0 control characters as \u00XX so the emitted line is
    # valid JSON for strict parsers (PowerShell ConvertFrom-Json, jq, python).
    case "$s" in
        *[$'\001'-$'\037']*)
            local out="" i ch
            i=0
            while [ "$i" -lt "${#s}" ]; do
                ch=${s:$i:1}
                case "$ch" in
                    [$'\001'-$'\037'])
                        out="$out$(printf '\\u%04x' "'$ch")" ;;
                    *) out="$out$ch" ;;
                esac
                i=$((i + 1))
            done
            s="$out"
            ;;
    esac
    printf '%s' "$s"
}

# emit_result <status> <exit_code> <message>
emit_result() {
    local status="$1" code="$2" message="$3"
    [ "$JSON_MODE" = "1" ] || return 0
    local pw_field=""
    # Only surface a generated password once it was actually applied to the
    # account — otherwise the RMM would record a credential that does not work.
    # Conversely, if it WAS applied we must surface it even on a later failure,
    # or the account becomes unreachable.
    if [ -n "$GENERATED_PASSWORD" ] && [ "$PASSWORD_APPLIED" = "1" ]; then
        pw_field=",\"generatedPassword\":\"$(json_escape "$GENERATED_PASSWORD")\""
    fi
    printf '{"tool":"securetoken","version":"%s","status":"%s","exitCode":%s,"action":"%s","user":"%s","tokenMethod":"%s","message":"%s"%s%s}\n' \
        "$ST_VERSION" \
        "$(json_escape "$status")" \
        "$code" \
        "$(json_escape "$ACTION")" \
        "$(json_escape "$NEW_USER")" \
        "$(json_escape "${TOKEN_METHOD:-none}")" \
        "$(json_escape "$message")" \
        "$EXTRA_JSON" \
        "$pw_field"
}

die() {
    local code="$1"; shift
    log_error "$*"
    maybe_rollback
    emit_result "error" "$code" "$*"
    exit "$code"
}

# ===========================================================================
# Platform / environment probes
# ===========================================================================
is_root() { [ "$(id -u)" -eq 0 ]; }

macos_product_version() { sw_vers -productVersion 2>/dev/null || printf '0.0.0'; }

# version_ge <a> <b> : true if version a >= b (dotted numeric compare)
version_ge() {
    local a="$1" b="$2"
    local IFS=.
    # shellcheck disable=SC2206  # deliberate word-split on dots
    local av=($a) bv=($b)
    local i an bn
    for i in 0 1 2; do
        an="${av[i]:-0}"; bn="${bv[i]:-0}"
        an=$(printf '%s' "$an" | tr -cd '0-9'); an=${an:-0}
        bn=$(printf '%s' "$bn" | tr -cd '0-9'); bn=${bn:-0}
        if [ "$an" -gt "$bn" ]; then return 0; fi
        if [ "$an" -lt "$bn" ]; then return 1; fi
    done
    return 0
}

is_apple_silicon() { [ "$(uname -m 2>/dev/null || printf '?')" = "arm64" ]; }

boot_is_apfs() {
    diskutil info / 2>/dev/null | grep -qiE "Type \(Bundle\):[[:space:]]*apfs|File System Personality:.*APFS"
}

mdm_enrolled() {
    profiles status -type enrollment 2>/dev/null | grep -qi "MDM enrollment: Yes"
}

bootstrap_token_escrowed() {
    profiles status -type bootstraptoken 2>/dev/null \
        | grep -qi "Bootstrap Token escrowed to server: YES"
}

# Can this Mac grant a Secure Token at first login via the Bootstrap Token?
# Requires macOS 11+ (grant-at-login for scripted local users) and an escrowed
# token. Escrow itself requires 10.15.4+, which 11+ implies.
bootstrap_login_grant_available() {
    version_ge "$(macos_product_version)" "11.0.0" \
        && mdm_enrolled && bootstrap_token_escrowed
}

# ===========================================================================
# Directory-service helpers
# ===========================================================================
user_exists() { dscl . -read "/Users/$1" >/dev/null 2>&1; }

token_status() {
    local out
    out=$(sysadminctl -secureTokenStatus "$1" 2>&1 || true)
    printf '%s' "$out" | grep -qi "ENABLED"
}

# Verify a password actually authenticates for a user. This is how we validate
# admin credentials BEFORE creating anything, and how we confirm the new
# account's password really took.
password_authenticates() {
    local user="$1" pass="$2"
    dscl . -authonly "$user" "$pass" >/dev/null 2>&1
}

# Prints the local (non-system) user list. Fails (non-zero) if dscl itself
# fails, so callers can distinguish "no users" from "could not enumerate".
list_local_users() {
    local out
    out=$(dscl . -list /Users 2>/dev/null) || return 1
    printf '%s\n' "$out" | grep -vE '^_' | grep -vxE 'daemon|nobody|root' || true
}

uid_in_use() {
    dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' | grep -qx "$1"
}

# first_unused_uid <floor> <ceiling> : reads used UIDs on stdin, prints the
# first UID in [floor, ceiling) not present. Returns 1 if exhausted. Pure.
first_unused_uid() {
    local floor="$1" ceiling="$2" used candidate
    used=$(cat)
    candidate="$floor"
    while [ "$candidate" -lt "$ceiling" ]; do
        if ! printf '%s\n' "$used" | grep -qx "$candidate"; then
            printf '%s' "$candidate"; return 0
        fi
        candidate=$((candidate + 1))
    done
    return 1
}

next_free_uid() {
    local floor="$1" ceiling="${2:-500}"
    dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' \
        | first_unused_uid "$floor" "$ceiling"
}

# ===========================================================================
# Validation
# ===========================================================================
RESERVED_USERS="root daemon nobody admin wheel kmem sys tty staff"

validate_username() {
    local u="${1:-}"
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
    return 0
}

validate_password() {
    local p="${1:-}" label="${2:-Password}"
    if [ "${#p}" -lt 4 ]; then die "$EX_USAGE" "$label must be at least 4 characters"; fi
    # A newline or carriage return would truncate the value (inline) or
    # misalign the stdin feed, silently setting a different password.
    case "$p" in
        *$'\n'*|*$'\r'*) die "$EX_USAGE" "$label must not contain newline or carriage-return characters" ;;
    esac
    return 0
}

validate_uid() {
    local u="${1:-}"
    [ -n "$u" ] || return 0
    case "$u" in
        ''|*[!0-9]*) die "$EX_USAGE" "UID must be numeric: '$u'" ;;
    esac
    if [ "$u" -lt 200 ] || [ "$u" -gt 2147483647 ]; then
        die "$EX_USAGE" "UID $u is outside the safe range 200-2147483647"
    fi
    if uid_in_use "$u"; then
        die "$EX_USAGE" "UID $u is already assigned to an existing account"
    fi
    return 0
}

# Generate a strong random password.
#
# Reads BOUNDED chunks from /dev/urandom so `tr` is never killed by SIGPIPE
# (an unbounded `tr < /dev/urandom | head -c N` exits 141 under pipefail and
# only survives set -e by a bash quirk), and loops until the exact length is
# reached even if filtering discards most bytes.
generate_password() {
    local len="${1:-20}" out="" chunk
    local alphabet='A-HJ-NP-Za-km-z2-9!@#%^&*_+='
    while [ "${#out}" -lt "$len" ]; do
        chunk=$(LC_ALL=C head -c 512 /dev/urandom 2>/dev/null | LC_ALL=C tr -dc "$alphabet" 2>/dev/null || true)
        if [ -z "$chunk" ]; then
            die "$EX_PRECOND" "Unable to read randomness from /dev/urandom"
        fi
        out="$out$chunk"
    done
    out=${out:0:$len}
    # Never start with '-': sysadminctl would parse it as an option flag.
    case "$out" in
        -*) out="s${out:1}" ;;
    esac
    printf '%s' "$out"
}

# ===========================================================================
# Single-instance lock — two overlapping RMM runs must not both create the
# account with different generated passwords. mkdir is atomic on macOS.
# ===========================================================================
acquire_lock() {
    local dir="/var/run/securetoken.lock"
    if ! mkdir "$dir" 2>/dev/null; then
        # Reap a stale lock whose owner is gone.
        local owner=""
        owner=$(cat "$dir/pid" 2>/dev/null || true)
        if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
            log_warn "Removing stale lock from dead pid $owner"
            rm -rf "$dir" 2>/dev/null || true
            mkdir "$dir" 2>/dev/null || die "$EX_LOCKED" "Another securetoken run is in progress"
        else
            die "$EX_LOCKED" "Another securetoken run is in progress (pid ${owner:-unknown})"
        fi
    fi
    printf '%s' "$$" >"$dir/pid" 2>/dev/null || true
    LOCK_DIR="$dir"
}

release_lock() {
    if [ -n "$LOCK_DIR" ] && [ -d "$LOCK_DIR" ]; then
        rm -rf "$LOCK_DIR" 2>/dev/null || true
        LOCK_DIR=""
    fi
}

cleanup() { release_lock; }
trap cleanup EXIT INT TERM

# ===========================================================================
# sysadminctl invocation
#
# SECRET_MODE=inline (DEFAULT): credentials are passed as arguments. This is the
#   path Apple documents for scripting ("directly with the -adminUser and
#   -adminPassword flags") and the only one that reliably works headless.
#   Trade-off: the password is briefly visible in `ps` to local users.
#
# SECRET_MODE=stdin: passes '-' placeholders so sysadminctl PROMPTS for each
#   secret. Apple documents '-' as the INTERACTIVE option; it reads the
#   controlling terminal, so under Intune/RMM (no TTY) it can hang or fail.
#   Offered only as an opt-in for interactive/TTY use. Every call is run under a
#   watchdog so an unexpected prompt can never hang an RMM job forever.
#
# Usage:
#   SYS_ARGS=( -addUser foo -password @@ST_SECRET@@ )
#   SYS_SECRETS=( "$password" )
#   run_sysadminctl   # sets SYS_OUT, returns sysadminctl's rc (124 on timeout)
# ===========================================================================
SYS_OUT=""
BUILT_ARGS=()
BUILT_FED=()

# Pure transform, unit-testable on any OS.
build_sysadminctl_args() {
    BUILT_ARGS=()
    BUILT_FED=()
    local a secret si=0
    for a in ${SYS_ARGS[@]+"${SYS_ARGS[@]}"}; do
        if [ "$a" = "@@ST_SECRET@@" ]; then
            secret="${SYS_SECRETS[si]:-}"
            si=$((si + 1))
            if [ "$SECRET_MODE" = "stdin" ]; then
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

# Run a command with a wall-clock watchdog. Returns 124 if it had to be killed.
# macOS has no GNU `timeout`, so this is implemented with a background pid.
run_with_timeout() {
    local secs="$1" outfile="$2"; shift 2
    "$@" >"$outfile" 2>&1 &
    local pid=$! waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge "$secs" ]; then
            kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
        waited=$((waited + 1))
    done
    local rc=0
    wait "$pid" || rc=$?
    return "$rc"
}

run_sysadminctl() {
    build_sysadminctl_args
    local rc=0 tmp
    tmp=$(mktemp /tmp/securetoken.XXXXXX) || die "$EX_PRECOND" "Cannot create temp file"

    if [ "$SECRET_MODE" = "stdin" ] && [ "${#BUILT_FED[@]}" -gt 0 ]; then
        local feed
        feed=$(mktemp /tmp/securetoken.XXXXXX) || die "$EX_PRECOND" "Cannot create temp file"
        chmod 600 "$feed" 2>/dev/null || true
        printf '%s\n' ${BUILT_FED[@]+"${BUILT_FED[@]}"} >"$feed"
        # shellcheck disable=SC2016  # $@/$0 must expand in the INNER sh, not here
        run_with_timeout "$SYS_TIMEOUT" "$tmp" \
            /bin/sh -c 'exec /usr/sbin/sysadminctl "$@" < "$0"' "$feed" ${BUILT_ARGS[@]+"${BUILT_ARGS[@]}"} || rc=$?
        rm -f "$feed" 2>/dev/null || true
    else
        run_with_timeout "$SYS_TIMEOUT" "$tmp" \
            /usr/sbin/sysadminctl ${BUILT_ARGS[@]+"${BUILT_ARGS[@]}"} || rc=$?
    fi

    SYS_OUT=$(cat "$tmp" 2>/dev/null || true)
    rm -f "$tmp" 2>/dev/null || true

    # Scrub secrets from lingering globals as soon as the call returns.
    SYS_SECRETS=()
    BUILT_FED=()
    BUILT_ARGS=()

    if [ "$rc" = "124" ]; then
        log_error "sysadminctl timed out after ${SYS_TIMEOUT}s (an interactive prompt in a headless session is the usual cause; SECRET_MODE=$SECRET_MODE)"
    fi
    log_debug "sysadminctl rc=$rc"
    return "$rc"
}

# ===========================================================================
# Core operations
# ===========================================================================
require_token_preconditions() {
    if ! boot_is_apfs; then
        die "$EX_PRECOND" "Boot volume is not APFS; Secure Tokens are unavailable on this system"
    fi
    return 0
}

# Decide how the token will be obtained. Sets TOKEN_PLAN to "admin" or
# "deferred". Dies EX_NO_TOKEN_SOURCE when neither is possible.
#
# The admin path is preferred because it grants immediately and is verifiable
# during this run; the Bootstrap Token path cannot be spent by sysadminctl and
# only takes effect at the user's first login.
resolve_token_plan() {
    if [ -n "$TOKEN_PLAN" ]; then return 0; fi

    if [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASSWORD" ]; then
        if ! user_exists "$ADMIN_USER"; then
            die "$EX_NO_TOKEN_SOURCE" "Token admin '$ADMIN_USER' does not exist"
        fi
        if ! token_status "$ADMIN_USER"; then
            die "$EX_NO_TOKEN_SOURCE" "Token admin '$ADMIN_USER' does not hold a Secure Token"
        fi
        # Validate the credential NOW, before creating anything, so a stale
        # password cannot leave a tokenless orphan account behind.
        if ! password_authenticates "$ADMIN_USER" "$ADMIN_PASSWORD"; then
            die "$EX_NO_TOKEN_SOURCE" "Token admin '$ADMIN_USER' password is incorrect (verified with dscl -authonly)"
        fi
        TOKEN_PLAN="admin"
        log_info "Token plan: immediate grant using Secure Token admin '$ADMIN_USER'"
        return 0
    fi

    if bootstrap_login_grant_available; then
        TOKEN_PLAN="deferred"
        log_info "Token plan: no admin credentials supplied; Bootstrap Token will grant the Secure Token at the user's FIRST LOGIN (macOS 11+)"
        return 0
    fi

    die "$EX_NO_TOKEN_SOURCE" \
        "No Secure Token admin credentials supplied (ST_ADMIN_USER/ST_ADMIN_PASSWORD) and no Bootstrap Token available for a first-login grant. sysadminctl cannot grant a Secure Token without an existing token holder's credentials."
}

create_user() {
    local user="$1" fullname="$2" password="$3"

    if user_exists "$user"; then
        log_info "User '$user' already exists — skipping creation"
        return 0
    fi

    local uid="$NEW_UID"
    if [ "$HIDDEN" = "1" ] && [ -z "$uid" ]; then
        uid=$(next_free_uid 200 500) || uid=""
        if [ -z "$uid" ]; then
            log_warn "No free UID in 200-499; letting macOS assign one (account will still be marked hidden)"
        fi
    fi

    log_info "Creating user '$user' (admin=$MAKE_ADMIN hidden=$HIDDEN uid=${uid:-auto})"

    SYS_ARGS=( -addUser "$user" -fullName "$fullname" -password @@ST_SECRET@@ )
    SYS_SECRETS=( "$password" )
    if [ -n "$uid" ]; then SYS_ARGS+=( -UID "$uid" ); fi
    if [ "$MAKE_ADMIN" = "1" ]; then SYS_ARGS+=( -admin ); fi

    if ! run_sysadminctl; then
        die "$EX_CREATE_FAILED" "Failed to create user '$user': $SYS_OUT"
    fi
    if ! user_exists "$user"; then
        die "$EX_CREATE_FAILED" "User '$user' not present after creation: $SYS_OUT"
    fi
    USER_WAS_CREATED=1

    # Confirm the password we believe we set actually authenticates. This is what
    # catches a mis-fed secret (e.g. a literal "-" password from a prompt that
    # never received input) before we hand the credential back to the RMM.
    if password_authenticates "$user" "$password"; then
        PASSWORD_APPLIED=1
    else
        die "$EX_CREATE_FAILED" "User '$user' was created but the intended password does not authenticate (secret mode '$SECRET_MODE' may not have delivered it). Investigate before using this account."
    fi

    createhomedir -c -u "$user" >/dev/null 2>&1 || true

    if [ "$HIDDEN" = "1" ]; then
        if ! dscl . -create "/Users/$user" IsHidden 1 >/dev/null 2>&1; then
            log_warn "Could not set IsHidden on '$user' — the account will be visible at the login window"
        fi
    fi

    log_info "User '$user' created"
}

# Roll back a just-created account when a later step fails (opt-in).
maybe_rollback() {
    if [ "$ROLLBACK" != "1" ] || [ "$USER_WAS_CREATED" != "1" ] || [ -z "$NEW_USER" ]; then
        return 0
    fi
    log_warn "Rolling back: deleting just-created account '$NEW_USER'"
    SYS_ARGS=( -deleteUser "$NEW_USER" )
    SYS_SECRETS=()
    if run_sysadminctl; then
        log_info "Rollback complete — '$NEW_USER' removed"
        USER_WAS_CREATED=0
        PASSWORD_APPLIED=0
    else
        log_error "Rollback FAILED for '$NEW_USER': $SYS_OUT"
    fi
}

# Ensure <user> holds a Secure Token, or that a deferred grant is arranged.
grant_token() {
    local user="$1" password="$2"

    if token_status "$user"; then
        log_info "User '$user' already holds a Secure Token — nothing to do"
        TOKEN_METHOD="existing"
        return 0
    fi

    require_token_preconditions
    resolve_token_plan

    if [ "$TOKEN_PLAN" = "deferred" ]; then
        TOKEN_METHOD="deferred-login"
        if [ "$REQUIRE_IMMEDIATE" = "1" ]; then
            die "$EX_TOKEN_DEFERRED" "No admin credentials supplied: the Secure Token can only be granted at first login via the Bootstrap Token, but ST_REQUIRE_IMMEDIATE_TOKEN=1 was set"
        fi
        log_info "Secure Token will be granted by macOS at '$user' first login (Bootstrap Token). No token is present yet — this is expected."
        return 0
    fi

    SYS_ARGS=( -secureTokenOn "$user" -password @@ST_SECRET@@ \
               -adminUser "$ADMIN_USER" -adminPassword @@ST_SECRET@@ )
    SYS_SECRETS=( "$password" "$ADMIN_PASSWORD" )

    if ! run_sysadminctl; then
        die "$EX_GRANT_FAILED" "Failed to grant Secure Token to '$user': $SYS_OUT"
    fi
    # sysadminctl frequently exits 0 even when the grant failed, so the
    # authoritative check is the status re-read.
    if ! token_status "$user"; then
        die "$EX_VERIFY_FAILED" "Secure Token not ENABLED for '$user' after grant: $SYS_OUT"
    fi
    TOKEN_METHOD="admin"
    log_info "Secure Token granted to '$user' via admin '$ADMIN_USER'"
}

# ===========================================================================
# Actions
# ===========================================================================
do_preflight() {
    log_info "securetoken $ST_VERSION preflight"
    local ok=1 mv arch
    mv=$(macos_product_version); arch=$(uname -m 2>/dev/null || printf '?')

    log_info "macOS version : $mv"
    log_info "architecture  : $arch"
    if is_root; then log_info "root          : yes"; else log_info "root          : NO"; ok=0; fi
    if version_ge "$mv" "10.13.0"; then
        log_info "secure token  : supported"
    else
        log_info "secure token  : UNSUPPORTED (needs 10.13+)"; ok=0
    fi

    local apfs="no" mdm="no" bt="no" login_grant="no"
    if boot_is_apfs; then apfs="yes"; fi
    if mdm_enrolled; then mdm="yes"; fi
    if bootstrap_token_escrowed; then bt="yes"; fi
    if bootstrap_login_grant_available; then login_grant="yes"; fi
    log_info "boot volume   : $([ "$apfs" = yes ] && printf 'APFS' || printf 'NOT APFS')"
    log_info "mdm enrolled  : $mdm"
    log_info "bootstrap tok : $bt (first-login grant available: $login_grant)"

    local holders="" u enum_ok=1
    if ! u=$(list_local_users); then
        log_error "Could not enumerate local users (dscl failed)"
        enum_ok=0; ok=0
    else
        local name
        while IFS= read -r name; do
            [ -z "$name" ] && continue
            if token_status "$name"; then
                holders="$holders $name"
                log_info "token holder  : $name"
            fi
        done <<EOF
$u
EOF
        [ -n "$holders" ] || log_info "token holder  : (none)"
    fi

    local readiness
    if [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASSWORD" ]; then
        readiness="admin credentials supplied — immediate grant possible"
    elif [ "$login_grant" = "yes" ]; then
        readiness="no admin credentials — token will be granted at first login (Bootstrap Token)"
    else
        readiness="NOT READY: supply ST_ADMIN_USER/ST_ADMIN_PASSWORD (a Secure Token holder), or enrol with an escrowed Bootstrap Token"
        ok=0
    fi
    log_info "readiness     : $readiness"

    # Machine-readable payload: preflight is the action operators are told to run
    # first, so its JSON must carry the data it reports.
    EXTRA_JSON=",\"macosVersion\":\"$(json_escape "$mv")\",\"arch\":\"$(json_escape "$arch")\""
    EXTRA_JSON="$EXTRA_JSON,\"isRoot\":$(is_root && printf 'true' || printf 'false')"
    EXTRA_JSON="$EXTRA_JSON,\"bootIsAPFS\":$([ "$apfs" = yes ] && printf 'true' || printf 'false')"
    EXTRA_JSON="$EXTRA_JSON,\"mdmEnrolled\":$([ "$mdm" = yes ] && printf 'true' || printf 'false')"
    EXTRA_JSON="$EXTRA_JSON,\"bootstrapTokenEscrowed\":$([ "$bt" = yes ] && printf 'true' || printf 'false')"
    EXTRA_JSON="$EXTRA_JSON,\"firstLoginGrantAvailable\":$([ "$login_grant" = yes ] && printf 'true' || printf 'false')"
    EXTRA_JSON="$EXTRA_JSON,\"userEnumerationOk\":$([ "$enum_ok" = 1 ] && printf 'true' || printf 'false')"
    EXTRA_JSON="$EXTRA_JSON,\"tokenHolders\":[$(printf '%s' "$holders" | awk '{for(i=1;i<=NF;i++) printf "%s\"%s\"", (i>1?",":""), $i}')]"

    if [ "$ok" = "1" ]; then
        emit_result "ok" "$EX_OK" "preflight passed: $readiness"
        return "$EX_OK"
    fi
    emit_result "error" "$EX_UNSUPPORTED" "preflight found blocking issues: $readiness"
    return "$EX_UNSUPPORTED"
}

do_status() {
    validate_username "$NEW_USER"
    if ! user_exists "$NEW_USER"; then
        log_warn "User '$NEW_USER' does not exist"
        EXTRA_JSON=",\"userExists\":false,\"hasSecureToken\":false"
        emit_result "error" "$EX_USAGE" "user does not exist"
        return "$EX_USAGE"
    fi
    if token_status "$NEW_USER"; then
        TOKEN_METHOD="existing"
        log_info "User '$NEW_USER' HAS a Secure Token"
        EXTRA_JSON=",\"userExists\":true,\"hasSecureToken\":true"
        emit_result "ok" "$EX_OK" "secure token enabled"
        return "$EX_OK"
    fi
    TOKEN_METHOD="none"
    log_info "User '$NEW_USER' does NOT have a Secure Token"
    EXTRA_JSON=",\"userExists\":true,\"hasSecureToken\":false"
    emit_result "ok" "$EX_OK" "secure token disabled"
    return "$EX_OK"
}

do_list() {
    local users
    if ! users=$(list_local_users); then
        die "$EX_PRECOND" "Could not enumerate local users (dscl failed)"
    fi
    log_info "Users with a Secure Token:"
    local u holders=""
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        if token_status "$u"; then log_info "  - $u"; holders="$holders $u"; fi
    done <<EOF
$users
EOF
    [ -n "$holders" ] || log_info "  (none)"
    EXTRA_JSON=",\"tokenHolders\":[$(printf '%s' "$holders" | awk '{for(i=1;i<=NF;i++) printf "%s\"%s\"", (i>1?",":""), $i}')]"
    emit_result "ok" "$EX_OK" "listed token holders"
    return "$EX_OK"
}

do_grant_token() {
    validate_username "$NEW_USER"
    if ! user_exists "$NEW_USER"; then
        die "$EX_USAGE" "User '$NEW_USER' does not exist (use create-user to create it)"
    fi
    if token_status "$NEW_USER"; then
        TOKEN_METHOD="existing"
        log_info "User '$NEW_USER' already holds a Secure Token"
        emit_result "ok" "$EX_OK" "already has a secure token"
        return "$EX_OK"
    fi
    [ -n "$NEW_PASSWORD" ] || die "$EX_USAGE" "Target user's password is required to grant a Secure Token (set ST_NEW_PASSWORD)"
    validate_password "$NEW_PASSWORD" "Target password"
    grant_token "$NEW_USER" "$NEW_PASSWORD"
    if [ "$TOKEN_METHOD" = "deferred-login" ]; then
        emit_result "ok" "$EX_OK" "secure token will be granted at first login (Bootstrap Token)"
    else
        emit_result "ok" "$EX_OK" "secure token ensured for $NEW_USER"
    fi
    return "$EX_OK"
}

do_delete_user() {
    validate_username "$NEW_USER"
    if ! user_exists "$NEW_USER"; then
        log_info "User '$NEW_USER' does not exist — nothing to delete"
        emit_result "ok" "$EX_OK" "user does not exist"
        return "$EX_OK"
    fi
    log_warn "Deleting user '$NEW_USER'"
    SYS_ARGS=( -deleteUser "$NEW_USER" )
    SYS_SECRETS=()
    if ! run_sysadminctl; then
        die "$EX_CREATE_FAILED" "Failed to delete '$NEW_USER': $SYS_OUT"
    fi
    if user_exists "$NEW_USER"; then
        die "$EX_VERIFY_FAILED" "User '$NEW_USER' still present after delete: $SYS_OUT"
    fi
    log_info "User '$NEW_USER' deleted"
    emit_result "ok" "$EX_OK" "user deleted"
    return "$EX_OK"
}

do_create_user() {
    validate_username "$NEW_USER"
    validate_uid "$NEW_UID"

    if [ -z "$NEW_PASSWORD" ]; then
        if [ "$GENERATE_PASSWORD" = "1" ]; then
            NEW_PASSWORD=$(generate_password 20)
            GENERATED_PASSWORD="$NEW_PASSWORD"
            log_info "Generated a random password for '$NEW_USER' (returned in the JSON result once applied)"
        else
            die "$EX_USAGE" "No password supplied (set ST_NEW_PASSWORD or ST_GENERATE_PASSWORD=1)"
        fi
    fi
    validate_password "$NEW_PASSWORD" "New user password"

    [ -n "$NEW_FULLNAME" ] || NEW_FULLNAME="$NEW_USER"

    if user_exists "$NEW_USER" && token_status "$NEW_USER"; then
        log_info "User '$NEW_USER' already exists and holds a Secure Token — nothing to do"
        TOKEN_METHOD="existing"
        emit_result "ok" "$EX_OK" "already provisioned"
        return "$EX_OK"
    fi

    if user_exists "$NEW_USER"; then
        log_warn "User '$NEW_USER' already exists; the supplied password must match the account's real password for the token grant to succeed"
    fi

    # Fail fast: prove a token source is viable (including that the admin
    # password actually authenticates) BEFORE creating the account.
    require_token_preconditions
    resolve_token_plan
    # ... and if the caller demands an immediate token, a deferred-only plan must
    # fail HERE, before the account exists — not in grant_token afterwards.
    if [ "$TOKEN_PLAN" = "deferred" ] && [ "$REQUIRE_IMMEDIATE" = "1" ]; then
        die "$EX_TOKEN_DEFERRED" "No admin credentials supplied: the Secure Token could only be granted at first login, but ST_REQUIRE_IMMEDIATE_TOKEN=1 was set. No account was created."
    fi

    create_user "$NEW_USER" "$NEW_FULLNAME" "$NEW_PASSWORD"
    grant_token "$NEW_USER" "$NEW_PASSWORD"

    if [ "$TOKEN_METHOD" = "deferred-login" ]; then
        log_info "SUCCESS: '$NEW_USER' created. Secure Token will be granted automatically at first login (Bootstrap Token)."
        emit_result "ok" "$EX_OK" "user created; secure token deferred to first login"
    else
        log_info "SUCCESS: '$NEW_USER' created and holds a Secure Token (method=$TOKEN_METHOD)"
        emit_result "ok" "$EX_OK" "user created and secure token granted"
    fi
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
  create-user     Create a user (if needed) and ensure it gets a Secure Token
  grant-token     Grant a Secure Token to an existing user
  delete-user     Delete a local user account
  status          Report Secure Token status for a user
  list            List all users holding a Secure Token
  preflight       Report system readiness (macOS, MDM, Bootstrap Token, holders)

HOW THE TOKEN IS OBTAINED
  With ST_ADMIN_USER/ST_ADMIN_PASSWORD (an existing Secure Token holder), the
  token is granted immediately and verified. Without them, on an MDM-enrolled
  Mac (macOS 11+) with an escrowed Bootstrap Token, macOS grants the token at
  the user's FIRST LOGIN; this run reports tokenMethod="deferred-login".
  sysadminctl cannot grant a token without an existing holder's credentials.

OPTIONS (env var equivalents in parentheses)
  --new-user NAME         Username             (ST_NEW_USER)
  --new-fullname NAME     Full/display name    (ST_NEW_FULLNAME)
  --new-password PASS     Password             (ST_NEW_PASSWORD)
  --generate-password     Auto-generate a password (ST_GENERATE_PASSWORD=1)
  --make-admin            Administrator account (ST_MAKE_ADMIN=1)
  --hidden                Hidden account        (ST_HIDDEN=1)
  --uid N                 Explicit UID          (ST_UID)
  --admin-user NAME       Secure Token admin    (ST_ADMIN_USER)
  --admin-password PASS   Admin password        (ST_ADMIN_PASSWORD)
  --log-file PATH         Log file (default /var/log/securetoken.log) (ST_LOG_FILE)
  --json                  Emit JSON result on stdout (ST_JSON=1)
  --secret-mode MODE      inline (default) | stdin  (ST_SECRET_MODE)
  --require-immediate     Treat a first-login (deferred) grant as failure (ST_REQUIRE_IMMEDIATE_TOKEN=1)
  --rollback-on-failure   Delete a just-created account if the grant fails (ST_ROLLBACK_ON_FAILURE=1)
  --timeout SECS          Per-sysadminctl watchdog, default 120 (ST_TIMEOUT)
  -h, --help              This help
  -v, --version           Print version

EXIT CODES
  0 ok/idempotent  2 usage  10 not-root  11 unsupported  12 precondition
  20 create-failed 21 grant-failed  22 no-token-source  23 token-deferred
  24 locked        40 verify-failed
EOF
}

# ===========================================================================
# Argument parsing
# ===========================================================================
FLAG_ACTION="" FLAG_NEW_USER="" FLAG_NEW_FULLNAME="" FLAG_NEW_PASSWORD=""
FLAG_GENERATE_PASSWORD="" FLAG_MAKE_ADMIN="" FLAG_HIDDEN="" FLAG_UID=""
FLAG_ADMIN_USER="" FLAG_ADMIN_PASSWORD="" FLAG_LOG_FILE="" FLAG_JSON=""
FLAG_SECRET_MODE="" FLAG_REQUIRE_IMMEDIATE="" FLAG_ROLLBACK="" FLAG_TIMEOUT=""

# Fetch the value for a value-taking flag, or fail cleanly if it is missing.
# (A bare `shift` past the end aborts with an unhelpful `exit 1` under set -u.)
need_value() {
    local flag="$1" value="${2:-__ST_MISSING__}"
    if [ "$value" = "__ST_MISSING__" ]; then
        printf 'ERROR: option %s requires a value\n' "$flag" >&2
        usage >&2
        exit "$EX_USAGE"
    fi
    printf '%s' "$value"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            create-user|grant-token|status|list|preflight|delete-user)
                FLAG_ACTION="$1" ;;
            --new-user)        FLAG_NEW_USER=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --new-fullname)    FLAG_NEW_FULLNAME=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --new-password)    FLAG_NEW_PASSWORD=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --generate-password) FLAG_GENERATE_PASSWORD="1" ;;
            --make-admin)      FLAG_MAKE_ADMIN="1" ;;
            --hidden)          FLAG_HIDDEN="1" ;;
            --uid)             FLAG_UID=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --admin-user)      FLAG_ADMIN_USER=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --admin-password)  FLAG_ADMIN_PASSWORD=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --log-file)        FLAG_LOG_FILE=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --json)            FLAG_JSON="1" ;;
            --secret-mode)     FLAG_SECRET_MODE=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            --require-immediate) FLAG_REQUIRE_IMMEDIATE="1" ;;
            --rollback-on-failure) FLAG_ROLLBACK="1" ;;
            --timeout)         FLAG_TIMEOUT=$(need_value "$1" "${2-__ST_MISSING__}"); shift ;;
            -h|--help)         usage; exit "$EX_OK" ;;
            -v|--version)      printf 'securetoken.sh %s\n' "$ST_VERSION"; exit "$EX_OK" ;;
            *) printf 'ERROR: unknown option: %s\n' "$1" >&2; usage >&2; exit "$EX_USAGE" ;;
        esac
        shift
    done
}

resolve_config() {
    ACTION=$(pick "$FLAG_ACTION" "ST_ACTION" "$CONFIG_ACTION" "create-user")
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
    SECRET_MODE=$(pick "$FLAG_SECRET_MODE" "ST_SECRET_MODE" "$CONFIG_SECRET_MODE" "inline")
    REQUIRE_IMMEDIATE=$(truthy "$(pick "$FLAG_REQUIRE_IMMEDIATE" "ST_REQUIRE_IMMEDIATE_TOKEN" "$CONFIG_REQUIRE_IMMEDIATE" "0")")
    ROLLBACK=$(truthy "$(pick "$FLAG_ROLLBACK" "ST_ROLLBACK_ON_FAILURE" "$CONFIG_ROLLBACK" "0")")
    SYS_TIMEOUT=$(pick "$FLAG_TIMEOUT" "ST_TIMEOUT" "$CONFIG_TIMEOUT" "120")

    JSON_MODE="$JSON"

    # Trim stray LEADING/TRAILING whitespace/CR from RMM-injected values.
    # (Interior whitespace is preserved so validation rejects it visibly.)
    ACTION=$(trim "$ACTION")
    NEW_USER=$(trim "$NEW_USER")
    ADMIN_USER=$(trim "$ADMIN_USER")
    NEW_UID=$(trim "$NEW_UID")
    SECRET_MODE=$(trim "$SECRET_MODE" | tr '[:upper:]' '[:lower:]')
    SYS_TIMEOUT=$(printf '%s' "$SYS_TIMEOUT" | tr -cd '0-9')
    [ -n "$SYS_TIMEOUT" ] || SYS_TIMEOUT=120

    case "$SECRET_MODE" in
        inline|stdin) ;;
        *) printf 'ERROR: --secret-mode must be "inline" or "stdin" (got "%s")\n' "$SECRET_MODE" >&2
           exit "$EX_USAGE" ;;
    esac

    # Secrets have been captured into shell variables; remove them from the
    # environment so every child process we spawn does not inherit them.
    unset ST_NEW_PASSWORD ST_ADMIN_PASSWORD 2>/dev/null || true

    setup_log
}

# Open the log file once, on fd 3, after validating it. Using a single fd for
# the whole run closes the TOCTOU window that a per-write open would leave.
setup_log() {
    LOG_FD_OPEN=0
    [ -n "$LOG_FILE" ] || return 0
    local dir
    dir=$(dirname "$LOG_FILE")
    if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then LOG_FILE=""; return 0; fi
    # Refuse a symlink or a hard-linked file at the predictable path: either can
    # redirect root-owned writes somewhere else.
    if [ -L "$LOG_FILE" ]; then
        printf 'WARNING: %s is a symlink; file logging disabled\n' "$LOG_FILE" >&2
        LOG_FILE=""; return 0
    fi
    if [ -e "$LOG_FILE" ]; then
        local links
        links=$(stat -f '%l' "$LOG_FILE" 2>/dev/null || stat -c '%h' "$LOG_FILE" 2>/dev/null || printf '1')
        if [ "${links:-1}" -gt 1 ]; then
            printf 'WARNING: %s has multiple hard links; file logging disabled\n' "$LOG_FILE" >&2
            LOG_FILE=""; return 0
        fi
        # Rotate a large log so an append-only audit file cannot fill the disk.
        local size
        size=$(stat -f '%z' "$LOG_FILE" 2>/dev/null || stat -c '%s' "$LOG_FILE" 2>/dev/null || printf '0')
        if [ "${size:-0}" -gt 1048576 ]; then
            mv -f "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null || true
        fi
    else
        ( umask 077; : >>"$LOG_FILE" ) 2>/dev/null || { LOG_FILE=""; return 0; }
    fi
    chmod 600 "$LOG_FILE" 2>/dev/null || true
    if exec 3>>"$LOG_FILE" 2>/dev/null; then LOG_FD_OPEN=1; else LOG_FILE=""; fi
    return 0
}

# ===========================================================================
# Main
# ===========================================================================
main() {
    parse_args "$@"
    resolve_config

    if [ "$(uname -s)" != "Darwin" ]; then
        die "$EX_UNSUPPORTED" "This tool runs on macOS only (uname=$(uname -s))"
    fi
    if ! is_root; then
        die "$EX_NOT_ROOT" "Must run as root (use sudo, or an RMM/Intune 'run as root' policy)"
    fi
    if ! version_ge "$(macos_product_version)" "10.13.0"; then
        die "$EX_UNSUPPORTED" "Secure Tokens require macOS 10.13+ (found $(macos_product_version))"
    fi

    log_info "securetoken $ST_VERSION action=$ACTION user=${NEW_USER:-<none>} secret_mode=$SECRET_MODE"

    # Serialise mutating actions; read-only queries need no lock.
    case "$ACTION" in
        create-user|grant-token|delete-user) acquire_lock ;;
    esac

    local rc=0
    case "$ACTION" in
        preflight)   do_preflight || rc=$? ;;
        status)      do_status || rc=$? ;;
        list)        do_list || rc=$? ;;
        grant-token) do_grant_token || rc=$? ;;
        delete-user) do_delete_user || rc=$? ;;
        create-user) do_create_user || rc=$? ;;
        *) die "$EX_USAGE" "Unknown action '$ACTION'" ;;
    esac
    release_lock
    return "$rc"
}

# Allow tests to source this file without executing main.
if [ "${ST_LIB_ONLY:-0}" != "1" ]; then
    main "$@"
    exit "$?"
fi
