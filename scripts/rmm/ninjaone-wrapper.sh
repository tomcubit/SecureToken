#!/bin/bash
#
# ninjaone-wrapper.sh — Run securetoken.sh from a NinjaOne "Mac Script" policy.
# ============================================================================
#
# Maps NinjaOne's two configuration channels onto the ST_* contract that
# securetoken.sh understands:
#
#   1. Script Variables     -> injected as environment variables. Name them
#                              ST_* and they are used as-is.
#   2. Secure Custom Fields -> read at runtime with `ninjarmm-cli get`, so
#                              secrets never sit in the policy body.
#
# CREDENTIALS: sysadminctl cannot grant a Secure Token without an existing
# token holder's credentials (Apple Platform Deployment guide). So either:
#   * supply ST_ADMIN_USER + an admin password custom field -> immediate grant; or
#   * supply neither, on an MDM-enrolled Mac (macOS 11+) with an escrowed
#     Bootstrap Token -> the account is created and macOS grants the token at
#     the user's FIRST LOGIN (result reports tokenMethod="deferred-login").
#
# Deploy this file together with securetoken.sh (same directory), or set ST_CORE
# to wherever you staged the core.
#
# Any arguments passed to this wrapper are forwarded to the core, so a NinjaOne
# Preset Parameter such as `preflight` works as expected.
#
set -uo pipefail   # NOTE: deliberately no `-e`; we must survive a non-zero core
                   # exit in order to report it back with the right status.

# --- Locate the core -------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ST_CORE="${ST_CORE:-$SCRIPT_DIR/securetoken.sh}"

if [ ! -f "$ST_CORE" ]; then
    echo "ERROR: cannot find securetoken.sh at '$ST_CORE'. Set ST_CORE." >&2
    exit 2
fi

# The core runs as root. Refuse to execute it from a location that non-root
# users can modify, otherwise this wrapper is a privilege-escalation vector.
core_is_safe() {
    local f="$1" owner perms
    owner=$(stat -f '%u' "$f" 2>/dev/null || stat -c '%u' "$f" 2>/dev/null || printf '')
    perms=$(stat -f '%p' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null || printf '')
    if [ -n "$owner" ] && [ "$owner" != "0" ]; then
        echo "ERROR: $f is not owned by root (uid $owner); refusing to run it as root." >&2
        return 1
    fi
    # Reject group/other write bits (last two octal digits containing 2, 3, 6, 7).
    # Extracted with tail -c rather than a negative substring offset, which is
    # not reliably available on the bash 3.2 that ships with macOS.
    local go_perms
    go_perms=$(printf '%s' "$perms" | tail -c 2)
    case "$go_perms" in
        *[2367]*) echo "ERROR: $f is group- or world-writable (mode $perms); refusing." >&2; return 1 ;;
    esac
    return 0
}
if ! core_is_safe "$ST_CORE"; then
    exit 2
fi

# --- Optionally pull secrets from NinjaOne Secure Custom Fields ------------
# Set these to the NAMES of your NinjaOne custom fields, or leave blank.
CUSTOM_FIELD_NEW_PW="${CUSTOM_FIELD_NEW_PW:-}"      # e.g. "secureTokenNewUserPassword"
CUSTOM_FIELD_ADMIN_PW="${CUSTOM_FIELD_ADMIN_PW:-}"  # e.g. "secureTokenAdminPassword"
CUSTOM_FIELD_RESULT="${CUSTOM_FIELD_RESULT:-}"      # optional: write the JSON result back

NINJA_CLI=""
for candidate in \
    /Applications/NinjaRMMAgent/programdata/ninjarmm-cli \
    /opt/NinjaRMMAgent/programdata/ninjarmm-cli
do
    if [ -x "$candidate" ]; then NINJA_CLI="$candidate"; break; fi
done
if [ -z "$NINJA_CLI" ] && command -v ninjarmm-cli >/dev/null 2>&1; then
    NINJA_CLI="$(command -v ninjarmm-cli)"
fi

ninja_get() {
    local field="$1"
    [ -n "$field" ] || return 0
    [ -n "$NINJA_CLI" ] || return 0
    "$NINJA_CLI" get "$field" 2>/dev/null || true
}

if [ -n "$CUSTOM_FIELD_NEW_PW" ] && [ -z "${ST_NEW_PASSWORD:-}" ]; then
    ST_NEW_PASSWORD="$(ninja_get "$CUSTOM_FIELD_NEW_PW")"
    export ST_NEW_PASSWORD
fi
if [ -n "$CUSTOM_FIELD_ADMIN_PW" ] && [ -z "${ST_ADMIN_PASSWORD:-}" ]; then
    ST_ADMIN_PASSWORD="$(ninja_get "$CUSTOM_FIELD_ADMIN_PW")"
    export ST_ADMIN_PASSWORD
fi

# Default to JSON so the activity log captures a parseable result line.
export ST_JSON="${ST_JSON:-1}"
export ST_ACTION="${ST_ACTION:-create-user}"

# --- Run the core, forwarding any arguments --------------------------------
# stdout (the JSON result) is captured; stderr streams straight through to the
# NinjaOne activity feed so progress is visible while the script runs.
RESULT=""
RC=0
RESULT="$(/bin/bash "$ST_CORE" "$@")" || RC=$?

# Echo the result so it lands in the NinjaOne script output.
[ -n "$RESULT" ] && printf '%s\n' "$RESULT"

# Optionally write the JSON outcome back to a device custom field.
if [ -n "$CUSTOM_FIELD_RESULT" ] && [ -n "$NINJA_CLI" ]; then
    LAST_JSON="$(printf '%s\n' "$RESULT" | grep '"tool":"securetoken"' | tail -1 || true)"
    if [ -n "$LAST_JSON" ]; then
        # ninjarmm-cli reads the value from stdin with --stdin; without it the
        # value would be taken as an argument and silently dropped for long or
        # special-character content.
        if ! printf '%s' "$LAST_JSON" | "$NINJA_CLI" set "$CUSTOM_FIELD_RESULT" --stdin 2>/dev/null; then
            echo "WARNING: could not write result to custom field '$CUSTOM_FIELD_RESULT'" >&2
        fi
    fi
fi

# Propagate the core's exit code unchanged so NinjaOne's pass/fail is accurate.
exit "$RC"
