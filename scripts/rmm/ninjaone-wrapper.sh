#!/bin/bash
#
# ninjaone-wrapper.sh — Run securetoken.sh from a NinjaOne "Mac Script" policy.
# ============================================================================
#
# NinjaOne exposes two ways to pass configuration into a script; this wrapper
# reads both and maps them onto the ST_* environment contract that
# securetoken.sh understands:
#
#   1. Script Variables            -> injected by NinjaOne as environment
#                                     variables (already ST_*-named if you name
#                                     them that way). Used as-is.
#   2. Secure Custom Fields        -> pulled at runtime with `ninjarmm-cli get`
#                                     so secrets never sit in the script body or
#                                     the policy UI in plaintext.
#
# RECOMMENDED (credential-free): MDM-enroll the Mac and escrow a Bootstrap
# Token. Then you need NO admin password at all — leave the admin fields empty
# and securetoken.sh grants the token via the Bootstrap Token.
#
# Deploy: add BOTH this file and securetoken.sh to the same NinjaOne script,
# or place securetoken.sh next to this wrapper. Set ST_CORE to an explicit path
# if you stage it elsewhere (e.g. /usr/local/cubit/securetoken.sh).
#
# Configure via NinjaOne Script Variables (Preset Parameter / Script Variables):
#   ST_NEW_USER, ST_NEW_FULLNAME, ST_MAKE_ADMIN, ST_HIDDEN, ST_JSON=1
# And, only if NOT using a Bootstrap Token, a Secure Custom Field holding the
# admin password (referenced below by CUSTOM_FIELD_ADMIN_PW).
#
set -euo pipefail

# --- Where is the core script? --------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ST_CORE="${ST_CORE:-$SCRIPT_DIR/securetoken.sh}"

if [ ! -f "$ST_CORE" ]; then
    echo "ERROR: cannot find securetoken.sh at '$ST_CORE'. Set ST_CORE." >&2
    exit 2
fi

# --- Optionally pull secrets from NinjaOne Secure Custom Fields ------------
# Set these to the *names* of your NinjaOne custom fields, or leave blank.
CUSTOM_FIELD_NEW_PW="${CUSTOM_FIELD_NEW_PW:-}"      # e.g. "secureTokenNewUserPassword"
CUSTOM_FIELD_ADMIN_PW="${CUSTOM_FIELD_ADMIN_PW:-}"  # e.g. "secureTokenAdminPassword"

ninja_get() {
    # Reads a device custom field via ninjarmm-cli if available; prints value.
    local field="$1"
    if [ -z "$field" ]; then return 0; fi
    if command -v /Applications/NinjaRMMAgent/programdata/ninjarmm-cli >/dev/null 2>&1; then
        /Applications/NinjaRMMAgent/programdata/ninjarmm-cli get "$field" 2>/dev/null || true
    elif command -v ninjarmm-cli >/dev/null 2>&1; then
        ninjarmm-cli get "$field" 2>/dev/null || true
    fi
}

if [ -n "$CUSTOM_FIELD_NEW_PW" ] && [ -z "${ST_NEW_PASSWORD:-}" ]; then
    ST_NEW_PASSWORD="$(ninja_get "$CUSTOM_FIELD_NEW_PW")"
    export ST_NEW_PASSWORD
fi
if [ -n "$CUSTOM_FIELD_ADMIN_PW" ] && [ -z "${ST_ADMIN_PASSWORD:-}" ]; then
    ST_ADMIN_PASSWORD="$(ninja_get "$CUSTOM_FIELD_ADMIN_PW")"
    export ST_ADMIN_PASSWORD
fi

# Default to JSON output so NinjaOne's activity log captures a parseable result.
export ST_JSON="${ST_JSON:-1}"
export ST_ACTION="${ST_ACTION:-create-user}"

# --- Run, capturing the JSON result line for NinjaOne ----------------------
set +e
RESULT="$(/bin/bash "$ST_CORE")"
RC=$?
set -e

# Echo everything back so it lands in the NinjaOne script result / activity feed.
printf '%s\n' "$RESULT"

# Optionally write the outcome back to a device custom field for reporting.
if [ -n "${CUSTOM_FIELD_RESULT:-}" ]; then
    LAST_JSON="$(printf '%s\n' "$RESULT" | grep '"tool":"securetoken"' | tail -1)"
    if [ -n "$LAST_JSON" ]; then
        if command -v /Applications/NinjaRMMAgent/programdata/ninjarmm-cli >/dev/null 2>&1; then
            printf '%s' "$LAST_JSON" | /Applications/NinjaRMMAgent/programdata/ninjarmm-cli set "$CUSTOM_FIELD_RESULT" 2>/dev/null || true
        fi
    fi
fi

exit "$RC"
