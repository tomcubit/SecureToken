#!/bin/bash
#
# secure-token-transfer.sh — DEPRECATED compatibility shim.
# =========================================================
#
# The interactive v1 script has been superseded by the unattended, RMM/Intune-
# ready core `securetoken.sh` in this same directory. This shim translates the
# old flags to the new tool so existing automation keeps working.
#
# Please migrate to `securetoken.sh` (see docs/DEPLOYMENT.md).
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CORE="$SCRIPT_DIR/securetoken.sh"

if [ ! -f "$CORE" ]; then
    echo "ERROR: securetoken.sh not found next to this shim ($CORE)" >&2
    exit 2
fi

echo "NOTE: secure-token-transfer.sh is deprecated; forwarding to securetoken.sh" >&2

# Fetch a value-taking flag's argument, or fail with a clear message rather than
# a bare `exit 1` from a shift past the end.
need_value() {
    local flag="$1" value="${2:-__ST_MISSING__}"
    if [ "$value" = "__ST_MISSING__" ]; then
        echo "ERROR: option $flag requires a value" >&2
        exit 2
    fi
    printf '%s' "$value"
}

action="create-user"
args=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --new-user)        args+=( --new-user      "$(need_value "$1" "${2-__ST_MISSING__}")" ); shift ;;
        --new-password)    args+=( --new-password  "$(need_value "$1" "${2-__ST_MISSING__}")" ); shift ;;
        --new-fullname)    args+=( --new-fullname  "$(need_value "$1" "${2-__ST_MISSING__}")" ); shift ;;
        --admin-user)      args+=( --admin-user    "$(need_value "$1" "${2-__ST_MISSING__}")" ); shift ;;
        --admin-password)  args+=( --admin-password "$(need_value "$1" "${2-__ST_MISSING__}")" ); shift ;;
        --make-admin)      args+=( --make-admin ) ;;
        --grant-only)      action="grant-token" ;;
        --status)          action="status"; args+=( --new-user "$(need_value "$1" "${2-__ST_MISSING__}")" ); shift ;;
        --list-tokens)     action="list" ;;
        --help|-h)         exec /bin/bash "$CORE" --help ;;
        --version|-v)      exec /bin/bash "$CORE" --version ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

exec /bin/bash "$CORE" "$action" ${args[@]+"${args[@]}"}
