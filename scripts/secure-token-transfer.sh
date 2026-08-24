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
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CORE="$SCRIPT_DIR/securetoken.sh"

if [ ! -f "$CORE" ]; then
    echo "ERROR: securetoken.sh not found next to this shim ($CORE)" >&2
    exit 2
fi

echo "NOTE: secure-token-transfer.sh is deprecated; forwarding to securetoken.sh" >&2

action="create-user"
args=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --new-user)        args+=( --new-user "${2:-}" ); shift ;;
        --new-password)    args+=( --new-password "${2:-}" ); shift ;;
        --new-fullname)    args+=( --new-fullname "${2:-}" ); shift ;;
        --admin-user)      args+=( --admin-user "${2:-}" ); shift ;;
        --admin-password)  args+=( --admin-password "${2:-}" ); shift ;;
        --make-admin)      args+=( --make-admin ) ;;
        --grant-only)      action="grant-token" ;;
        --status)          action="status"; args+=( --new-user "${2:-}" ); shift ;;
        --list-tokens)     action="list" ;;
        --help|-h)         exec /bin/bash "$CORE" --help ;;
        --version|-v)      exec /bin/bash "$CORE" --version ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

exec /bin/bash "$CORE" "$action" ${args[@]+"${args[@]}"}
