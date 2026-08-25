#!/bin/bash
#
# install-mocks.sh — install a mock macOS command set on a LINUX host so that
# scripts/securetoken.sh can be exercised end-to-end without a Mac.
#
# The mocks emulate the documented behaviour of sysadminctl/dscl/profiles/
# sw_vers/diskutil — crucially INCLUDING Apple's rule that -secureTokenOn
# without -adminUser/-adminPassword does NOT grant a token (it "succeeds"
# with exit 0 and an error message, like the real tool), and that a password
# value of '-' means "prompt the terminal" (emulated by blocking, which is
# what a headless session experiences).
#
# State lives under $ST_MOCK_STATE (default /tmp/st-mock-state):
#   macos_version            e.g. "14.5"
#   mdm_enrolled             0/1
#   bootstrap_escrowed       0/1
#   apfs                     0/1
#   fail_adduser             (exists -> -addUser reports an error, creates nothing)
#   fail_tokenon_silently    (exists -> -secureTokenOn prints Done but sets nothing)
#   hang_tokenon             (exists -> -secureTokenOn blocks, for watchdog tests)
#   users/<name>/password    the account password
#   users/<name>/token       0/1
#   users/<name>/admin       0/1
#   users/<name>/uid         numeric uid
#   users/<name>/hidden      (marker created by dscl IsHidden)
#
# ONLY for disposable environments (CI runners, dev containers): it writes into
# /usr/bin and /usr/sbin, and wraps /usr/bin/uname (delegating to the real
# binary unless ST_MOCK_DARWIN=1).
#
set -euo pipefail

if [ "$(uname -s)" = "Darwin" ]; then
    echo "Refusing to install mocks on macOS." >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root (writes to /usr/bin, /usr/sbin)." >&2
    exit 1
fi

# --- shared helper sourced by every mock ------------------------------------
mkdir -p /usr/local/lib/st-mocks
cat > /usr/local/lib/st-mocks/common.sh <<'COMMON'
STATE="${ST_MOCK_STATE:-/tmp/st-mock-state}"
mkdir -p "$STATE/users"
state_get() { cat "$STATE/$1" 2>/dev/null || printf '%s' "${2:-}"; }
user_dir() { printf '%s/users/%s' "$STATE" "$1"; }
COMMON

install_mock() {
    local path="$1"
    cat > "$path"
    chmod 755 "$path"
}

# --- sw_vers -----------------------------------------------------------------
install_mock /usr/bin/sw_vers <<'EOF'
#!/bin/bash
. /usr/local/lib/st-mocks/common.sh
case "${1:-}" in
    -productVersion) state_get macos_version "14.5"; echo ;;
    *) echo "ProductName: macOS"; echo "ProductVersion: $(state_get macos_version 14.5)" ;;
esac
EOF

# --- profiles ------------------------------------------------------------------
install_mock /usr/bin/profiles <<'EOF'
#!/bin/bash
. /usr/local/lib/st-mocks/common.sh
if [ "${1:-}" = "status" ] && [ "${2:-}" = "-type" ]; then
    case "${3:-}" in
        enrollment)
            if [ "$(state_get mdm_enrolled 0)" = "1" ]; then
                echo "Enrolled via DEP: Yes"
                echo "MDM enrollment: Yes (User Approved)"
            else
                echo "Enrolled via DEP: No"
                echo "MDM enrollment: No"
            fi ;;
        bootstraptoken)
            if [ "$(state_get bootstrap_escrowed 0)" = "1" ]; then
                echo "profiles: Bootstrap Token escrowed to server: YES"
            else
                echo "profiles: Bootstrap Token escrowed to server: NO"
            fi ;;
    esac
fi
exit 0
EOF

# --- diskutil ------------------------------------------------------------------
install_mock /usr/sbin/diskutil <<'EOF'
#!/bin/bash
. /usr/local/lib/st-mocks/common.sh
if [ "${1:-}" = "info" ]; then
    if [ "$(state_get apfs 1)" = "1" ]; then
        echo "   File System Personality:  APFS"
        echo "   Type (Bundle):            apfs"
    else
        echo "   File System Personality:  Journaled HFS+"
        echo "   Type (Bundle):            hfs"
    fi
fi
exit 0
EOF

# --- createhomedir ---------------------------------------------------------------
install_mock /usr/sbin/createhomedir <<'EOF'
#!/bin/bash
exit 0
EOF

# --- dscl ------------------------------------------------------------------------
install_mock /usr/bin/dscl <<'EOF'
#!/bin/bash
. /usr/local/lib/st-mocks/common.sh
# Supported forms (exactly what securetoken.sh uses):
#   dscl . -read /Users/<u>
#   dscl . -list /Users
#   dscl . -list /Users UniqueID
#   dscl . -authonly <u> <pw>
#   dscl . -create /Users/<u> IsHidden 1
shift  # drop the "."
case "${1:-}" in
    -read)
        u="${2#/Users/}"
        [ -d "$(user_dir "$u")" ] && exit 0
        echo "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)" >&2
        exit 56 ;;
    -list)
        if [ "${3:-}" = "UniqueID" ]; then
            printf 'root 0\ndaemon 1\nnobody -2\n_mbsetupuser 248\n'
            for d in "$STATE"/users/*/; do
                [ -d "$d" ] || continue
                n=$(basename "$d")
                printf '%s %s\n' "$n" "$(cat "$d/uid" 2>/dev/null || echo 501)"
            done
        else
            printf 'root\ndaemon\nnobody\n_mbsetupuser\n_spotlight\n'
            for d in "$STATE"/users/*/; do
                [ -d "$d" ] || continue
                basename "$d"
            done
        fi
        exit 0 ;;
    -authonly)
        u="${2:-}"; pw="${3:-}"
        stored=$(cat "$(user_dir "$u")/password" 2>/dev/null || printf '\001nope')
        [ "$pw" = "$stored" ] && exit 0
        echo "Authentication for node failed. (-14090, eDSAuthFailed)" >&2
        exit 1 ;;
    -create)
        u="${2#/Users/}"
        if [ "${3:-}" = "IsHidden" ]; then
            [ -d "$(user_dir "$u")" ] && touch "$(user_dir "$u")/hidden"
        fi
        exit 0 ;;
esac
exit 0
EOF

# --- sysadminctl -------------------------------------------------------------------
install_mock /usr/sbin/sysadminctl <<'EOF'
#!/bin/bash
# Mock sysadminctl emulating the REAL tool's documented semantics:
#  * -secureTokenOn ALWAYS requires -adminUser/-adminPassword of an existing
#    Secure Token admin (Apple Platform Deployment guide). Without them it
#    reports an error but still EXITS 0 — like the real tool often does.
#  * A password value of '-' means "prompt the terminal interactively"; in a
#    headless session that blocks. Emulated by sleeping.
. /usr/local/lib/st-mocks/common.sh
err() { echo "sysadminctl[$$] $*" >&2; }

# Collect args into an assoc-style lookup (bash 4 on Linux is fine for mocks).
declare -A OPT
FLAGS=""
CMD=""
while [ $# -gt 0 ]; do
    case "$1" in
        -secureTokenStatus|-addUser|-secureTokenOn|-secureTokenOff|-deleteUser)
            CMD="${1#-}"; OPT[target]="${2:-}"; shift ;;
        -password|-adminUser|-adminPassword|-fullName|-UID|-home|-shell)
            OPT["${1#-}"]="${2:-}"; shift ;;
        -admin) FLAGS="$FLAGS admin" ;;
    esac
    shift
done

# '-' == interactive prompt: block like a real headless prompt would.
for k in password adminPassword; do
    if [ "${OPT[$k]:-}" = "-" ]; then
        err "Enter password:"
        sleep 300
        exit 1
    fi
done

case "$CMD" in
    secureTokenStatus)
        u="${OPT[target]}"
        if [ -d "$(user_dir "$u")" ] && [ "$(cat "$(user_dir "$u")/token" 2>/dev/null)" = "1" ]; then
            err "Secure token is ENABLED for user $u"
        else
            err "Secure token is DISABLED for user $u"
        fi
        exit 0 ;;
    addUser)
        u="${OPT[target]}"
        if [ -e "$STATE/fail_adduser" ]; then
            err "Error: unable to create user record"; exit 0
        fi
        d="$(user_dir "$u")"
        mkdir -p "$d"
        printf '%s' "${OPT[password]:-}" > "$d/password"
        printf '0' > "$d/token"
        case "$FLAGS" in *admin*) printf '1' > "$d/admin" ;; *) printf '0' > "$d/admin" ;; esac
        printf '%s' "${OPT[UID]:-501}" > "$d/uid"
        err "Creating user record…"
        exit 0 ;;
    secureTokenOn)
        u="${OPT[target]}"
        if [ -e "$STATE/hang_tokenon" ]; then sleep 300; exit 1; fi
        au="${OPT[adminUser]:-}"; ap="${OPT[adminPassword]:-}"
        if [ -z "$au" ] || [ -z "$ap" ]; then
            # THE crucial Apple behaviour: no credential-free grants exist.
            err "Operation requires an existing Secure Token administrator (use -adminUser/-adminPassword)."
            exit 0
        fi
        if [ ! -d "$(user_dir "$au")" ] || [ "$(cat "$(user_dir "$au")/token" 2>/dev/null)" != "1" ]; then
            err "Error: admin '$au' does not hold a Secure Token"; exit 0
        fi
        if [ "$(cat "$(user_dir "$au")/password" 2>/dev/null)" != "$ap" ]; then
            err "Error: authentication failed for admin '$au'"; exit 0
        fi
        if [ "$(cat "$(user_dir "$u")/password" 2>/dev/null)" != "${OPT[password]:-}" ]; then
            err "Error: wrong password for user '$u'"
            exit 1
        fi
        if [ -e "$STATE/fail_tokenon_silently" ]; then
            err "Done"   # lies, like some macOS builds do
            exit 0
        fi
        printf '1' > "$(user_dir "$u")/token"
        err "Done"
        exit 0 ;;
    deleteUser)
        rm -rf "$(user_dir "${OPT[target]}")"
        err "Deleting record…"
        exit 0 ;;
esac
exit 0
EOF

# --- uname wrapper -----------------------------------------------------------------
# Delegates to the real uname unless ST_MOCK_DARWIN=1, in which case -s reports
# Darwin (everything else still delegates).
if [ ! -e /usr/local/lib/st-mocks/uname.real ]; then
    if grep -q ST_MOCK_DARWIN /usr/bin/uname 2>/dev/null; then
        echo "uname wrapper already installed but uname.real missing — aborting." >&2
        exit 1
    fi
    cp -p /usr/bin/uname /usr/local/lib/st-mocks/uname.real
fi
install_mock /usr/bin/uname <<'EOF'
#!/bin/bash
# ST_MOCK_DARWIN wrapper — see tests/mocks/install-mocks.sh
if [ "${ST_MOCK_DARWIN:-0}" = "1" ]; then
    for a in "$@"; do
        if [ "$a" = "-s" ]; then echo "Darwin"; exit 0; fi
    done
fi
exec /usr/local/lib/st-mocks/uname.real "$@"
EOF

echo "Mocks installed. Drive them via ST_MOCK_DARWIN=1 and ST_MOCK_STATE=<dir>."
