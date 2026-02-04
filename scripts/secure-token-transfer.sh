#!/bin/bash
#
# SecureToken Transfer Script
# Automates the creation of a new user account and secure token transfer on macOS
#
# Usage:
#   sudo ./secure-token-transfer.sh [options]
#
# Options:
#   --new-user USERNAME      Username for the new account
#   --new-password PASSWORD  Password for the new account
#   --new-fullname NAME      Full name for the new account
#   --admin-user USERNAME    Admin username (must have secure token)
#   --admin-password PASS    Admin password
#   --make-admin             Make the new user an administrator
#   --help                   Show this help message
#   --version                Show version information
#
# Author: SecureToken Team
# License: MIT
#

set -e

VERSION="1.0.0"
LOG_FILE="/var/log/securetoken.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[$timestamp] $1" >> "$LOG_FILE" 2>/dev/null || true
}

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show banner
show_banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           SecureToken - macOS Token Transfer Tool            ║"
    echo "║                        Version $VERSION                         ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  This tool will create a new user account and transfer a     ║"
    echo "║  secure token from an existing admin user.                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# Show help
show_help() {
    cat << EOF
SecureToken Transfer Script v$VERSION

USAGE:
    sudo $0 [OPTIONS]

OPTIONS:
    --new-user USERNAME      Username for the new account
    --new-password PASSWORD  Password for the new account (use interactive mode for security)
    --new-fullname NAME      Full name for the new account
    --admin-user USERNAME    Admin username (must have secure token)
    --admin-password PASS    Admin password (use interactive mode for security)
    --make-admin             Make the new user an administrator
    --grant-only             Only grant token to existing user (don't create)
    --status USERNAME        Check secure token status for a user
    --list-tokens            List all users with secure tokens
    --help                   Show this help message
    --version                Show version information

EXAMPLES:
    # Interactive mode (recommended)
    sudo $0

    # Create user with arguments
    sudo $0 --new-user newuser --new-fullname "New User" \\
            --admin-user admin --make-admin

    # Check token status
    sudo $0 --status admin

    # List all tokens
    sudo $0 --list-tokens

SECURITY NOTE:
    For security, it's recommended to use interactive mode to avoid
    passwords appearing in shell history or process listings.

EOF
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check macOS version
check_macos_version() {
    local version=$(sw_vers -productVersion 2>/dev/null || echo "0.0.0")
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)

    # Check for macOS 10.13+ or macOS 11+
    if [[ "$major" -lt 10 ]] || [[ "$major" -eq 10 && "$minor" -lt 13 ]]; then
        print_error "macOS 10.13 (High Sierra) or later is required"
        print_error "Current version: $version"
        exit 1
    fi

    print_success "macOS version compatible ($version)"
}

# Check secure token status for a user
check_secure_token_status() {
    local username="$1"
    local status=$(/usr/sbin/sysadminctl -secureTokenStatus "$username" 2>&1)

    if echo "$status" | grep -q "ENABLED"; then
        return 0
    else
        return 1
    fi
}

# List all users with secure tokens
list_secure_tokens() {
    print_info "Users with Secure Tokens:"
    echo "─────────────────────────────"

    local found_tokens=false
    local users=$(/usr/bin/dscl . -list /Users | grep -v "^_" | grep -v "^daemon$" | grep -v "^nobody$" | grep -v "^root$")

    for user in $users; do
        if check_secure_token_status "$user"; then
            echo "  ✓ $user"
            found_tokens=true
        fi
    done

    if [[ "$found_tokens" == "false" ]]; then
        echo "  No users with secure tokens found"
    fi
}

# Validate username
validate_username() {
    local username="$1"

    # Check length
    if [[ ${#username} -lt 1 ]] || [[ ${#username} -gt 255 ]]; then
        print_error "Username must be 1-255 characters"
        return 1
    fi

    # Check if starts with letter
    if [[ ! "$username" =~ ^[a-zA-Z] ]]; then
        print_error "Username must start with a letter"
        return 1
    fi

    # Check valid characters
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "Username can only contain letters, numbers, hyphens, and underscores"
        return 1
    fi

    # Check reserved names
    local reserved="root daemon nobody admin wheel kmem sys tty"
    for r in $reserved; do
        if [[ "${username,,}" == "$r" ]]; then
            print_error "Username '$username' is reserved"
            return 1
        fi
    done

    return 0
}

# Check if user exists
user_exists() {
    local username="$1"
    /usr/bin/dscl . -read "/Users/$username" &>/dev/null
    return $?
}

# Read password securely
read_password() {
    local prompt="$1"
    local password=""

    # Disable echo
    stty -echo 2>/dev/null || true
    printf "%s" "$prompt"
    read -r password
    stty echo 2>/dev/null || true
    echo ""

    echo "$password"
}

# Create user account
create_user() {
    local username="$1"
    local fullname="$2"
    local password="$3"
    local admin_user="$4"
    local admin_pass="$5"
    local make_admin="$6"

    log "Creating user: $username"

    local cmd=("/usr/sbin/sysadminctl"
        "-addUser" "$username"
        "-fullName" "$fullname"
        "-password" "$password"
        "-adminUser" "$admin_user"
        "-adminPassword" "$admin_pass")

    if [[ "$make_admin" == "true" ]]; then
        cmd+=("-admin")
    fi

    local output
    if output=$("${cmd[@]}" 2>&1); then
        print_success "User account created"
        log "User account created: $username"
        return 0
    else
        print_error "Failed to create user: $output"
        log "User creation failed: $output"
        return 1
    fi
}

# Grant secure token
grant_secure_token() {
    local target_user="$1"
    local target_pass="$2"
    local admin_user="$3"
    local admin_pass="$4"

    log "Granting secure token to: $target_user"

    # Check if already has token
    if check_secure_token_status "$target_user"; then
        print_info "User '$target_user' already has a secure token"
        return 0
    fi

    local output
    if output=$(/usr/sbin/sysadminctl \
        -secureTokenOn "$target_user" \
        -password "$target_pass" \
        -adminUser "$admin_user" \
        -adminPassword "$admin_pass" 2>&1); then
        print_success "Secure token granted"
        log "Secure token granted to: $target_user"
        return 0
    else
        print_error "Failed to grant secure token: $output"
        log "Token grant failed: $output"
        return 1
    fi
}

# Interactive mode
run_interactive() {
    show_banner

    # Check prerequisites
    print_info "[1/5] Checking prerequisites..."
    check_macos_version

    # Get admin credentials
    echo ""
    print_info "[2/5] Admin user credentials (must have secure token):"
    printf "  Admin username: "
    read -r ADMIN_USER
    ADMIN_PASSWORD=$(read_password "  Admin password: ")

    # Verify admin has secure token
    print_info "Verifying admin secure token status..."
    if ! check_secure_token_status "$ADMIN_USER"; then
        print_error "Admin user '$ADMIN_USER' does not have a secure token"
        exit 1
    fi
    print_success "Admin user has secure token"

    # Get new user details
    echo ""
    print_info "[3/5] New user account details:"
    printf "  New username: "
    read -r NEW_USER
    printf "  Full name: "
    read -r NEW_FULLNAME
    NEW_PASSWORD=$(read_password "  Password for new user: ")
    CONFIRM_PASSWORD=$(read_password "  Confirm password: ")

    if [[ "$NEW_PASSWORD" != "$CONFIRM_PASSWORD" ]]; then
        print_error "Passwords do not match"
        exit 1
    fi

    printf "  Make this user an administrator? (y/n): "
    read -r make_admin_input
    MAKE_ADMIN="false"
    if [[ "${make_admin_input,,}" == "y" ]] || [[ "${make_admin_input,,}" == "yes" ]]; then
        MAKE_ADMIN="true"
    fi

    # Validate inputs
    if ! validate_username "$NEW_USER"; then
        exit 1
    fi

    if user_exists "$NEW_USER"; then
        print_error "User '$NEW_USER' already exists"
        exit 1
    fi

    # Confirm action
    echo ""
    print_info "[4/5] Summary:"
    echo "  • New username: $NEW_USER"
    echo "  • Full name: $NEW_FULLNAME"
    echo "  • Administrator: $([ "$MAKE_ADMIN" == "true" ] && echo "Yes" || echo "No")"
    echo "  • Token source: $ADMIN_USER"

    printf "\nProceed with user creation and token transfer? (y/n): "
    read -r confirm
    if [[ "${confirm,,}" != "y" ]] && [[ "${confirm,,}" != "yes" ]]; then
        print_warning "Operation cancelled by user"
        exit 0
    fi

    # Create user and transfer token
    echo ""
    print_info "[5/5] Creating user and transferring secure token..."

    if ! create_user "$NEW_USER" "$NEW_FULLNAME" "$NEW_PASSWORD" "$ADMIN_USER" "$ADMIN_PASSWORD" "$MAKE_ADMIN"; then
        exit 1
    fi

    if ! grant_secure_token "$NEW_USER" "$NEW_PASSWORD" "$ADMIN_USER" "$ADMIN_PASSWORD"; then
        print_warning "User was created but secure token transfer may have failed"
        exit 1
    fi

    # Verify
    print_info "Verifying secure token status..."
    if check_secure_token_status "$NEW_USER"; then
        print_success "Secure token verified"
    else
        print_warning "Could not verify secure token status"
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Operation Complete!                       ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  ✓ User '$NEW_USER' created successfully"
    echo "║  ✓ Secure token transferred from '$ADMIN_USER'"
    echo "║  ✓ User can now unlock FileVault                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
}

# Main script
main() {
    # Parse arguments
    NEW_USER=""
    NEW_PASSWORD=""
    NEW_FULLNAME=""
    ADMIN_USER=""
    ADMIN_PASSWORD=""
    MAKE_ADMIN="false"
    GRANT_ONLY="false"
    STATUS_USER=""
    LIST_TOKENS="false"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --new-user)
                NEW_USER="$2"
                shift 2
                ;;
            --new-password)
                NEW_PASSWORD="$2"
                shift 2
                ;;
            --new-fullname)
                NEW_FULLNAME="$2"
                shift 2
                ;;
            --admin-user)
                ADMIN_USER="$2"
                shift 2
                ;;
            --admin-password)
                ADMIN_PASSWORD="$2"
                shift 2
                ;;
            --make-admin)
                MAKE_ADMIN="true"
                shift
                ;;
            --grant-only)
                GRANT_ONLY="true"
                shift
                ;;
            --status)
                STATUS_USER="$2"
                shift 2
                ;;
            --list-tokens)
                LIST_TOKENS="true"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                echo "SecureToken Transfer Script v$VERSION"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Check root first
    check_root

    # Handle status check
    if [[ -n "$STATUS_USER" ]]; then
        if check_secure_token_status "$STATUS_USER"; then
            print_success "User '$STATUS_USER' has a secure token"
        else
            print_warning "User '$STATUS_USER' does NOT have a secure token"
        fi
        exit 0
    fi

    # Handle list tokens
    if [[ "$LIST_TOKENS" == "true" ]]; then
        list_secure_tokens
        exit 0
    fi

    # If no arguments provided, run interactive mode
    if [[ -z "$NEW_USER" ]] && [[ -z "$ADMIN_USER" ]] && [[ "$GRANT_ONLY" == "false" ]]; then
        run_interactive
        exit 0
    fi

    # Non-interactive mode - validate required arguments
    check_macos_version

    if [[ -z "$ADMIN_USER" ]]; then
        print_error "Admin username is required (--admin-user)"
        exit 1
    fi

    if [[ -z "$ADMIN_PASSWORD" ]]; then
        ADMIN_PASSWORD=$(read_password "Admin password for '$ADMIN_USER': ")
    fi

    # Verify admin has secure token
    if ! check_secure_token_status "$ADMIN_USER"; then
        print_error "Admin user '$ADMIN_USER' does not have a secure token"
        exit 1
    fi

    if [[ -z "$NEW_USER" ]]; then
        print_error "New username is required (--new-user)"
        exit 1
    fi

    if ! validate_username "$NEW_USER"; then
        exit 1
    fi

    # Grant only mode
    if [[ "$GRANT_ONLY" == "true" ]]; then
        if [[ -z "$NEW_PASSWORD" ]]; then
            NEW_PASSWORD=$(read_password "Password for '$NEW_USER': ")
        fi

        if ! user_exists "$NEW_USER"; then
            print_error "User '$NEW_USER' does not exist"
            exit 1
        fi

        grant_secure_token "$NEW_USER" "$NEW_PASSWORD" "$ADMIN_USER" "$ADMIN_PASSWORD"
        exit $?
    fi

    # Create user mode
    if user_exists "$NEW_USER"; then
        print_error "User '$NEW_USER' already exists"
        exit 1
    fi

    if [[ -z "$NEW_FULLNAME" ]]; then
        NEW_FULLNAME="$NEW_USER"
    fi

    if [[ -z "$NEW_PASSWORD" ]]; then
        NEW_PASSWORD=$(read_password "Password for new user '$NEW_USER': ")
        CONFIRM_PASSWORD=$(read_password "Confirm password: ")
        if [[ "$NEW_PASSWORD" != "$CONFIRM_PASSWORD" ]]; then
            print_error "Passwords do not match"
            exit 1
        fi
    fi

    print_info "Creating user '$NEW_USER' with secure token..."

    if ! create_user "$NEW_USER" "$NEW_FULLNAME" "$NEW_PASSWORD" "$ADMIN_USER" "$ADMIN_PASSWORD" "$MAKE_ADMIN"; then
        exit 1
    fi

    if ! grant_secure_token "$NEW_USER" "$NEW_PASSWORD" "$ADMIN_USER" "$ADMIN_PASSWORD"; then
        print_warning "User was created but secure token transfer may have failed"
        exit 1
    fi

    if check_secure_token_status "$NEW_USER"; then
        print_success "User '$NEW_USER' created with secure token"
    else
        print_warning "User created but secure token status could not be verified"
    fi
}

# Run main
main "$@"
