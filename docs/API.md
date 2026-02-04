# SecureToken API Reference

This document describes the programmatic API for the SecureToken tool.

## Table of Contents

- [SecureTokenManager Class](#securetokenmanager-class)
- [Commands](#commands)
- [Error Types](#error-types)
- [Shell Script API](#shell-script-api)

## SecureTokenManager Class

The core class that handles all secure token operations.

### Initialization

```swift
let manager = SecureTokenManager()
```

### Methods

#### checkMacOSVersion()

Checks if the current system supports secure tokens.

```swift
func checkMacOSVersion() -> Bool
```

**Returns:** `true` if macOS 10.13 or later, `false` otherwise.

---

#### isRunningAsRoot()

Checks if the current process has root privileges.

```swift
func isRunningAsRoot() -> Bool
```

**Returns:** `true` if running as root (UID 0), `false` otherwise.

---

#### checkSecureTokenStatus(username:)

Checks if a user has a secure token.

```swift
func checkSecureTokenStatus(username: String) -> Bool
```

**Parameters:**
- `username`: The username to check

**Returns:** `true` if the user has a secure token, `false` otherwise.

---

#### listAllUsers()

Lists all local user accounts (excluding system accounts).

```swift
func listAllUsers() -> [String]
```

**Returns:** An array of usernames.

---

#### userExists(username:)

Checks if a user account exists.

```swift
func userExists(username: String) -> Bool
```

**Parameters:**
- `username`: The username to check

**Returns:** `true` if the user exists, `false` otherwise.

---

#### createUserWithSecureToken(...)

Creates a new user account and grants a secure token.

```swift
func createUserWithSecureToken(
    newUsername: String,
    newFullName: String,
    newPassword: String,
    adminUsername: String,
    adminPassword: String,
    makeAdmin: Bool
) throws
```

**Parameters:**
- `newUsername`: Username for the new account
- `newFullName`: Display name for the new account
- `newPassword`: Password for the new account
- `adminUsername`: Admin user who will grant the token
- `adminPassword`: Admin user's password
- `makeAdmin`: Whether to make the new user an administrator

**Throws:** `SecureTokenError` if the operation fails.

---

#### grantSecureToken(...)

Grants a secure token to an existing user.

```swift
func grantSecureToken(
    targetUsername: String,
    targetPassword: String,
    adminUsername: String,
    adminPassword: String
) throws
```

**Parameters:**
- `targetUsername`: User to grant token to
- `targetPassword`: Target user's password
- `adminUsername`: Admin user with secure token
- `adminPassword`: Admin user's password

**Throws:** `SecureTokenError` if the operation fails.

---

#### revokeSecureToken(...)

Revokes a secure token from a user.

```swift
func revokeSecureToken(
    targetUsername: String,
    targetPassword: String,
    adminUsername: String,
    adminPassword: String
) throws
```

**Parameters:**
- `targetUsername`: User to revoke token from
- `targetPassword`: Target user's password
- `adminUsername`: Admin user with secure token
- `adminPassword`: Admin user's password

**Throws:** `SecureTokenError` if the operation fails.

---

## Commands

The CLI tool provides the following commands:

### interactive (default)

Runs in interactive mode with guided prompts.

```bash
sudo securetoken
sudo securetoken interactive
```

### create-user

Creates a new user with a secure token.

```bash
sudo securetoken create-user \
    --username <username> \
    --fullname <fullname> \
    --admin-user <admin> \
    [--password <password>] \
    [--admin-password <password>] \
    [--admin]
```

### grant-token

Grants a secure token to an existing user.

```bash
sudo securetoken grant-token \
    --target-user <username> \
    --admin-user <admin> \
    [--target-password <password>] \
    [--admin-password <password>]
```

### status

Checks secure token status for a user.

```bash
sudo securetoken status --username <username>
```

### list-tokens

Lists all users with secure tokens.

```bash
sudo securetoken list-tokens
```

---

## Error Types

### SecureTokenError

```swift
enum SecureTokenError: Error {
    case unsupportedSystem(String)
    case insufficientPrivileges(String)
    case noSecureToken(String)
    case userCreationFailed(String)
    case tokenGrantFailed(String)
    case userAlreadyExists(String)
    case validationError(String)
    case commandFailed(String, Int32)
}
```

| Error | Description |
|-------|-------------|
| `unsupportedSystem` | macOS version doesn't support secure tokens |
| `insufficientPrivileges` | Not running with root/sudo |
| `noSecureToken` | Admin user doesn't have a secure token |
| `userCreationFailed` | Failed to create user account |
| `tokenGrantFailed` | Failed to grant secure token |
| `userAlreadyExists` | User account already exists |
| `validationError` | Input validation failed |
| `commandFailed` | System command returned non-zero exit code |

---

## Shell Script API

The shell script provides equivalent functionality through command-line arguments.

### Arguments

| Argument | Description |
|----------|-------------|
| `--new-user USERNAME` | Username for new account |
| `--new-password PASSWORD` | Password for new account |
| `--new-fullname NAME` | Full name for new account |
| `--admin-user USERNAME` | Admin username |
| `--admin-password PASSWORD` | Admin password |
| `--make-admin` | Make user an administrator |
| `--grant-only` | Only grant token, don't create user |
| `--status USERNAME` | Check token status |
| `--list-tokens` | List all users with tokens |
| `--help` | Show help |
| `--version` | Show version |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Insufficient privileges |
| 4 | User already exists |
| 5 | Token grant failed |

---

## macOS System Commands Used

The tool uses the following macOS system commands:

### sysadminctl

Used for user and token management:

```bash
# Check token status
sysadminctl -secureTokenStatus <username>

# Grant token
sysadminctl -secureTokenOn <username> \
    -password <user_password> \
    -adminUser <admin> \
    -adminPassword <admin_password>

# Create user
sysadminctl -addUser <username> \
    -fullName <fullname> \
    -password <password> \
    -adminUser <admin> \
    -adminPassword <admin_password>
```

### dscl

Used for directory services queries:

```bash
# List users
dscl . -list /Users

# Check if user exists
dscl . -read /Users/<username>
```

---

## Security Considerations

1. **Password Handling**: Passwords are passed directly to system commands. For production use, consider using the Security framework for secure credential storage.

2. **Logging**: Operations are logged to `/var/log/securetoken.log`. Ensure this file has appropriate permissions.

3. **Root Privileges**: This tool requires root privileges. Always use `sudo` to execute.

4. **Validation**: All inputs are validated before use. Invalid usernames or passwords will be rejected.
