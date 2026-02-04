# SecureToken

A macOS application to automate secure token transfer to new user accounts without manual intervention.

## Overview

Secure tokens are cryptographic keys used in macOS (10.13+) for FileVault disk encryption. When setting up new user accounts, they need to be granted a secure token to:

- Unlock FileVault-encrypted volumes at boot
- Authenticate for certain system operations
- Enable full disk encryption capabilities

This tool automates the process of creating a new user account and transferring/granting a secure token from an existing admin user.

## Requirements

- macOS 10.13 (High Sierra) or later
- Administrator privileges
- An existing admin user with a secure token
- System Integrity Protection (SIP) considerations for some operations

## Installation

### Using Swift Package Manager

```bash
cd SecureToken
swift build -c release
sudo cp .build/release/securetoken /usr/local/bin/
```

### Using the Shell Script

```bash
chmod +x scripts/secure-token-transfer.sh
sudo ./scripts/secure-token-transfer.sh
```

## Usage

### Swift CLI Tool

```bash
# Interactive mode (recommended)
sudo securetoken

# Create user and grant secure token
sudo securetoken create-user \
    --username "newuser" \
    --fullname "New User" \
    --password "userpassword" \
    --admin-user "existingadmin" \
    --admin-password "adminpassword"

# Grant secure token to existing user
sudo securetoken grant-token \
    --target-user "existinguser" \
    --target-password "userpassword" \
    --admin-user "adminwithtoken" \
    --admin-password "adminpassword"

# Check secure token status
sudo securetoken status --username "anyuser"

# List all users with secure tokens
sudo securetoken list-tokens
```

### Shell Script

```bash
# Interactive mode
sudo ./scripts/secure-token-transfer.sh

# With arguments
sudo ./scripts/secure-token-transfer.sh \
    --new-user "newuser" \
    --new-password "password" \
    --admin-user "admin" \
    --admin-password "adminpass"
```

## How It Works

1. **Validates Prerequisites**: Checks that the current system supports secure tokens and that the admin user has a valid secure token.

2. **Creates New User Account**: Uses `sysadminctl` to create a new local user account with the specified credentials.

3. **Grants Secure Token**: The admin user (who must have a secure token) grants a secure token to the new user via `sysadminctl -secureTokenOn`.

4. **Verifies Transfer**: Confirms the new user now has a valid secure token.

## Security Considerations

- **Passwords in Command Line**: For security, use interactive mode when possible to avoid passwords in shell history. The tool supports secure password input.

- **Admin Credentials**: The admin password is required to grant secure tokens. Ensure this is handled securely.

- **Audit Logging**: All operations are logged to `/var/log/securetoken.log` for audit purposes.

- **Keychain**: The tool can optionally create a keychain for the new user.

## Troubleshooting

### "Secure token is not supported on this system"
- Ensure you're running macOS 10.13 or later
- Check that your boot volume is APFS formatted

### "Admin user does not have a secure token"
- The admin user granting the token must have a secure token themselves
- Check with: `sysadminctl -secureTokenStatus -adminUser <username>`

### "Operation requires FileVault authentication"
- Ensure the admin credentials are correct
- The admin user must be a FileVault-enabled user

## API Reference

See [docs/API.md](docs/API.md) for detailed API documentation.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
