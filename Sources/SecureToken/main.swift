import Foundation
import ArgumentParser

/// SecureToken - macOS Secure Token Transfer Automation Tool
///
/// This tool automates the process of creating new user accounts and
/// transferring secure tokens on macOS systems.
@main
struct SecureToken: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "securetoken",
        abstract: "Automate secure token transfer on macOS",
        discussion: """
            SecureToken automates the creation of new user accounts and the transfer
            of secure tokens on macOS. Secure tokens are required for users to unlock
            FileVault-encrypted volumes and perform certain system operations.

            This tool requires administrator privileges and must be run with sudo.
            """,
        version: "1.0.0",
        subcommands: [
            CreateUser.self,
            GrantToken.self,
            Status.self,
            ListTokens.self,
            Interactive.self
        ],
        defaultSubcommand: Interactive.self
    )
}

// MARK: - Interactive Mode Command

struct Interactive: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "interactive",
        abstract: "Run in interactive mode (default)"
    )

    func run() throws {
        let manager = SecureTokenManager()

        print("""
        ╔══════════════════════════════════════════════════════════════╗
        ║           SecureToken - macOS Token Transfer Tool            ║
        ╠══════════════════════════════════════════════════════════════╣
        ║  This tool will create a new user account and transfer a     ║
        ║  secure token from an existing admin user.                   ║
        ╚══════════════════════════════════════════════════════════════╝
        """)

        // Check prerequisites
        print("\n[1/5] Checking prerequisites...")

        guard manager.checkMacOSVersion() else {
            throw SecureTokenError.unsupportedSystem("macOS 10.13 or later required")
        }
        print("  ✓ macOS version compatible")

        guard manager.isRunningAsRoot() else {
            throw SecureTokenError.insufficientPrivileges("This tool must be run with sudo")
        }
        print("  ✓ Running with administrator privileges")

        // Get admin credentials
        print("\n[2/5] Admin user credentials (must have secure token):")
        let adminUser = promptForInput("  Admin username: ")
        let adminPassword = promptForSecureInput("  Admin password: ")

        // Verify admin has secure token
        print("\n  Verifying admin secure token status...")
        guard manager.checkSecureTokenStatus(username: adminUser) else {
            throw SecureTokenError.noSecureToken("Admin user '\(adminUser)' does not have a secure token")
        }
        print("  ✓ Admin user has secure token")

        // Get new user details
        print("\n[3/5] New user account details:")
        let newUsername = promptForInput("  New username: ")
        let newFullName = promptForInput("  Full name: ")
        let newPassword = promptForSecureInput("  Password for new user: ")
        let confirmPassword = promptForSecureInput("  Confirm password: ")

        guard newPassword == confirmPassword else {
            throw SecureTokenError.validationError("Passwords do not match")
        }

        let makeAdmin = promptForYesNo("  Make this user an administrator? (y/n): ")

        // Confirm action
        print("\n[4/5] Summary:")
        print("  • New username: \(newUsername)")
        print("  • Full name: \(newFullName)")
        print("  • Administrator: \(makeAdmin ? "Yes" : "No")")
        print("  • Token source: \(adminUser)")

        guard promptForYesNo("\nProceed with user creation and token transfer? (y/n): ") else {
            print("\nOperation cancelled by user.")
            return
        }

        // Create user and transfer token
        print("\n[5/5] Creating user and transferring secure token...")

        try manager.createUserWithSecureToken(
            newUsername: newUsername,
            newFullName: newFullName,
            newPassword: newPassword,
            adminUsername: adminUser,
            adminPassword: adminPassword,
            makeAdmin: makeAdmin
        )

        print("""

        ╔══════════════════════════════════════════════════════════════╗
        ║                    Operation Complete!                       ║
        ╠══════════════════════════════════════════════════════════════╣
        ║  ✓ User '\(newUsername)' created successfully
        ║  ✓ Secure token transferred from '\(adminUser)'
        ║  ✓ User can now unlock FileVault                            ║
        ╚══════════════════════════════════════════════════════════════╝
        """)
    }
}

// MARK: - Create User Command

struct CreateUser: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "create-user",
        abstract: "Create a new user and grant secure token"
    )

    @Option(name: .long, help: "Username for the new account")
    var username: String

    @Option(name: .long, help: "Full name for the new account")
    var fullname: String

    @Option(name: .long, help: "Password for the new account")
    var password: String?

    @Option(name: .long, help: "Admin username (must have secure token)")
    var adminUser: String

    @Option(name: .long, help: "Admin password")
    var adminPassword: String?

    @Flag(name: .long, help: "Make the new user an administrator")
    var admin: Bool = false

    func run() throws {
        let manager = SecureTokenManager()

        // Validate prerequisites
        guard manager.checkMacOSVersion() else {
            throw SecureTokenError.unsupportedSystem("macOS 10.13 or later required")
        }

        guard manager.isRunningAsRoot() else {
            throw SecureTokenError.insufficientPrivileges("This tool must be run with sudo")
        }

        // Get passwords securely if not provided
        let userPassword = password ?? promptForSecureInput("Password for new user: ")
        let adminPass = adminPassword ?? promptForSecureInput("Admin password: ")

        // Verify admin has secure token
        guard manager.checkSecureTokenStatus(username: adminUser) else {
            throw SecureTokenError.noSecureToken("Admin user '\(adminUser)' does not have a secure token")
        }

        print("Creating user '\(username)' and granting secure token...")

        try manager.createUserWithSecureToken(
            newUsername: username,
            newFullName: fullname,
            newPassword: userPassword,
            adminUsername: adminUser,
            adminPassword: adminPass,
            makeAdmin: admin
        )

        print("✓ User '\(username)' created with secure token successfully")
    }
}

// MARK: - Grant Token Command

struct GrantToken: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "grant-token",
        abstract: "Grant secure token to an existing user"
    )

    @Option(name: .long, help: "Target username to grant token to")
    var targetUser: String

    @Option(name: .long, help: "Target user's password")
    var targetPassword: String?

    @Option(name: .long, help: "Admin username (must have secure token)")
    var adminUser: String

    @Option(name: .long, help: "Admin password")
    var adminPassword: String?

    func run() throws {
        let manager = SecureTokenManager()

        guard manager.checkMacOSVersion() else {
            throw SecureTokenError.unsupportedSystem("macOS 10.13 or later required")
        }

        guard manager.isRunningAsRoot() else {
            throw SecureTokenError.insufficientPrivileges("This tool must be run with sudo")
        }

        let targetPass = targetPassword ?? promptForSecureInput("Target user password: ")
        let adminPass = adminPassword ?? promptForSecureInput("Admin password: ")

        guard manager.checkSecureTokenStatus(username: adminUser) else {
            throw SecureTokenError.noSecureToken("Admin user '\(adminUser)' does not have a secure token")
        }

        print("Granting secure token to '\(targetUser)'...")

        try manager.grantSecureToken(
            targetUsername: targetUser,
            targetPassword: targetPass,
            adminUsername: adminUser,
            adminPassword: adminPass
        )

        print("✓ Secure token granted to '\(targetUser)' successfully")
    }
}

// MARK: - Status Command

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Check secure token status for a user"
    )

    @Option(name: .long, help: "Username to check")
    var username: String

    func run() throws {
        let manager = SecureTokenManager()

        guard manager.checkMacOSVersion() else {
            throw SecureTokenError.unsupportedSystem("macOS 10.13 or later required")
        }

        let hasToken = manager.checkSecureTokenStatus(username: username)

        if hasToken {
            print("✓ User '\(username)' has a secure token")
        } else {
            print("✗ User '\(username)' does NOT have a secure token")
        }
    }
}

// MARK: - List Tokens Command

struct ListTokens: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list-tokens",
        abstract: "List all users with secure tokens"
    )

    func run() throws {
        let manager = SecureTokenManager()

        guard manager.checkMacOSVersion() else {
            throw SecureTokenError.unsupportedSystem("macOS 10.13 or later required")
        }

        print("Users with Secure Tokens:")
        print("─────────────────────────")

        let users = manager.listAllUsers()
        var foundTokens = false

        for user in users {
            if manager.checkSecureTokenStatus(username: user) {
                print("  ✓ \(user)")
                foundTokens = true
            }
        }

        if !foundTokens {
            print("  No users with secure tokens found")
        }
    }
}

// MARK: - Helper Functions

func promptForInput(_ prompt: String) -> String {
    print(prompt, terminator: "")
    return readLine() ?? ""
}

func promptForSecureInput(_ prompt: String) -> String {
    // Disable echo for password input
    print(prompt, terminator: "")

    var oldTermSettings = termios()
    tcgetattr(STDIN_FILENO, &oldTermSettings)

    var newTermSettings = oldTermSettings
    newTermSettings.c_lflag &= ~UInt(ECHO)
    tcsetattr(STDIN_FILENO, TCSANOW, &newTermSettings)

    let password = readLine() ?? ""

    tcsetattr(STDIN_FILENO, TCSANOW, &oldTermSettings)
    print() // New line after password input

    return password
}

func promptForYesNo(_ prompt: String) -> Bool {
    print(prompt, terminator: "")
    let response = readLine()?.lowercased() ?? ""
    return response == "y" || response == "yes"
}
