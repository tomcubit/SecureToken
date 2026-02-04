import Foundation

/// Errors that can occur during secure token operations
enum SecureTokenError: Error, CustomStringConvertible {
    case unsupportedSystem(String)
    case insufficientPrivileges(String)
    case noSecureToken(String)
    case userCreationFailed(String)
    case tokenGrantFailed(String)
    case userAlreadyExists(String)
    case validationError(String)
    case commandFailed(String, Int32)

    var description: String {
        switch self {
        case .unsupportedSystem(let msg):
            return "Unsupported System: \(msg)"
        case .insufficientPrivileges(let msg):
            return "Insufficient Privileges: \(msg)"
        case .noSecureToken(let msg):
            return "No Secure Token: \(msg)"
        case .userCreationFailed(let msg):
            return "User Creation Failed: \(msg)"
        case .tokenGrantFailed(let msg):
            return "Token Grant Failed: \(msg)"
        case .userAlreadyExists(let msg):
            return "User Already Exists: \(msg)"
        case .validationError(let msg):
            return "Validation Error: \(msg)"
        case .commandFailed(let cmd, let code):
            return "Command Failed: '\(cmd)' exited with code \(code)"
        }
    }
}

/// Manages secure token operations on macOS
class SecureTokenManager {

    private let fileManager = FileManager.default
    private let logFile = "/var/log/securetoken.log"

    init() {
        // Ensure log file exists
        if !fileManager.fileExists(atPath: logFile) {
            fileManager.createFile(atPath: logFile, contents: nil, attributes: nil)
        }
    }

    // MARK: - Public Methods

    /// Check if the current macOS version supports secure tokens
    func checkMacOSVersion() -> Bool {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        // Secure tokens require macOS 10.13 (High Sierra) or later
        return version.majorVersion >= 10 && version.minorVersion >= 13 || version.majorVersion >= 11
    }

    /// Check if running as root
    func isRunningAsRoot() -> Bool {
        return getuid() == 0
    }

    /// Check if a user has a secure token
    func checkSecureTokenStatus(username: String) -> Bool {
        let result = runCommand("/usr/sbin/sysadminctl", arguments: [
            "-secureTokenStatus", username
        ])

        // sysadminctl outputs to stderr, check for "ENABLED"
        return result.stderr.contains("ENABLED") || result.stdout.contains("ENABLED")
    }

    /// List all local users
    func listAllUsers() -> [String] {
        let result = runCommand("/usr/bin/dscl", arguments: [
            ".", "-list", "/Users"
        ])

        let users = result.stdout
            .components(separatedBy: .newlines)
            .filter { !$0.isEmpty && !$0.hasPrefix("_") }
            .filter { $0 != "daemon" && $0 != "nobody" && $0 != "root" }

        return users
    }

    /// Check if a user exists
    func userExists(username: String) -> Bool {
        let result = runCommand("/usr/bin/dscl", arguments: [
            ".", "-read", "/Users/\(username)"
        ])
        return result.exitCode == 0
    }

    /// Create a new user account with a secure token
    func createUserWithSecureToken(
        newUsername: String,
        newFullName: String,
        newPassword: String,
        adminUsername: String,
        adminPassword: String,
        makeAdmin: Bool
    ) throws {
        log("Starting user creation: \(newUsername)")

        // Validate inputs
        try validateUsername(newUsername)
        try validatePassword(newPassword)

        // Check if user already exists
        if userExists(username: newUsername) {
            throw SecureTokenError.userAlreadyExists("User '\(newUsername)' already exists")
        }

        // Create the user with sysadminctl
        print("  Creating user account...")
        var createArgs = [
            "-addUser", newUsername,
            "-fullName", newFullName,
            "-password", newPassword,
            "-adminUser", adminUsername,
            "-adminPassword", adminPassword
        ]

        if makeAdmin {
            createArgs.append("-admin")
        }

        let createResult = runCommand("/usr/sbin/sysadminctl", arguments: createArgs)

        if createResult.exitCode != 0 {
            log("User creation failed: \(createResult.stderr)")
            throw SecureTokenError.userCreationFailed(createResult.stderr)
        }

        print("  ✓ User account created")
        log("User account created: \(newUsername)")

        // Grant secure token
        print("  Granting secure token...")
        try grantSecureToken(
            targetUsername: newUsername,
            targetPassword: newPassword,
            adminUsername: adminUsername,
            adminPassword: adminPassword
        )

        print("  ✓ Secure token granted")
        log("Secure token granted to: \(newUsername)")

        // Verify the token was granted
        print("  Verifying secure token status...")
        if !checkSecureTokenStatus(username: newUsername) {
            log("WARNING: Token verification failed for: \(newUsername)")
            print("  ⚠ Warning: Could not verify secure token status")
        } else {
            print("  ✓ Secure token verified")
        }
    }

    /// Grant a secure token to an existing user
    func grantSecureToken(
        targetUsername: String,
        targetPassword: String,
        adminUsername: String,
        adminPassword: String
    ) throws {
        log("Granting secure token to: \(targetUsername)")

        // Check if target already has a token
        if checkSecureTokenStatus(username: targetUsername) {
            log("User already has secure token: \(targetUsername)")
            print("  Note: User '\(targetUsername)' already has a secure token")
            return
        }

        // Grant the secure token using sysadminctl
        let grantResult = runCommand("/usr/sbin/sysadminctl", arguments: [
            "-secureTokenOn", targetUsername,
            "-password", targetPassword,
            "-adminUser", adminUsername,
            "-adminPassword", adminPassword
        ])

        if grantResult.exitCode != 0 {
            log("Token grant failed: \(grantResult.stderr)")
            throw SecureTokenError.tokenGrantFailed(grantResult.stderr)
        }

        log("Secure token granted successfully to: \(targetUsername)")
    }

    /// Delete a secure token from a user (requires another admin with token)
    func revokeSecureToken(
        targetUsername: String,
        targetPassword: String,
        adminUsername: String,
        adminPassword: String
    ) throws {
        log("Revoking secure token from: \(targetUsername)")

        let revokeResult = runCommand("/usr/sbin/sysadminctl", arguments: [
            "-secureTokenOff", targetUsername,
            "-password", targetPassword,
            "-adminUser", adminUsername,
            "-adminPassword", adminPassword
        ])

        if revokeResult.exitCode != 0 {
            log("Token revocation failed: \(revokeResult.stderr)")
            throw SecureTokenError.commandFailed("secureTokenOff", revokeResult.exitCode)
        }

        log("Secure token revoked from: \(targetUsername)")
    }

    // MARK: - Validation

    private func validateUsername(_ username: String) throws {
        // Username must be 1-255 characters
        guard username.count >= 1 && username.count <= 255 else {
            throw SecureTokenError.validationError("Username must be 1-255 characters")
        }

        // Username must start with a letter
        guard let first = username.first, first.isLetter else {
            throw SecureTokenError.validationError("Username must start with a letter")
        }

        // Username can only contain letters, numbers, hyphens, and underscores
        let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        guard username.unicodeScalars.allSatisfy({ allowedCharacters.contains($0) }) else {
            throw SecureTokenError.validationError("Username can only contain letters, numbers, hyphens, and underscores")
        }

        // Reserved usernames
        let reserved = ["root", "daemon", "nobody", "admin", "wheel", "kmem", "sys", "tty"]
        guard !reserved.contains(username.lowercased()) else {
            throw SecureTokenError.validationError("Username '\(username)' is reserved")
        }
    }

    private func validatePassword(_ password: String) throws {
        // Minimum password length
        guard password.count >= 4 else {
            throw SecureTokenError.validationError("Password must be at least 4 characters")
        }
    }

    // MARK: - Command Execution

    struct CommandResult {
        let stdout: String
        let stderr: String
        let exitCode: Int32
    }

    private func runCommand(_ command: String, arguments: [String]) -> CommandResult {
        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: command)
        process.arguments = arguments
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return CommandResult(stdout: "", stderr: error.localizedDescription, exitCode: -1)
        }

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""

        return CommandResult(stdout: stdout, stderr: stderr, exitCode: process.terminationStatus)
    }

    // MARK: - Logging

    private func log(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let logEntry = "[\(timestamp)] \(message)\n"

        if let data = logEntry.data(using: .utf8),
           let handle = FileHandle(forWritingAtPath: logFile) {
            handle.seekToEndOfFile()
            handle.write(data)
            handle.closeFile()
        }
    }
}
