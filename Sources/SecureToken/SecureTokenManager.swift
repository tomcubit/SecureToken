import Foundation

/// Stable process exit codes — kept in sync with scripts/securetoken.sh so that
/// RMM/Intune result parsing behaves identically regardless of which
/// implementation is deployed.
enum ExitStatus: Int32 {
    case ok = 0
    case usage = 2
    case notRoot = 10
    case unsupported = 11
    case precondition = 12
    case createFailed = 20
    case grantFailed = 21
    case noTokenSource = 22
    case tokenDeferred = 23
    case verifyFailed = 40
}

/// Errors that can occur during secure token operations. Each carries the
/// process exit code that should be returned to the caller (RMM/Intune).
struct SecureTokenError: Error, CustomStringConvertible {
    let status: ExitStatus
    let message: String

    var description: String { message }
    var code: Int32 { status.rawValue }

    static func unsupported(_ m: String) -> SecureTokenError { .init(status: .unsupported, message: m) }
    static func notRoot(_ m: String) -> SecureTokenError { .init(status: .notRoot, message: m) }
    static func usage(_ m: String) -> SecureTokenError { .init(status: .usage, message: m) }
    static func precondition(_ m: String) -> SecureTokenError { .init(status: .precondition, message: m) }
    static func createFailed(_ m: String) -> SecureTokenError { .init(status: .createFailed, message: m) }
    static func grantFailed(_ m: String) -> SecureTokenError { .init(status: .grantFailed, message: m) }
    static func noTokenSource(_ m: String) -> SecureTokenError { .init(status: .noTokenSource, message: m) }
    static func verifyFailed(_ m: String) -> SecureTokenError { .init(status: .verifyFailed, message: m) }
}

/// How a Secure Token was (or will be) granted.
enum TokenMethod: String {
    /// Granted immediately using an existing Secure Token administrator.
    case admin
    /// No credentials supplied; macOS will grant the token at the user's first
    /// login via the escrowed Bootstrap Token (macOS 11+).
    case deferredLogin = "deferred-login"
    /// The user already held a Secure Token.
    case existing
    case none
}

/// Result of a provisioning operation, serialisable to a single JSON line.
struct OperationResult {
    var status: String
    var exitCode: Int32
    var action: String
    var user: String
    var tokenMethod: String
    var message: String
    var generatedPassword: String?

    func jsonLine(version: String) -> String {
        func esc(_ s: String) -> String {
            var r = s
            r = r.replacingOccurrences(of: "\\", with: "\\\\")
            r = r.replacingOccurrences(of: "\"", with: "\\\"")
            r = r.replacingOccurrences(of: "\n", with: "\\n")
            r = r.replacingOccurrences(of: "\r", with: "\\r")
            r = r.replacingOccurrences(of: "\t", with: "\\t")
            return r
        }
        var pw = ""
        if let g = generatedPassword {
            pw = ",\"generatedPassword\":\"\(esc(g))\""
        }
        return "{\"tool\":\"securetoken\",\"version\":\"\(version)\",\"status\":\"\(esc(status))\","
            + "\"exitCode\":\(exitCode),\"action\":\"\(esc(action))\",\"user\":\"\(esc(user))\","
            + "\"tokenMethod\":\"\(esc(tokenMethod))\",\"message\":\"\(esc(message))\"\(pw)}"
    }
}

/// Manages Secure Token operations on macOS.
final class SecureTokenManager {

    static let version = "3.0.0"   // keep in lockstep with scripts/securetoken.sh

    private let fileManager = FileManager.default
    private let logFile: String
    /// When true, passwords are streamed to sysadminctl over stdin (using `-`
    /// placeholders) so they never appear in the process table. Set false only
    /// as a fallback if a specific macOS build misbehaves with stdin feeding.
    var stdinSecrets: Bool = true
    /// Prefer the escrowed Bootstrap Token when available (credential-free).
    var preferBootstrap: Bool = true

    init(logFile: String = "/var/log/securetoken.log") {
        self.logFile = logFile
    }

    // MARK: - Logging (stderr + file; stdout stays clean for JSON)

    /// Strip C0 control characters so a crafted value cannot forge log lines.
    private func sanitizeForLog(_ s: String) -> String {
        return String(s.unicodeScalars.filter { $0.value >= 0x20 || $0 == "\u{09}" })
    }

    /// True once the log path has been validated for this process.
    private var logChecked = false
    private var logUsable = false

    /// Validate the log path the same way the shell core does: refuse symlinks
    /// and hard-linked files at a predictable root-writable path, and create it
    /// mode 0600 rather than world-readable.
    private func prepareLogIfNeeded() {
        if logChecked { return }
        logChecked = true
        let dir = (logFile as NSString).deletingLastPathComponent
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else { return }

        let attrs = try? fileManager.attributesOfItem(atPath: logFile)
        if let attrs = attrs {
            if let type = attrs[.type] as? FileAttributeType, type == .typeSymbolicLink { return }
            if let links = attrs[.referenceCount] as? Int, links > 1 { return }
        } else {
            guard fileManager.createFile(atPath: logFile, contents: nil,
                                         attributes: [.posixPermissions: 0o600]) else { return }
        }
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: logFile)
        logUsable = true
    }

    private func log(_ level: String, _ message: String) {
        let ts = ISO8601DateFormatter().string(from: Date())
        let line = "\(ts) [\(level)] \(sanitizeForLog(message))"
        FileHandle.standardError.write((line + "\n").data(using: .utf8) ?? Data())

        prepareLogIfNeeded()
        guard logUsable, let data = (line + "\n").data(using: .utf8),
              let handle = FileHandle(forWritingAtPath: logFile) else { return }
        handle.seekToEndOfFile()
        handle.write(data)
        // closeFile() rather than close(): close() is macOS 10.15+, and
        // Package.swift declares a 10.13 deployment target.
        handle.closeFile()
    }
    func info(_ m: String) { log("INFO", m) }
    func warn(_ m: String) { log("WARN", m) }
    func error(_ m: String) { log("ERROR", m) }

    // MARK: - Command execution

    struct CommandResult {
        let stdout: String
        let stderr: String
        let exitCode: Int32
        var combined: String { stdout + stderr }
    }

    /// Run an executable, optionally streaming `secrets` to its stdin (one per
    /// line, in order). Used so sysadminctl passwords are never in `ps`.
    @discardableResult
    private func run(_ launchPath: String, _ args: [String], secrets: [String] = []) -> CommandResult {
        let process = Process()
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = args
        process.standardOutput = outPipe
        process.standardError = errPipe

        var inPipe: Pipe?
        if !secrets.isEmpty {
            let p = Pipe()
            process.standardInput = p
            inPipe = p
        }

        do {
            try process.run()
        } catch {
            return CommandResult(stdout: "", stderr: "spawn failed: \(error)", exitCode: -1)
        }

        if let inPipe = inPipe {
            let handle = inPipe.fileHandleForWriting
            for secret in secrets {
                handle.write((secret + "\n").data(using: .utf8) ?? Data())
            }
            handle.closeFile()   // closeFile(): close() requires macOS 10.15+
        }

        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        return CommandResult(
            stdout: String(data: outData, encoding: .utf8) ?? "",
            stderr: String(data: errData, encoding: .utf8) ?? "",
            exitCode: process.terminationStatus
        )
    }

    /// Build a sysadminctl argument list, substituting secret placeholders with
    /// either `-` (stdin mode) or the literal secret (inline fallback).
    /// `template` entries equal to the sentinel are replaced in order by
    /// `secretValues`.
    private static let secretSentinel = "\u{0}SECRET\u{0}"

    private func runSysadminctl(_ template: [String], secretValues: [String]) -> CommandResult {
        var args: [String] = []
        var fed: [String] = []
        var idx = 0
        for item in template {
            if item == SecureTokenManager.secretSentinel {
                let secret = idx < secretValues.count ? secretValues[idx] : ""
                idx += 1
                if stdinSecrets {
                    args.append("-")
                    fed.append(secret)
                } else {
                    args.append(secret)
                }
            } else {
                args.append(item)
            }
        }
        return run("/usr/sbin/sysadminctl", args, secrets: stdinSecrets ? fed : [])
    }

    private var S: String { SecureTokenManager.secretSentinel }

    // MARK: - Platform probes

    func isRoot() -> Bool { getuid() == 0 }

    func macOSVersion() -> String {
        let r = run("/usr/bin/sw_vers", ["-productVersion"])
        let v = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.isEmpty ? "0.0.0" : v
    }

    /// Returns true if version string `a` >= `b` (dotted numeric compare).
    func versionAtLeast(_ a: String, _ b: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            s.split(separator: ".").map { Int($0.filter { $0.isNumber }) ?? 0 }
        }
        let av = parts(a), bv = parts(b)
        for i in 0..<3 {
            let an = i < av.count ? av[i] : 0
            let bn = i < bv.count ? bv[i] : 0
            if an > bn { return true }
            if an < bn { return false }
        }
        return true
    }

    func supportsSecureToken() -> Bool { versionAtLeast(macOSVersion(), "10.13.0") }

    func isAppleSilicon() -> Bool {
        run("/usr/bin/uname", ["-m"]).stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "arm64"
    }

    func bootIsAPFS() -> Bool {
        let info = run("/usr/sbin/diskutil", ["info", "/"]).combined
        return info.range(of: "APFS", options: .caseInsensitive) != nil
    }

    func mdmEnrolled() -> Bool {
        run("/usr/bin/profiles", ["status", "-type", "enrollment"]).combined
            .range(of: "MDM enrollment: Yes", options: .caseInsensitive) != nil
    }

    func bootstrapTokenEscrowed() -> Bool {
        run("/usr/bin/profiles", ["status", "-type", "bootstraptoken"]).combined
            .range(of: "Bootstrap Token escrowed to server: YES", options: .caseInsensitive) != nil
    }

    // MARK: - Directory services

    func userExists(_ user: String) -> Bool {
        run("/usr/bin/dscl", [".", "-read", "/Users/\(user)"]).exitCode == 0
    }

    func hasSecureToken(_ user: String) -> Bool {
        run("/usr/sbin/sysadminctl", ["-secureTokenStatus", user]).combined
            .range(of: "ENABLED", options: .caseInsensitive) != nil
    }

    func localUsers() -> [String] {
        run("/usr/bin/dscl", [".", "-list", "/Users"]).stdout
            .split(separator: "\n")
            .map { String($0) }
            .filter { !$0.isEmpty && !$0.hasPrefix("_") && !["daemon", "nobody", "root"].contains($0) }
    }

    func tokenHolders() -> [String] { localUsers().filter { hasSecureToken($0) } }

    // MARK: - Validation

    private static let reserved: Set<String> = ["root", "daemon", "nobody", "admin", "wheel", "kmem", "sys", "tty", "staff"]

    func validateUsername(_ u: String) throws {
        guard !u.isEmpty, u.count <= 244 else {
            throw SecureTokenError.usage("Username must be 1-244 characters")
        }
        guard let first = u.first, first.isLetter, first.isASCII else {
            throw SecureTokenError.usage("Username must start with an ASCII letter: '\(u)'")
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        guard u.unicodeScalars.allSatisfy({ allowed.contains($0) && $0.isASCII }) else {
            throw SecureTokenError.usage("Username may contain only ASCII letters, digits, '-' and '_': '\(u)'")
        }
        if SecureTokenManager.reserved.contains(u.lowercased()) {
            throw SecureTokenError.usage("Username '\(u)' is reserved")
        }
    }

    func validatePassword(_ p: String) throws {
        guard p.count >= 4 else { throw SecureTokenError.usage("Password must be at least 4 characters") }
    }

    func generatePassword(length: Int = 20) -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%^&*_-")
        var out = ""
        for _ in 0..<length {
            let idx = Int.random(in: 0..<alphabet.count)
            out.append(alphabet[idx])
        }
        return out
    }

    // MARK: - Token method resolution

    /// Verify a password actually authenticates for a user.
    func passwordAuthenticates(_ user: String, _ password: String) -> Bool {
        run("/usr/bin/dscl", [".", "-authonly", user, password]).exitCode == 0
    }

    /// Can macOS grant the token at first login via an escrowed Bootstrap Token?
    /// Requires macOS 11+ (grant-at-login for scripted local users).
    func bootstrapLoginGrantAvailable() -> Bool {
        versionAtLeast(macOSVersion(), "11.0.0") && mdmEnrolled() && bootstrapTokenEscrowed()
    }

    /// Decide how the token will be obtained.
    ///
    /// Per Apple's Platform Deployment guide, changing secure token status with
    /// sysadminctl ALWAYS requires an existing secure token administrator's
    /// credentials — a Bootstrap Token cannot be spent by sysadminctl. The
    /// Bootstrap Token instead causes macOS to grant the token at the user's
    /// first login (macOS 11+). So the admin path is preferred (immediate and
    /// verifiable) and the bootstrap path is a deferred fallback.
    func resolveTokenPlan(adminUser: String?, adminPassword: String?) throws -> (TokenMethod, String?, String?) {
        if let au = adminUser, let ap = adminPassword, !au.isEmpty, !ap.isEmpty {
            guard userExists(au) else { throw SecureTokenError.noTokenSource("Token admin '\(au)' does not exist") }
            guard hasSecureToken(au) else { throw SecureTokenError.noTokenSource("Token admin '\(au)' has no Secure Token") }
            guard passwordAuthenticates(au, ap) else {
                throw SecureTokenError.noTokenSource("Token admin '\(au)' password is incorrect (verified with dscl -authonly)")
            }
            info("Token plan: immediate grant using Secure Token admin '\(au)'")
            return (.admin, au, ap)
        }
        if preferBootstrap, bootstrapLoginGrantAvailable() {
            info("Token plan: no admin credentials; Bootstrap Token will grant the token at FIRST LOGIN (macOS 11+)")
            return (.deferredLogin, nil, nil)
        }
        throw SecureTokenError.noTokenSource(
            "No Secure Token admin credentials supplied and no Bootstrap Token available for a first-login grant. "
            + "sysadminctl cannot grant a Secure Token without an existing token holder's credentials.")
    }

    // MARK: - Operations

    func createUser(username: String, fullName: String, password: String, makeAdmin: Bool,
                    hidden: Bool, uid: String?) throws {
        if userExists(username) {
            info("User '\(username)' already exists — skipping creation")
            return
        }
        info("Creating user '\(username)' (admin=\(makeAdmin) hidden=\(hidden))")

        var template = ["-addUser", username, "-fullName", fullName, "-password", S]
        if let uid = uid, !uid.isEmpty { template += ["-UID", uid] }
        if makeAdmin { template.append("-admin") }

        let r = runSysadminctl(template, secretValues: [password])
        if r.exitCode != 0 || !userExists(username) {
            throw SecureTokenError.createFailed("Failed to create '\(username)': \(r.combined)")
        }
        // Confirm the password we believe we set actually authenticates, so a
        // mis-delivered secret is caught before the credential is handed back.
        guard passwordAuthenticates(username, password) else {
            throw SecureTokenError.createFailed(
                "User '\(username)' was created but the intended password does not authenticate. Investigate before using this account.")
        }
        _ = run("/usr/sbin/createhomedir", ["-c", "-u", username])
        if hidden {
            let h = run("/usr/bin/dscl", [".", "-create", "/Users/\(username)", "IsHidden", "1"])
            if h.exitCode != 0 {
                warn("Could not set IsHidden on '\(username)' — the account will be visible at the login window")
            }
        }
        info("User '\(username)' created")
    }

    /// Ensure `user` ends up with a Secure Token, or that a deferred first-login
    /// grant is arranged. Returns the method used.
    @discardableResult
    func ensureToken(user: String, password: String, adminUser: String?, adminPassword: String?) throws -> TokenMethod {
        if hasSecureToken(user) {
            info("User '\(user)' already holds a Secure Token")
            return .existing
        }
        if !bootIsAPFS() {
            throw SecureTokenError.precondition("Boot volume is not APFS; Secure Tokens unavailable")
        }
        let (method, au, ap) = try resolveTokenPlan(adminUser: adminUser, adminPassword: adminPassword)

        if method == .deferredLogin {
            info("Secure Token will be granted by macOS at '\(user)' first login (Bootstrap Token). No token is present yet — this is expected.")
            return .deferredLogin
        }

        let template = ["-secureTokenOn", user, "-password", S, "-adminUser", au ?? "", "-adminPassword", S]
        let r = runSysadminctl(template, secretValues: [password, ap ?? ""])
        if r.exitCode != 0 {
            throw SecureTokenError.grantFailed("Failed to grant token to '\(user)': \(r.combined)")
        }
        // sysadminctl often exits 0 even when the grant failed, so the status
        // re-read is the authoritative check.
        if !hasSecureToken(user) {
            throw SecureTokenError.verifyFailed("Secure Token not ENABLED for '\(user)' after grant")
        }
        info("Secure Token granted to '\(user)' via admin '\(au ?? "")'")
        return .admin
    }
}
