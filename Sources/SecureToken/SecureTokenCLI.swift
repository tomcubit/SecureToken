import Foundation
import ArgumentParser

// MARK: - Shared helpers

/// Read an ST_* environment variable, returning nil if unset/empty.
func env(_ name: String) -> String? {
    if let v = ProcessInfo.processInfo.environment[name], !v.isEmpty { return v }
    return nil
}

func envFlag(_ name: String) -> Bool {
    guard let v = env(name)?.lowercased() else { return false }
    return ["1", "true", "yes", "on", "y"].contains(v)
}

/// Emit a JSON result line to stdout when requested, then return the exit code.
func finish(json: Bool, result: OperationResult) -> Never {
    if json { print(result.jsonLine(version: SecureTokenManager.version)) }
    exit(result.exitCode)
}

/// Convert a thrown SecureTokenError into a JSON line (optional) + exit code.
///
/// `generatedPassword` must be passed whenever the tool actually applied a
/// generated password to a real account: dropping it on a failure path would
/// leave an account nobody holds the credential for.
func fail(json: Bool, action: String, user: String, method: TokenMethod, _ error: Error,
          generatedPassword: String? = nil) -> Never {
    let message: String
    let code: Int32
    if let e = error as? SecureTokenError {
        message = e.message; code = e.code
    } else {
        message = "\(error)"; code = ExitStatus.usage.rawValue
    }
    FileHandle.standardError.write(("ERROR: " + message + "\n").data(using: .utf8) ?? Data())
    if json {
        let r = OperationResult(status: "error", exitCode: code, action: action,
                                user: user, tokenMethod: method.rawValue, message: message,
                                generatedPassword: generatedPassword)
        print(r.jsonLine(version: SecureTokenManager.version))
    }
    exit(code)
}

func requireDarwinRootSupported(_ mgr: SecureTokenManager, json: Bool, action: String) {
    #if os(macOS)
    guard mgr.isRoot() else {
        fail(json: json, action: action, user: "", method: .none,
             SecureTokenError.notRoot("Must run as root (use sudo or an RMM/Intune run-as-root policy)"))
    }
    guard mgr.supportsSecureToken() else {
        fail(json: json, action: action, user: "", method: .none,
             SecureTokenError.unsupported("Secure Tokens require macOS 10.13+ (found \(mgr.macOSVersion()))"))
    }
    #else
    fail(json: json, action: action, user: "", method: .none,
         SecureTokenError.unsupported("This tool runs on macOS only"))
    #endif
}

// MARK: - Root command

@main
struct SecureToken: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "securetoken",
        abstract: "Automate macOS Secure Token provisioning (RMM/Intune-ready)",
        version: SecureTokenManager.version,
        subcommands: [Preflight.self, CreateUser.self, GrantToken.self, Status.self, ListTokens.self, Interactive.self],
        defaultSubcommand: CreateUser.self
    )
}

// MARK: - Common options

struct CommonOptions: ParsableArguments {
    @Flag(name: .long, help: "Emit a JSON result line on stdout (or ST_JSON=1).")
    var json = false

    @Option(name: .long, help: "Secret delivery: inline (default) or stdin (ST_SECRET_MODE). '-'/stdin is an interactive prompt and needs a TTY.")
    var secretMode: String?

    @Flag(name: .long, help: "Do not fall back to a deferred first-login Bootstrap Token grant (ST_PREFER_BOOTSTRAP=0).")
    var noBootstrap = false

    @Flag(name: .long, help: "Treat a deferred (first-login) grant as a failure (ST_REQUIRE_IMMEDIATE_TOKEN=1).")
    var requireImmediate = false

    @Option(name: .long, help: "Log file path (default /var/log/securetoken.log or ST_LOG_FILE).")
    var logFile: String?

    var jsonEnabled: Bool { json || envFlag("ST_JSON") }
    var requireImmediateToken: Bool { requireImmediate || envFlag("ST_REQUIRE_IMMEDIATE_TOKEN") }

    func makeManager() -> SecureTokenManager {
        let mgr = SecureTokenManager(logFile: logFile ?? env("ST_LOG_FILE") ?? "/var/log/securetoken.log")
        let mode = (secretMode ?? env("ST_SECRET_MODE") ?? "inline").lowercased()
        mgr.stdinSecrets = (mode == "stdin")
        mgr.preferBootstrap = !(noBootstrap || (env("ST_PREFER_BOOTSTRAP").map { $0 == "0" } ?? false))
        return mgr
    }
}

// MARK: - preflight

struct Preflight: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Report system readiness for Secure Token provisioning.")
    @OptionGroup var common: CommonOptions

    func run() throws {
        let mgr = common.makeManager()
        let json = common.jsonEnabled
        let v = mgr.macOSVersion()
        mgr.info("securetoken \(SecureTokenManager.version) preflight")
        mgr.info("macOS version : \(v)")
        mgr.info("architecture  : \(mgr.isAppleSilicon() ? "arm64" : "intel")")
        mgr.info("root          : \(mgr.isRoot() ? "yes" : "NO")")
        mgr.info("secure token  : \(mgr.supportsSecureToken() ? "supported" : "UNSUPPORTED")")
        mgr.info("boot volume   : \(mgr.bootIsAPFS() ? "APFS" : "NOT APFS")")
        mgr.info("mdm enrolled  : \(mgr.mdmEnrolled() ? "yes" : "no")")
        let bt = mgr.bootstrapTokenEscrowed()
        mgr.info("bootstrap tok : \(bt ? "yes" : "no")")
        mgr.info("token holders : \(mgr.tokenHolders().joined(separator: ", "))")

        // Readiness reflects how a token could actually be obtained. sysadminctl
        // cannot spend a Bootstrap Token, so "escrowed" alone is not readiness:
        // it only enables a deferred grant at the user's first login.
        let haveAdmin = (env("ST_ADMIN_USER") != nil) && (env("ST_ADMIN_PASSWORD") != nil)
        let loginGrant = mgr.bootstrapLoginGrantAvailable()
        let readinessMsg: String
        var ready = mgr.isRoot() && mgr.supportsSecureToken()
        if haveAdmin {
            readinessMsg = "admin credentials supplied — immediate grant possible"
        } else if loginGrant {
            readinessMsg = "no admin credentials — token will be granted at first login (Bootstrap Token)"
        } else {
            readinessMsg = "NOT READY: supply ST_ADMIN_USER/ST_ADMIN_PASSWORD (a Secure Token holder), or enrol with an escrowed Bootstrap Token"
            ready = false
        }
        mgr.info("readiness     : \(readinessMsg)")
        finish(json: json, result: OperationResult(
            status: ready ? "ok" : "error",
            exitCode: ready ? ExitStatus.ok.rawValue : ExitStatus.unsupported.rawValue,
            action: "preflight", user: "",
            tokenMethod: haveAdmin ? "admin" : (loginGrant ? "deferred-login" : "none"),
            message: readinessMsg, generatedPassword: nil))
    }
}

// MARK: - create-user

struct CreateUser: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Create a user (if needed) and ensure it holds a Secure Token.")
    @OptionGroup var common: CommonOptions

    @Option(name: .long) var username: String?
    @Option(name: .long) var fullname: String?
    @Option(name: .long) var password: String?
    @Flag(name: .long, help: "Generate a strong random password (ST_GENERATE_PASSWORD=1).")
    var generatePassword = false
    @Flag(name: .long) var makeAdmin = false
    @Flag(name: .long) var hidden = false
    @Option(name: .long) var uid: String?
    @Option(name: .long) var adminUser: String?
    @Option(name: .long) var adminPassword: String?

    func run() throws {
        let mgr = common.makeManager()
        let json = common.jsonEnabled
        let action = "create-user"
        requireDarwinRootSupported(mgr, json: json, action: action)

        let user = username ?? env("ST_NEW_USER") ?? ""
        var generated: String? = nil
        var passwordApplied = false
        do {
            try mgr.validateUsername(user)
        } catch { fail(json: json, action: action, user: user, method: .none, error) }

        // Resolve password: explicit, env, or generated on request.
        var pw = password ?? env("ST_NEW_PASSWORD") ?? ""
        let wantGenerate = generatePassword || envFlag("ST_GENERATE_PASSWORD")
        if pw.isEmpty {
            if wantGenerate {
                pw = mgr.generatePassword()
                generated = pw
                mgr.info("Generated a random password (surfaced in JSON result)")
            } else {
                fail(json: json, action: action, user: user, method: .none,
                     SecureTokenError.usage("No password supplied (set --password, ST_NEW_PASSWORD, or --generate-password)"))
            }
        }

        let full = fullname ?? env("ST_NEW_FULLNAME") ?? user
        let admin = makeAdmin || envFlag("ST_MAKE_ADMIN")
        let hide = hidden || envFlag("ST_HIDDEN")
        let resolvedUID = uid ?? env("ST_UID")
        let au = adminUser ?? env("ST_ADMIN_USER")
        let ap = adminPassword ?? env("ST_ADMIN_PASSWORD")

        do {
            try mgr.validatePassword(pw)
            if mgr.userExists(user) && mgr.hasSecureToken(user) {
                mgr.info("User '\(user)' already provisioned — nothing to do")
                finish(json: json, result: OperationResult(status: "ok", exitCode: 0, action: action,
                    user: user, tokenMethod: "existing", message: "already provisioned", generatedPassword: nil))
            }
            if mgr.userExists(user) {
                mgr.warn("User '\(user)' already exists; token grant uses the supplied password and fails if it does not match")
            }
            // Fail fast: prove a token source is viable (including that the admin
            // password authenticates) BEFORE creating anything, so a stale
            // credential cannot leave an orphaned tokenless account behind.
            let plan = try mgr.resolveTokenPlan(adminUser: au, adminPassword: ap)
            if plan.0 == .deferredLogin && common.requireImmediateToken {
                throw SecureTokenError(status: .tokenDeferred,
                    message: "No admin credentials supplied: the Secure Token can only be granted at first login, but --require-immediate was set")
            }

            try mgr.createUser(username: user, fullName: full, password: pw,
                               makeAdmin: admin, hidden: hide, uid: resolvedUID)
            // The password is now applied to a real account: from here on it must
            // be surfaced even on failure, or the account becomes unreachable.
            passwordApplied = true

            let method = try mgr.ensureToken(user: user, password: pw, adminUser: au, adminPassword: ap)
            if method == .deferredLogin {
                mgr.info("SUCCESS: '\(user)' created. Secure Token will be granted at first login (Bootstrap Token).")
                finish(json: json, result: OperationResult(status: "ok", exitCode: 0, action: action,
                    user: user, tokenMethod: method.rawValue,
                    message: "user created; secure token deferred to first login", generatedPassword: generated))
            }
            mgr.info("SUCCESS: '\(user)' created and holds a Secure Token (method=\(method.rawValue))")
            finish(json: json, result: OperationResult(status: "ok", exitCode: 0, action: action,
                user: user, tokenMethod: method.rawValue,
                message: "user created and secure token granted", generatedPassword: generated))
        } catch {
            // Surface a generated password that was actually applied, so a later
            // failure never leaves an account nobody can log into.
            fail(json: json, action: action, user: user, method: .none, error,
                 generatedPassword: passwordApplied ? generated : nil)
        }
    }
}

// MARK: - grant-token

struct GrantToken: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Grant a Secure Token to an existing user.")
    @OptionGroup var common: CommonOptions
    @Option(name: .long) var username: String?
    @Option(name: .long) var password: String?
    @Option(name: .long) var adminUser: String?
    @Option(name: .long) var adminPassword: String?

    func run() throws {
        let mgr = common.makeManager()
        let json = common.jsonEnabled
        let action = "grant-token"
        requireDarwinRootSupported(mgr, json: json, action: action)

        let user = username ?? env("ST_NEW_USER") ?? ""
        let pw = password ?? env("ST_NEW_PASSWORD") ?? ""
        let au = adminUser ?? env("ST_ADMIN_USER")
        let ap = adminPassword ?? env("ST_ADMIN_PASSWORD")
        do {
            try mgr.validateUsername(user)
            guard mgr.userExists(user) else {
                throw SecureTokenError.usage("User '\(user)' does not exist (use create-user)")
            }
            guard !pw.isEmpty else {
                throw SecureTokenError.usage("Target user's password is required (set --password or ST_NEW_PASSWORD)")
            }
            let method = try mgr.ensureToken(user: user, password: pw, adminUser: au, adminPassword: ap)
            if method == .deferredLogin {
                if common.requireImmediateToken {
                    throw SecureTokenError(status: .tokenDeferred,
                        message: "Secure Token can only be granted at first login, but --require-immediate was set")
                }
                finish(json: json, result: OperationResult(status: "ok", exitCode: 0, action: action,
                    user: user, tokenMethod: method.rawValue,
                    message: "secure token will be granted at first login (Bootstrap Token)", generatedPassword: nil))
            }
            finish(json: json, result: OperationResult(status: "ok", exitCode: 0, action: action,
                user: user, tokenMethod: method.rawValue, message: "secure token ensured", generatedPassword: nil))
        } catch {
            fail(json: json, action: action, user: user, method: .none, error)
        }
    }
}

// MARK: - status

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Report Secure Token status for a user.")
    @OptionGroup var common: CommonOptions
    @Option(name: .long) var username: String?

    func run() throws {
        let mgr = common.makeManager()
        let json = common.jsonEnabled
        // status reads directory services and must not report a confidently
        // wrong answer when run without privileges.
        requireDarwinRootSupported(mgr, json: json, action: "status")
        let user = username ?? env("ST_NEW_USER") ?? ""
        do { try mgr.validateUsername(user) }
        catch { fail(json: json, action: "status", user: user, method: .none, error) }

        guard mgr.userExists(user) else {
            fail(json: json, action: "status", user: user, method: .none,
                 SecureTokenError.usage("User '\(user)' does not exist"))
        }
        let has = mgr.hasSecureToken(user)
        mgr.info("User '\(user)' \(has ? "HAS" : "does NOT have") a Secure Token")
        finish(json: json, result: OperationResult(status: "ok", exitCode: 0, action: "status",
            user: user, tokenMethod: has ? "existing" : "none",
            message: has ? "secure token enabled" : "secure token disabled", generatedPassword: nil))
    }
}

// MARK: - list

struct ListTokens: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list", abstract: "List users that hold a Secure Token.")
    @OptionGroup var common: CommonOptions

    func run() throws {
        let mgr = common.makeManager()
        requireDarwinRootSupported(mgr, json: common.jsonEnabled, action: "list")
        let holders = mgr.tokenHolders()
        mgr.info("Users with a Secure Token:")
        if holders.isEmpty { mgr.info("  (none)") } else { holders.forEach { mgr.info("  - \($0)") } }
        finish(json: common.jsonEnabled, result: OperationResult(status: "ok", exitCode: 0, action: "list",
            user: "", tokenMethod: "", message: holders.joined(separator: ","), generatedPassword: nil))
    }
}

// MARK: - interactive (local admin convenience)

struct Interactive: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Interactive prompts (for local, hands-on use).")

    func run() throws {
        let mgr = SecureTokenManager()
        guard mgr.isRoot() else {
            FileHandle.standardError.write("Must run as root (sudo).\n".data(using: .utf8) ?? Data())
            throw ExitCode(ExitStatus.notRoot.rawValue)
        }
        print("SecureToken \(SecureTokenManager.version) — interactive mode")
        print("Bootstrap Token escrowed: \(mgr.bootstrapTokenEscrowed() ? "yes" : "no")")

        let user = prompt("New username: ")
        let full = prompt("Full name: ")
        let pw = securePrompt("Password: ")
        let admin = yesNo("Administrator? (y/n): ")

        // sysadminctl cannot spend a Bootstrap Token, so admin credentials are
        // what enable an immediate grant. Offer to skip them only when a
        // deferred first-login grant is genuinely available.
        var au: String? = nil
        var ap: String? = nil
        let canDefer = mgr.bootstrapLoginGrantAvailable()
        if canDefer {
            print("A Bootstrap Token is escrowed: without admin credentials the Secure Token")
            print("will be granted automatically at this user's FIRST LOGIN.")
        }
        if !canDefer || yesNo("Supply Secure Token admin credentials for an immediate grant? (y/n): ") {
            au = prompt("Admin username: ")
            ap = securePrompt("Admin password: ")
        }

        do {
            try mgr.validateUsername(user)
            try mgr.validatePassword(pw)
            _ = try mgr.resolveTokenPlan(adminUser: au, adminPassword: ap)  // fail fast
            try mgr.createUser(username: user, fullName: full, password: pw, makeAdmin: admin, hidden: false, uid: nil)
            let method = try mgr.ensureToken(user: user, password: pw, adminUser: au, adminPassword: ap)
            if method == .deferredLogin {
                print("Done — '\(user)' created. Its Secure Token will be granted at first login.")
            } else {
                print("Done — '\(user)' holds a Secure Token (via \(method.rawValue)).")
            }
        } catch let e as SecureTokenError {
            FileHandle.standardError.write(("ERROR: " + e.message + "\n").data(using: .utf8) ?? Data())
            throw ExitCode(e.code)
        }
    }
}

// MARK: - Prompt helpers

func prompt(_ text: String) -> String {
    print(text, terminator: "")
    return readLine() ?? ""
}

func securePrompt(_ text: String) -> String {
    print(text, terminator: "")
    var oldt = termios(); tcgetattr(STDIN_FILENO, &oldt)
    var newt = oldt; newt.c_lflag &= ~UInt(ECHO)
    tcsetattr(STDIN_FILENO, TCSANOW, &newt)
    let line = readLine() ?? ""
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt)
    print()
    return line
}

func yesNo(_ text: String) -> Bool {
    print(text, terminator: "")
    let r = (readLine() ?? "").lowercased()
    return r == "y" || r == "yes"
}
