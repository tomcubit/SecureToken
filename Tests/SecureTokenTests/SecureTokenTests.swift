import XCTest
@testable import SecureToken

final class SecureTokenTests: XCTestCase {

    var mgr: SecureTokenManager!

    override func setUp() {
        super.setUp()
        // Use a temp log path so tests never touch /var/log.
        mgr = SecureTokenManager(logFile: NSTemporaryDirectory() + "securetoken-test.log")
    }

    override func tearDown() { mgr = nil; super.tearDown() }

    // MARK: - Version comparison (platform-independent)

    func testVersionAtLeast() {
        XCTAssertTrue(mgr.versionAtLeast("14.5.0", "10.13.0"))
        XCTAssertTrue(mgr.versionAtLeast("10.13.0", "10.13.0"))
        XCTAssertTrue(mgr.versionAtLeast("11.0.1", "10.15.0"))
        XCTAssertTrue(mgr.versionAtLeast("15", "10.13.0"))
        XCTAssertFalse(mgr.versionAtLeast("10.12.6", "10.13.0"))
        XCTAssertFalse(mgr.versionAtLeast("9.9", "10.0"))
    }

    // MARK: - Username validation

    func testValidUsernames() throws {
        for u in ["jsmith", "a_b-c1", "User1", "a"] {
            XCTAssertNoThrow(try mgr.validateUsername(u), "'\(u)' should be valid")
        }
    }

    func testInvalidUsernames() {
        for u in ["", "1abc", "_svc", "-x", "has space", "user@host", "root", "ROOT", "daemon"] {
            XCTAssertThrowsError(try mgr.validateUsername(u), "'\(u)' should be rejected") { err in
                XCTAssertTrue(err is SecureTokenError)
                if let e = err as? SecureTokenError {
                    XCTAssertEqual(e.status, .usage)
                }
            }
        }
    }

    func testPasswordValidation() {
        XCTAssertNoThrow(try mgr.validatePassword("abcd"))
        XCTAssertNoThrow(try mgr.validatePassword("longenoughpassword"))
        XCTAssertThrowsError(try mgr.validatePassword("abc"))
        XCTAssertThrowsError(try mgr.validatePassword(""))
    }

    // MARK: - Password generation

    func testGeneratePassword() {
        let a = mgr.generatePassword(length: 20)
        let b = mgr.generatePassword(length: 20)
        XCTAssertEqual(a.count, 20)
        XCTAssertEqual(b.count, 20)
        XCTAssertNotEqual(a, b, "two generations should differ")
        // No ambiguous characters (0/O/1/l/I) in the alphabet.
        for ch in "0O1lI" {
            XCTAssertFalse(a.contains(ch), "generated password should avoid ambiguous '\(ch)'")
        }
    }

    // MARK: - Exit-code contract

    func testExitCodeContract() {
        // Must stay in lockstep with scripts/securetoken.sh.
        XCTAssertEqual(ExitStatus.ok.rawValue, 0)
        XCTAssertEqual(ExitStatus.usage.rawValue, 2)
        XCTAssertEqual(ExitStatus.notRoot.rawValue, 10)
        XCTAssertEqual(ExitStatus.unsupported.rawValue, 11)
        XCTAssertEqual(ExitStatus.precondition.rawValue, 12)
        XCTAssertEqual(ExitStatus.createFailed.rawValue, 20)
        XCTAssertEqual(ExitStatus.grantFailed.rawValue, 21)
        XCTAssertEqual(ExitStatus.noTokenSource.rawValue, 22)
        XCTAssertEqual(ExitStatus.tokenDeferred.rawValue, 23)
        XCTAssertEqual(ExitStatus.verifyFailed.rawValue, 40)
    }

    /// The tokenMethod strings are a documented part of the JSON contract.
    func testTokenMethodRawValues() {
        XCTAssertEqual(TokenMethod.admin.rawValue, "admin")
        XCTAssertEqual(TokenMethod.deferredLogin.rawValue, "deferred-login")
        XCTAssertEqual(TokenMethod.existing.rawValue, "existing")
        XCTAssertEqual(TokenMethod.none.rawValue, "none")
    }

    // MARK: - JSON result serialisation

    func testJSONResultShape() {
        let r = OperationResult(status: "ok", exitCode: 0, action: "create-user",
                                user: "itadmin", tokenMethod: TokenMethod.admin.rawValue,
                                message: "done", generatedPassword: nil)
        let line = r.jsonLine(version: SecureTokenManager.version)
        XCTAssertTrue(line.contains("\"tool\":\"securetoken\""))
        XCTAssertTrue(line.contains("\"status\":\"ok\""))
        XCTAssertTrue(line.contains("\"exitCode\":0"))
        XCTAssertTrue(line.contains("\"user\":\"itadmin\""))
        XCTAssertTrue(line.contains("\"tokenMethod\":\"admin\""))
        XCTAssertFalse(line.contains("generatedPassword"), "should omit when nil")
    }

    func testJSONResultDeferredMethod() {
        let r = OperationResult(status: "ok", exitCode: 0, action: "create-user",
                                user: "itadmin", tokenMethod: TokenMethod.deferredLogin.rawValue,
                                message: "deferred", generatedPassword: nil)
        XCTAssertTrue(r.jsonLine(version: SecureTokenManager.version)
                        .contains("\"tokenMethod\":\"deferred-login\""))
    }

    func testJSONResultEscaping() {
        let r = OperationResult(status: "error", exitCode: 20, action: "create-user",
                                user: "he\"quote", tokenMethod: "none",
                                message: "line1\nline2\ttab", generatedPassword: "p\\w")
        let line = r.jsonLine(version: SecureTokenManager.version)
        XCTAssertTrue(line.contains("he\\\"quote"))
        XCTAssertTrue(line.contains("line1\\nline2\\ttab"))
        XCTAssertTrue(line.contains("\"generatedPassword\":\"p\\\\w\""))
    }

    // MARK: - macOS-only smoke tests (do not assert environment specifics)

    func testProbesDoNotCrash() {
        #if os(macOS)
        _ = mgr.isRoot()
        _ = mgr.macOSVersion()
        _ = mgr.isAppleSilicon()
        _ = mgr.localUsers()
        _ = mgr.userExists("definitely_not_a_user_\(UUID().uuidString.prefix(6))")
        #endif
    }
}
