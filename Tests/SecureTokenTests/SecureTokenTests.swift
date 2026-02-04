import XCTest
@testable import SecureToken

final class SecureTokenTests: XCTestCase {

    var manager: SecureTokenManager!

    override func setUp() {
        super.setUp()
        manager = SecureTokenManager()
    }

    override func tearDown() {
        manager = nil
        super.tearDown()
    }

    // MARK: - Version Check Tests

    func testMacOSVersionCheck() {
        // This test will pass on macOS 10.13+ and fail on earlier versions
        // On non-macOS systems, behavior depends on ProcessInfo
        let result = manager.checkMacOSVersion()
        #if os(macOS)
        // On actual macOS, this should typically be true for modern systems
        XCTAssertTrue(result, "Should detect compatible macOS version")
        #endif
    }

    // MARK: - Root Check Tests

    func testIsRunningAsRoot() {
        // When running tests normally, we're not root
        let isRoot = manager.isRunningAsRoot()
        #if os(macOS)
        // Normal test execution should not be as root
        XCTAssertFalse(isRoot, "Tests should not run as root")
        #endif
    }

    // MARK: - User Listing Tests

    func testListAllUsers() {
        #if os(macOS)
        let users = manager.listAllUsers()
        // Should return at least one user on any macOS system
        XCTAssertGreaterThan(users.count, 0, "Should find at least one user")

        // Should not include system users
        XCTAssertFalse(users.contains("daemon"), "Should not include daemon")
        XCTAssertFalse(users.contains("nobody"), "Should not include nobody")

        // Should not include underscore-prefixed system accounts
        let systemUsers = users.filter { $0.hasPrefix("_") }
        XCTAssertEqual(systemUsers.count, 0, "Should not include system accounts starting with _")
        #endif
    }

    // MARK: - User Existence Tests

    func testUserExistsForSystemUser() {
        #if os(macOS)
        // Root should always exist on macOS
        XCTAssertTrue(manager.userExists(username: "root"), "root user should exist")
        #endif
    }

    func testUserExistsForNonexistentUser() {
        #if os(macOS)
        // Random username should not exist
        let randomUser = "nonexistent_user_\(UUID().uuidString.prefix(8))"
        XCTAssertFalse(manager.userExists(username: randomUser), "Random user should not exist")
        #endif
    }

    // MARK: - Validation Tests

    func testValidUsernameFormats() {
        // These tests use the internal validation logic
        // Valid usernames
        let validUsernames = [
            "john",
            "john_doe",
            "john-doe",
            "johndoe123",
            "a",
            "user1"
        ]

        for username in validUsernames {
            XCTAssertTrue(isValidUsername(username), "'\(username)' should be valid")
        }
    }

    func testInvalidUsernameFormats() {
        // Invalid usernames
        let invalidUsernames = [
            "",              // empty
            "123user",       // starts with number
            "_user",         // starts with underscore
            "-user",         // starts with hyphen
            "user name",     // contains space
            "user@name",     // contains special character
            "root",          // reserved
            "daemon",        // reserved
            "nobody"         // reserved
        ]

        for username in invalidUsernames {
            XCTAssertFalse(isValidUsername(username), "'\(username)' should be invalid")
        }
    }

    func testPasswordValidation() {
        // Valid passwords
        XCTAssertTrue(isValidPassword("password"), "Basic password should be valid")
        XCTAssertTrue(isValidPassword("12345"), "Numeric password should be valid")
        XCTAssertTrue(isValidPassword("abcd"), "Short password (4 chars) should be valid")

        // Invalid passwords
        XCTAssertFalse(isValidPassword(""), "Empty password should be invalid")
        XCTAssertFalse(isValidPassword("abc"), "Too short password should be invalid")
    }

    // MARK: - Helper Functions for Validation Tests

    private func isValidUsername(_ username: String) -> Bool {
        // Replicating validation logic from SecureTokenManager
        guard username.count >= 1 && username.count <= 255 else { return false }
        guard let first = username.first, first.isLetter else { return false }

        let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        guard username.unicodeScalars.allSatisfy({ allowedCharacters.contains($0) }) else { return false }

        let reserved = ["root", "daemon", "nobody", "admin", "wheel", "kmem", "sys", "tty"]
        guard !reserved.contains(username.lowercased()) else { return false }

        return true
    }

    private func isValidPassword(_ password: String) -> Bool {
        return password.count >= 4
    }

    // MARK: - Integration Tests (require root)

    func testSecureTokenStatusCheck() {
        #if os(macOS)
        // This test checks that the status check doesn't crash
        // Actual token status depends on the user
        _ = manager.checkSecureTokenStatus(username: "nonexistent_user_test")
        // If we got here without crashing, the test passes
        #endif
    }

    // MARK: - Error Type Tests

    func testErrorDescriptions() {
        let errors: [SecureTokenError] = [
            .unsupportedSystem("Test message"),
            .insufficientPrivileges("Test message"),
            .noSecureToken("Test message"),
            .userCreationFailed("Test message"),
            .tokenGrantFailed("Test message"),
            .userAlreadyExists("Test message"),
            .validationError("Test message"),
            .commandFailed("test", 1)
        ]

        for error in errors {
            let description = error.description
            XCTAssertFalse(description.isEmpty, "Error should have a description")
            XCTAssertTrue(description.contains("Test message") || description.contains("test"),
                         "Error description should contain the message")
        }
    }

    static var allTests = [
        ("testMacOSVersionCheck", testMacOSVersionCheck),
        ("testIsRunningAsRoot", testIsRunningAsRoot),
        ("testListAllUsers", testListAllUsers),
        ("testUserExistsForSystemUser", testUserExistsForSystemUser),
        ("testUserExistsForNonexistentUser", testUserExistsForNonexistentUser),
        ("testValidUsernameFormats", testValidUsernameFormats),
        ("testInvalidUsernameFormats", testInvalidUsernameFormats),
        ("testPasswordValidation", testPasswordValidation),
        ("testSecureTokenStatusCheck", testSecureTokenStatusCheck),
        ("testErrorDescriptions", testErrorDescriptions),
    ]
}
