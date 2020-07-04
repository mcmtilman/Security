//
//  WHOTPTests.swift
//  Security
//
//  Created by Michel Tilman on 02/07/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import XCTest
@testable import Authentication

/**
 Tests generation and validation of HOTP passwords.
 */
class WHOTPTests: XCTestCase {

    // MARK: Testing creating a WHOTP service
    
    // Test creating a WHOTP service with default values.
    func testDefaults() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret) else { return XCTFail("nil HOTP") }
        guard let whotp = WHOTP(hotp: hotp) else { return XCTFail("nil WHOTP") }

        XCTAssertEqual(whotp.window, 1)
    }
    
    // Test creating a WHOTP service with non-default values.
    func testNonDefaults() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret) else { return XCTFail("nil HOTP") }
        guard let whotp = WHOTP(hotp: hotp, window: 3) else { return XCTFail("nil WHOTP") }

        XCTAssertEqual(whotp.window, 3)
    }
    
    // Test creating WHOTP services with invalid windows.
    func testInvalidWindow() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret) else { return XCTFail("nil HOTP") }

        XCTAssertNil(WHOTP(hotp: hotp, window: 0))
        XCTAssertNil(WHOTP(hotp: hotp, window: 6))
    }
    
    // Test creating WHOTP services with minimum and maximum valid windows.
    func testValidWindow() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret) else { return XCTFail("nil HOTP") }

        XCTAssertNotNil(WHOTP(hotp: hotp, window: 1))
        XCTAssertNotNil(WHOTP(hotp: hotp, window: 5))
    }
    
    // MARK: Testing generating RFC 4226 reference passwords
    
    // Test generating SHA1-based passwords for counters 0 through 9, truncating to 6 digits and using the secret listed in the RFC.
    func testGenerateRFC4226Passwords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret, algorithm: .sha1) else { return XCTFail("nil HOTP") }
        guard let whotp = WHOTP(hotp: hotp) else { return XCTFail("nil WHOTP") }

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertEqual(whotp.generatePassword(for: Int64(i)), expected[i])
        }
    }
    
    // Test generating passwords for different counter / secret / hash algorithm / digits combinations.
    // Compare results with test data produced by the RFC4226 Java reference implementation.
    func testGenerateTestDataPasswords() {
        let algorithms = ["SHA1": HOTP.Algorithm.sha1, "SHA256": .sha256, "SHA384": .sha384, "SHA512": .sha512]
        
        for (counter, secret, algorithm, digits, otp, _) in HOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            guard let algorithm = algorithms[algorithm] else { return XCTFail("Unsupported algorithm") }
            guard let hotp = HOTP(secret: secret, algorithm: algorithm, digits: digits) else { return XCTFail("nil HOTP") }
            guard let whotp = WHOTP(hotp: hotp) else { return XCTFail("nil WHOTP") }

            XCTAssertEqual(whotp.generatePassword(for: Int64(counter)), otp)
        }
    }
    
    // MARK: Testing validating RFC 4226 reference passwords
    
    // Test validating the RFC2446 reference passwords for counters outside a window of 2 of the actual counter.
    func testInvalidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret, algorithm: .sha1) else { return XCTFail("nil HOTP") }
        guard let whotp = WHOTP(hotp: hotp, window: 2) else { return XCTFail("nil WHOTP") }

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertFalse(whotp.isValidPassword(expected[i], for: Int64(i - 3)))
            XCTAssertFalse(whotp.isValidPassword(expected[i], for: Int64(i + 3)))
        }
    }
    
    // Test validating the RFC2446 reference passwords for counters inside a window of 2 of the actual counter.
    func testValidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret, algorithm: .sha1) else { return XCTFail("nil HOTP") }
        guard let whotp = WHOTP(hotp: hotp, window: 2) else { return XCTFail("nil WHOTP") }

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            for j in -2 ... 2 {
                XCTAssertTrue(whotp.isValidPassword(expected[i], for: Int64(i + j)))
            }
        }
    }
    
}


/**
 WHOTP test suite.
 */
extension WHOTPTests {
    
    static var allTests = [
        ("testDefaults", testDefaults),
        ("testNonDefaults", testNonDefaults),
        ("testInvalidWindow", testInvalidWindow),
        ("testValidWindow", testValidWindow),
        ("testGenerateRFC4226Passwords", testGenerateRFC4226Passwords),
        ("testGenerateTestDataPasswords", testGenerateTestDataPasswords),
        ("testInvalidPasswords", testInvalidPasswords),
        ("testValidPasswords", testValidPasswords),
    ]
    
}
