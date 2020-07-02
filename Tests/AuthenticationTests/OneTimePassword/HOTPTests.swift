//
//  HOTPTests.swift
//  Security
//
//  Created by Michel Tilman on 29/06/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import XCTest
@testable import Authentication

/**
 Tests generation and validation of HOTP passwords.
 */
class HOTPTests: XCTestCase {

    // MARK: Testing creating a HOTP service
    
    // Test creating a HOTP service with default values.
    func testDefaults() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret) else { return XCTFail("nil HOTP") }
        
        XCTAssertEqual(hotp.algorithm, .sha256)
        XCTAssertEqual(hotp.digits, 6)
    }
    
    // Test creating a HOTP service with non-default values.
    func testNonDefaults() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret, algorithm: .sha1, digits: 8) else { return XCTFail("nil HOTP") }
        
        XCTAssertEqual(hotp.algorithm, .sha1)
        XCTAssertEqual(hotp.digits, 8)
    }
    
    // Test creating HOTP services with invalid digits.
    func testInvalidDigits() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        
        XCTAssertNil(HOTP(secret: secret, digits: 0))
        XCTAssertNil(HOTP(secret: secret, digits: 10))
    }
    
    // Test creating HOTP services with minimum and maximum valid digits.
    func testValidDigits() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        
        XCTAssertNotNil(HOTP(secret: secret, digits: 1))
        XCTAssertNotNil(HOTP(secret: secret, digits: 9))
    }
    
    // MARK: Testing generating RFC 4226 reference passwords
    
    // Test generating SHA1-based passwords for counters 0 through 9, truncating to 6 digits and using the secret listed in the RFC.
    func testGenerateRFC4226Passwords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret, algorithm: .sha1) else { return XCTFail("nil HOTP") }
        
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertEqual(hotp.generatePassword(for: Int64(i)), expected[i])
        }
    }
    
    // Test generating passwords for different counter / secret / hash algorithm / digits combinations.
    // Compare results with test data produced by the RFC4226 Java reference implementation.
    func testGenerateTestDataPasswords() {
        let algorithms = ["SHA1": HOTP.Algorithm.sha1, "SHA256": .sha256, "SHA384": .sha384, "SHA512": .sha512]
        
        for (counter, secret, algorithm, digits, otp) in HOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            guard let algorithm = algorithms[algorithm] else { return XCTFail("Unsupported algorithm") }
            guard let hotp = HOTP(secret: secret, algorithm: algorithm, digits: digits) else { return XCTFail("nil HOTP") }
            
            XCTAssertEqual(hotp.generatePassword(for: Int64(counter)), otp)
        }
    }
    
    // MARK: Testing validating RFC 4226 reference passwords
    
    // Test validating wrong passwords for the RFC2446 reference counter / passwords.
    func testInvalidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret, algorithm: .sha1) else { return XCTFail("nil HOTP") }
        
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            for j in 0 ... 9 where j != i {
                XCTAssertFalse(hotp.isValidPassword(expected[i], for: Int64(j)))
            }
        }
    }
    
    // Test validating the RFC2446 reference passwords.
    func testValidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = HOTP(secret: secret, algorithm: .sha1) else { return XCTFail("nil HOTP") }
        
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertTrue(hotp.isValidPassword(expected[i], for: Int64(i)))
        }
    }
    
}


/**
 HOTP test suite.
 */
extension HOTPTests {
    
    static var allTests = [
        ("testDefaults", testDefaults),
        ("testNonDefaults", testNonDefaults),
        ("testInvalidDigits", testInvalidDigits),
        ("testValidDigits", testValidDigits),
        ("testGenerateRFC4226Passwords", testGenerateRFC4226Passwords),
        ("testGenerateTestDataPasswords", testGenerateTestDataPasswords),
        ("testInvalidPasswords", testInvalidPasswords),
        ("testValidPasswords", testValidPasswords),
    ]
    
}
