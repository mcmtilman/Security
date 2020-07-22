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
    
    typealias Algorithm = HOTP.Algorithm
    typealias Configuration = HOTP.Configuration
    
    // MARK: Testing algorithms
    
    // Test byte counts of the various algorithms.
    func testByteCounts() {
        XCTAssertEqual(Algorithm.sha1.byteCount, 20)
        XCTAssertEqual(Algorithm.sha256.byteCount, 32)
        XCTAssertEqual(Algorithm.sha384.byteCount, 48)
        XCTAssertEqual(Algorithm.sha512.byteCount, 64)
    }

    // MARK: Testing creating a HOTP configuration
    
    // Test creating a HOTP configuration with default values.
    func testDefaults() {
        let configuration = Configuration()
        
        XCTAssertEqual(configuration.algorithm, .sha1)
        XCTAssertEqual(configuration.digits, 6)
        XCTAssertNil(configuration.offset)
        XCTAssertNil(configuration.window)
    }
    
    // Test creating a HOTP configuration with non-default values.
    func testNonDefaults() {
        let configuration = Configuration(algorithm: .sha256, digits: 8, offset: 5, window: 2)
        
        XCTAssertEqual(configuration.algorithm, .sha256)
        XCTAssertEqual(configuration.digits, 8)
        XCTAssertEqual(configuration.offset, 5)
        XCTAssertEqual(configuration.window, 2)
    }
    
    // Test creating HOTP configurations with invalid digits.
    func testInvalidDigits() {
        for (given, expected) in [(0, 1), (10, 9)] {
            let configuration = Configuration(digits: given)
            
            XCTAssertEqual(configuration.digits, expected)
        }
    }
    
    // Test creating HOTP configurations with minimum and maximum valid digits.
    func testValidDigits() {
        for (given, expected) in [(1, 1), (9, 9)] {
            let configuration = Configuration(digits: given)
            
            XCTAssertEqual(configuration.digits, expected)
        }
    }
    
    // Test creating HOTP configurations with invalid offset.
    func testInvalidOffset() {
        let offsets = [
            (Algorithm.sha1, -1, 0), (.sha1, 16, 15),
            (.sha256, -1, 0), (.sha256, 28, 27),
            (.sha384, -1, 0), (.sha384, 44, 43),
            (.sha512, -1, 0), (.sha512, 60, 59)
        ]
        
        for (algorithm, given, expected) in offsets {
            let configuration = Configuration(algorithm: algorithm, offset: given)
            
            XCTAssertEqual(configuration.offset, expected)
        }
    }
    
    // Test creating HOTP configurations with minimum and maximum valid offset.
    func testValidOffset() {
        let offsets = [
            (Algorithm.sha1, 0, 0), (.sha1, 16, 15),
            (.sha256, 0, 0), (.sha256, 27, 27),
            (.sha384, 0, 0), (.sha384, 43, 43),
            (.sha512, 0, 0), (.sha512, 59, 59)
        ]
        
        for (algorithm, given, expected) in offsets {
            let configuration = Configuration(algorithm: algorithm, offset: given)
            
            XCTAssertEqual(configuration.offset, expected)
        }
    }
    
    // Test creating HOTP configurations with invalid window.
    func testInvalidWindow() {
        for (given, expected) in [(0, 1), (6, 5)] {
            let configuration = Configuration(window: given)
            
            XCTAssertEqual(configuration.window, expected)
        }
    }
    
    // Test creating HOTP configurations with minimum and maximum valid window.
    func testValidWindow() {
        for (given, expected) in [(1, 1), (5, 5)] {
            let configuration = Configuration(window: given)
            
            XCTAssertEqual(configuration.window, expected)
        }
    }
    
    // MARK: Testing a HOTP service with default configuration
    
    // Test creating a HOTP service with default configuration.
    func testDefaultServiceConfiguration() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret)

        XCTAssertEqual(hotp.configuration.algorithm, .sha1)
        XCTAssertEqual(hotp.configuration.digits, 6)
        XCTAssertNil(hotp.configuration.offset)
        XCTAssertNil(hotp.configuration.window)
    }

    // MARK: Testing generating RFC4226 reference passwords
    
    // Test generating SHA1-based passwords for counters 0 through 9, truncating to 6 digits and using the secret listed in the RFC.
    func testGenerateRFC4226Passwords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret)
        
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertEqual(hotp.generatePassword(for: Int64(i)), expected[i])
        }
    }
    
    // Test generating passwords for different counter / secret / hash algorithm / digits combinations.
    // Compare results with test data produced by the RFC4226 Java reference implementation.
    func testGenerateTestDataPasswords() {
        for (counter, secret, algorithm, digits, otp, _) in HOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: digits))
            
            XCTAssertEqual(hotp.generatePassword(for: Int64(counter)), otp)
        }
    }
    
    // MARK: Testing truncation offsets
    
    // Test generating passwords for different counter / secret / hash algorithm / digits combinations.
    // Compare results with test data produced by the RFC4226 Java reference implementation.
    // First test using explicit truncation offsets matching the recorded dynamic offsets in the test data.
    // Then test using shifted explicit offsets, with enough digits to generate different results.
    //
    func testTruncationOffsets() {
        for (counter, secret, algorithm, digits, otp, offset) in HOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: digits, offset: offset))

            XCTAssertEqual(hotp.generatePassword(for: Int64(counter)), otp)
        }
        for (counter, secret, algorithm, digits, otp, offset) in HOTPTestResources.referenceData where digits > 2 {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            let configuration = Configuration(algorithm: algorithm, digits: digits, offset: (offset + 1) % (algorithm.byteCount - 4))
            let hotp = HOTP(secret: secret, configuration: configuration)

            XCTAssertNotEqual(hotp.generatePassword(for: Int64(counter)), otp)
        }
    }
    
    // MARK: Testing validating RFC4226 reference passwords
    
    // Test validating wrong passwords for the RFC2446 reference counter / passwords.
    func testInvalidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret)

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]

        for i in 0 ... 9 {
            for j in 0 ... 9 where j != i {
                XCTAssertFalse(hotp.isValidPassword(expected[i], for: Int64(j)))
            }
        }
    }
    
    // Test validating the RFC2446 reference passwords.
    func testValidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret)

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]

        for i in 0 ... 9 {
            XCTAssertTrue(hotp.isValidPassword(expected[i], for: Int64(i)))
        }
    }
    
    // MARK: Testing validating RFC4226 reference passwords using a window
    
    // Test validating the RFC2446 reference passwords for counters outside a window of 2 of the actual counter.
    func testInvalidWindowPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret, configuration: .init(window: 2))

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]

        for i in 0 ... 9 {
            XCTAssertFalse(hotp.isValidPassword(expected[i], for: Int64(i - 3)))
            XCTAssertFalse(hotp.isValidPassword(expected[i], for: Int64(i + 3)))
        }
    }
    
    // Test validating the RFC2446 reference passwords for counters inside a window of 2 of the actual counter.
    func testValidWindowPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret, configuration: .init(window: 2))

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]

        for i in 0 ... 9 {
            for j in -2 ... 2 {
                XCTAssertTrue(hotp.isValidPassword(expected[i], for: Int64(i + j)))
            }
        }
    }
    
}


/**
 HOTP test suite.
 */
extension HOTPTests {
    
    static var allTests = [
        ("testByteCounts", testByteCounts),
        ("testDefaults", testDefaults),
        ("testNonDefaults", testNonDefaults),
        ("testInvalidDigits", testInvalidDigits),
        ("testValidDigits", testValidDigits),
        ("testInvalidOffset", testInvalidOffset),
        ("testValidOffset", testValidOffset),
        ("testInvalidWindow", testInvalidWindow),
        ("testValidWindow", testValidWindow),
        ("testDefaultServiceConfiguration", testDefaultServiceConfiguration),
        ("testGenerateRFC4226Passwords", testGenerateRFC4226Passwords),
        ("testGenerateTestDataPasswords", testGenerateTestDataPasswords),
        ("testTruncationOffsets", testTruncationOffsets),
        ("testInvalidPasswords", testInvalidPasswords),
        ("testValidPasswords", testValidPasswords),
        ("testInvalidWindowPasswords", testInvalidWindowPasswords),
        ("testValidWindowPasswords", testValidWindowPasswords),
    ]
    
}
