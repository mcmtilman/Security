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
    typealias ConfigurationError = HOTP.ConfigurationError
    
    // MARK: Testing algorithm
    
    // Test byte counts of the various algorithms.
    func testByteCounts() {
        XCTAssertEqual(Algorithm.sha1.byteCount, 20)
        XCTAssertEqual(Algorithm.sha256.byteCount, 32)
        XCTAssertEqual(Algorithm.sha384.byteCount, 48)
        XCTAssertEqual(Algorithm.sha512.byteCount, 64)
    }

    // MARK: Testing creating a HOTP service
    
    // Test creating a HOTP service with default values.
    func testDefaults() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = try? HOTP(secret: secret) else { return XCTFail("nil HOTP") }
        
        XCTAssertEqual(hotp.algorithm, .sha1)
        XCTAssertEqual(hotp.digits, 6)
        XCTAssertNil(hotp.offset)
        XCTAssertNil(hotp.window)
    }
    
    // Test creating a HOTP service with non-default values.
    func testNonDefaults() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = try? HOTP(secret: secret, algorithm: .sha256, digits: 8, offset: 5, window: 2) else { return XCTFail("nil HOTP") }
        
        XCTAssertEqual(hotp.algorithm, .sha256)
        XCTAssertEqual(hotp.digits, 8)
        XCTAssertEqual(hotp.offset, 5)
        XCTAssertEqual(hotp.window, 2)
    }
    
    // Test creating HOTP services with invalid digits.
    func testInvalidDigits() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        
        for digits in [0, 10] {
            XCTAssertThrowsError(try HOTP(secret: secret, digits: digits), "digits error expected") { error in
                XCTAssertEqual(error as? ConfigurationError, .digits)
            }
        }
    }
    
    // Test creating HOTP services with minimum and maximum valid digits.
    func testValidDigits() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        
        for digits in [1, 9] {
            XCTAssertNoThrow(try HOTP(secret: secret, digits: digits))
        }
    }
    
    // Test creating HOTP services with invalid offset.
    func testInvalidOffset() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }

        let offsets = [
            (Algorithm.sha1, -1), (.sha1, 16),
            (.sha256, -1), (.sha256, 28),
            (.sha384, -1), (.sha384, 44),
            (.sha512, -1), (.sha512, 60)
        ]
        
        for (algorithm, offset) in offsets {
            XCTAssertThrowsError(try HOTP(secret: secret, algorithm: algorithm, offset: offset), "offset error expected") { error in
                XCTAssertEqual(error as? ConfigurationError, .offset)
            }
        }
    }
    
    // Test creating HOTP services with minimum and maximum valid offset.
    func testValidOffset() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        
        let offsets = [
            (Algorithm.sha1, 0), (.sha1, 15),
            (.sha256, 0), (.sha256, 27),
            (.sha384, 0), (.sha384, 43),
            (.sha512, 0), (.sha512, 59)
        ]
        
        for (algorithm, offset) in offsets {
            XCTAssertNoThrow(try HOTP(secret: secret, algorithm: algorithm, offset: offset))
        }
    }
    
    // Test creating HOTP services with invalid window.
    func testInvalidWindow() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        
        for window in [0, 6] {
            XCTAssertThrowsError(try HOTP(secret: secret, window: window), "window error expected") { error in
                XCTAssertEqual(error as? ConfigurationError, .window)
            }
        }
    }
    
    // Test creating HOTP services with minimum and maximum valid window.
    func testValidWindow() {
        guard let secret = "123456".data(using: .utf8) else { return XCTFail("nil secret") }
        
        for window in [1, 5] {
            XCTAssertNoThrow(try HOTP(secret: secret, window: window))
        }
    }
    
    // MARK: Testing generating RFC 4226 reference passwords
    
    // Test generating SHA1-based passwords for counters 0 through 9, truncating to 6 digits and using the secret listed in the RFC.
    func testGenerateRFC4226Passwords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = try? HOTP(secret: secret) else { return XCTFail("nil HOTP") }
        
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertEqual(hotp.generatePassword(for: Int64(i)), expected[i])
        }
    }
    
    // Test generating passwords for different counter / secret / hash algorithm / digits combinations.
    // Compare results with test data produced by the RFC4226 Java reference implementation.
    func testGenerateTestDataPasswords() {
        let algorithms = ["SHA1": HOTP.Algorithm.sha1, "SHA256": .sha256, "SHA384": .sha384, "SHA512": .sha512]
        
        for (counter, secret, algorithm, digits, otp, _) in HOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            guard let algorithm = algorithms[algorithm] else { return XCTFail("Unsupported algorithm") }
            guard let hotp = try? HOTP(secret: secret, algorithm: algorithm, digits: digits) else { return XCTFail("nil HOTP") }
            
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
        let algorithms = ["SHA1": HOTP.Algorithm.sha1, "SHA256": .sha256, "SHA384": .sha384, "SHA512": .sha512]
        
        for (counter, secret, algorithm, digits, otp, offset) in HOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            guard let algorithm = algorithms[algorithm] else { return XCTFail("Unsupported algorithm") }
            guard let hotp = try? HOTP(secret: secret, algorithm: algorithm, digits: digits, offset: offset) else { return XCTFail("nil HOTP") }

            XCTAssertEqual(hotp.generatePassword(for: Int64(counter)), otp)
        }
        for (counter, secret, algorithm, digits, otp, offset) in HOTPTestResources.referenceData where digits > 2 {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            guard let algorithm = algorithms[algorithm] else { return XCTFail("Unsupported algorithm") }
            guard let hotp = try? HOTP(secret: secret, algorithm: algorithm, digits: digits, offset: (offset + 1) % (algorithm.byteCount - 4)) else { return XCTFail("nil HOTP") }

            XCTAssertNotEqual(hotp.generatePassword(for: Int64(counter)), otp)
        }
    }
    
    // MARK: Testing validating RFC 4226 reference passwords
    
    // Test validating wrong passwords for the RFC2446 reference counter / passwords.
    func testInvalidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = try? HOTP(secret: secret) else { return XCTFail("nil HOTP") }
        
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
        guard let hotp = try? HOTP(secret: secret) else { return XCTFail("nil HOTP") }
        
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertTrue(hotp.isValidPassword(expected[i], for: Int64(i)))
        }
    }
    
    // MARK: Testing validating RFC 4226 reference passwords using a window
    
    // Test validating the RFC2446 reference passwords for counters outside a window of 2 of the actual counter.
    func testInvalidWindowPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = try? HOTP(secret: secret, window: 2) else { return XCTFail("nil HOTP") }

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertFalse(hotp.isValidPassword(expected[i], for: Int64(i - 3)))
            XCTAssertFalse(hotp.isValidPassword(expected[i], for: Int64(i + 3)))
        }
    }
    
    // Test validating the RFC2446 reference passwords for counters inside a window of 2 of the actual counter.
    func testValidWindowPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        guard let hotp = try? HOTP(secret: secret, window: 2) else { return XCTFail("nil HOTP") }

        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

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
        ("testGenerateRFC4226Passwords", testGenerateRFC4226Passwords),
        ("testGenerateTestDataPasswords", testGenerateTestDataPasswords),
        ("testTruncationOffsets", testTruncationOffsets),
        ("testInvalidPasswords", testInvalidPasswords),
        ("testValidPasswords", testValidPasswords),
        ("testInvalidWindowPasswords", testInvalidWindowPasswords),
        ("testValidWindowPasswords", testValidWindowPasswords),
    ]
    
}
