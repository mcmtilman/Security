//
//  TOTPTests.swift
//  Security
//
//  Created by Michel Tilman on 21/07/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import XCTest
@testable import Authentication

/**
 Tests generation and validation of TOTP passwords.
 */
class TOTPTests: XCTestCase {
    
    typealias Algorithm = HOTP.Algorithm
    typealias Configuration = TOTP.Configuration
    
    // MARK: Testing creating a TOTP configuration
    
    // Test creating a TOTP configuration with default values.
    func testDefaults() {
        let configuration = Configuration()
        
        XCTAssertEqual(configuration.period, 30)
    }
    
    // Test creating a TOTP configuration with non-default values.
    func testNonDefaults() {
        let configuration = Configuration(period: 10)
        
        XCTAssertEqual(configuration.period, 10)
    }
    
    // Test creating TOTP configurations with invalid period.
    func testInvalidPeriod() {
        for (given, expected) in [(0, 1), (121, 120)] {
            let configuration = Configuration(period: TimeInterval(given))
            
            XCTAssertEqual(configuration.period, TimeInterval(expected))
        }
    }
    
    // Test creating TOTP configurations with minimum and maximum valid periods.
    func testValidPeriod() {
        for (given, expected) in [(1, 1), (120, 120)] {
            let configuration = Configuration(period: TimeInterval(given))
            
            XCTAssertEqual(configuration.period, TimeInterval(expected))
        }
    }
    
    // MARK: Testing a TOTP service with default configuration
    
    // Test creating a TOTP service with default configuration.
    func testDefaultServiceConfiguration() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret)
        let totp = TOTP(hotp: hotp)

        XCTAssertEqual(totp.configuration.period, 30)
    }

    // MARK: Testing generating RFC6238 reference passwords
    
    // Test generating the RFC6238 reference passwords for different hash algorithm / secret / date combinations.
    // Compare results with the RFC6238 Java reference data.
    func testGenerateRFC6238Passwords() {
        for (algorithm, secret, date, _, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: HOTP.Configuration(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: TOTP.Configuration(period: 30))

            XCTAssertEqual(totp.generatePassword(for: Date(timeIntervalSince1970: TimeInterval(date))), otp)
        }
    }
    
    // MARK: Testing validating RFC6238 reference passwords
    
    // Test validating the RFC6238 reference passwords using dates skewed by 30 seconds.
    func testInvalidPasswords() {
        for (algorithm, secret, date, _, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: HOTP.Configuration(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: TOTP.Configuration(period: 30))

            XCTAssertFalse(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(date + 30))))
        }
    }
    
    // Test validating the RFC6238 reference passwords using correct dates.
    func testValidPasswords() {
        for (algorithm, secret, date, _, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: HOTP.Configuration(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: TOTP.Configuration(period: 30))

            XCTAssertTrue(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(date))))
        }
    }

}


/**
 TOTP test suite.
 */
extension TOTPTests {
    
    static var allTests = [
        ("testDefaults", testDefaults),
        ("testNonDefaults", testNonDefaults),
        ("testInvalidPeriod", testInvalidPeriod),
        ("testValidPeriod", testValidPeriod),
        ("testDefaultServiceConfiguration", testDefaultServiceConfiguration),
        ("testGenerateRFC6238Passwords", testGenerateRFC6238Passwords),
        ("testInvalidPasswords", testInvalidPasswords),
        ("testValidPasswords", testValidPasswords),
    ]
    
}
