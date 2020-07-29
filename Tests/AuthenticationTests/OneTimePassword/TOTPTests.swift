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
        for (period, expected) in [(0, 1), (121, 120)] {
            let configuration = Configuration(period: TimeInterval(period))
            
            XCTAssertEqual(configuration.period, TimeInterval(expected))
        }
    }
    
    // Test creating TOTP configurations with minimum and maximum valid periods.
    func testValidPeriod() {
        for (period, expected) in [(1, 1), (120, 120)] {
            let configuration = Configuration(period: TimeInterval(period))
            
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
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))

            XCTAssertEqual(totp.generatePassword(for: Date(timeIntervalSince1970: TimeInterval(seconds))), otp)
        }
    }
    
    // MARK: Testing validation of RFC6238 reference passwords using a zero window
    
    // Test validating the RFC6238 reference passwords using dates skewed by 30 seconds.
    func testInvalidPasswords() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))

            XCTAssertFalse(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(seconds + 30))))
        }
    }
    
    // Test validating the RFC6238 reference passwords using correct dates.
    func testValidPasswords() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))

            XCTAssertTrue(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(seconds))))
        }
    }

    // MARK: Testing skew of RFC6238 reference passwords using a zero window
    
    // Test the skew of RFC6238 reference passwords using dates outside the correct period.
    func testInvalidPasswordsSkew() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))

            XCTAssertNil(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds + 30)), password: otp))
        }
    }
    
    // Test the skew of RFC6238 reference passwords using correct dates.
    func testValidPasswordsSkew() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))

            XCTAssertEqual(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds)), password: otp), 0)
        }
    }

    // MARK: Testing validation of RFC6238 reference passwords using a non-zero window
    
    // Test validating the RFC6238 reference passwords for dates outside a window of 2 of the correct date.
    func testWindowInvalidPasswords() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData where seconds >= 90 {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8, window: 2))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))
            
            XCTAssertFalse(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(seconds - 90))))
            XCTAssertFalse(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(seconds + 90))))
        }
    }
    
    // Test validating the RFC6238 reference passwords for dates inside a window of 2 of the correct date.
    func testWindowValidPasswords() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData where seconds >= 90 {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8, window: 2))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))
            
            XCTAssertTrue(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(seconds - 60))))
            XCTAssertTrue(totp.isValidPassword(otp, for: Date(timeIntervalSince1970: TimeInterval(seconds + 60))))
        }
    }

    // MARK: Testing skew of RFC6238 reference passwords using a non-zero window
    
    // Test the skew of RFC6238 reference passwords for dates outside a window of 2 of the correct date.
    func testWindowInvalidPasswordsSkew() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData where seconds >= 90 {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8, window: 2))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))
            
            XCTAssertNil(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds - 90)), password: otp))
            XCTAssertNil(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds + 90)), password: otp))
        }
    }
    
    // Test the skew of RFC6238 reference passwords for dates inside a window of 2 of the correct date.
    func testWindowValidPasswordsSkew() {
        for (_, seconds, secret, algorithm, otp) in TOTPTestResources.referenceData where seconds >= 90 {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("nil secret") }
            let hotp = HOTP(secret: secret, configuration: .init(algorithm: algorithm, digits: 8, window: 2))
            let totp = TOTP(hotp: hotp, configuration: .init(period: 30))
            
            XCTAssertEqual(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds - 60)), password: otp), 2)
            XCTAssertEqual(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds + 60)), password: otp), -2)
        }
    }

    // MARK: Testing validation of RFC6238 reference passwords using different periods
    
    // Test validating RFC6238 reference passwords for different date / period combinations yielding a different counter.
    func testDatePeriodInvalidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret, configuration: .init(digits: 8))
        
        for (seconds, period) in [(59, 29), (59, 60)] {
            let totp = TOTP(hotp: hotp, configuration: .init(period: TimeInterval(period)))
            
            XCTAssertFalse(totp.isValidPassword("94287082", for: Date(timeIntervalSince1970: TimeInterval(seconds))))
        }
    }
    
    // Test validating RFC6238 reference passwords for different date / period combinations yielding the same counter.
    func testDatePeriodValidPasswords() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret, configuration: .init(digits: 8))
        
        for (seconds, period) in [(59, 30), (59, 59)] {
            let totp = TOTP(hotp: hotp, configuration: .init(period: TimeInterval(period)))
            
            XCTAssertTrue(totp.isValidPassword("94287082", for: Date(timeIntervalSince1970: TimeInterval(seconds))))
        }
    }
    
    // MARK: Testing skew of RFC6238 reference passwords using different periods
    
    // Test the skew of RFC6238 reference passwords for different date / period combinations yielding a different counter.
    func testDatePeriodInvalidPasswordsSkew() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret, configuration: .init(digits: 8))
        
        for (seconds, period) in [(59, 29), (59, 60)] {
            let totp = TOTP(hotp: hotp, configuration: .init(period: TimeInterval(period)))
            
            XCTAssertNil(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds)), password: "94287082"))
        }
    }
    
    // Test the skew of RFC6238 reference passwords for different date / period combinations yielding the same counter.
    func testDatePeriodValidPasswordsSkew() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret, configuration: .init(digits: 8))
        
        for (seconds, period) in [(59, 30), (59, 59)] {
            let totp = TOTP(hotp: hotp, configuration: .init(period: TimeInterval(period)))
            
            XCTAssertEqual(totp.skew(date: Date(timeIntervalSince1970: TimeInterval(seconds)), password: "94287082"), 0)
        }
    }
    
}
