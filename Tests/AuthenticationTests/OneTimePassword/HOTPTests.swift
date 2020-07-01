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
    
    // Test results for different counter / digits / hash algorithm / secret combinations.
    // Compare with data produced by the RFC4226 Java reference implementation.
    func testGenerateReferenceImplementationPasswords() {
        let algorithms = ["SHA1": HOTP.Algorithm.sha1, "SHA256": .sha256, "SHA384": .sha384, "SHA512": .sha512]
        
        for (counter, digits, hashName, secretName, otp) in referenceData {
            guard let algorithm = algorithms[hashName] else { return XCTFail("Unsupported algorithm") }
            guard let secret = secretName.data(using: .utf8) else { return XCTFail("Invalid secret") }
            guard let hotp = HOTP(secret: secret, algorithm: algorithm, digits: digits) else { return XCTFail("nil HOTP") }
            
            XCTAssertEqual(hotp.generatePassword(for: Int64(counter)), otp)
        }
    }
    
}


/**
 Function test suite.
 */
extension HOTPTests {
    
    static var allTests = [
        ("testDefaults", testDefaults),
        ("testNonDefaults", testNonDefaults),
        ("testInvalidDigits", testInvalidDigits),
        ("testValidDigits", testValidDigits),
        ("testGenerateRFC4226Passwords", testGenerateRFC4226Passwords),
        ("testGenerateReferenceImplementationPasswords", testGenerateReferenceImplementationPasswords)
    ]
    
}


// Test data
// One-time passwords generated by the Java reference implementation for multiple counter / digits / algorithm / secret combinations.
fileprivate let referenceData: [(counter: Int, digits: Int, algorithm: String, secret: String, otp: String)] = [
    (counter: 1, digits: 1, algorithm: "SHA1", secret: "12345", otp: "8"),
    (counter: 1, digits: 1, algorithm: "SHA1", secret: "1234567890", otp: "0"),
    (counter: 1, digits: 1, algorithm: "SHA1", secret: "12345678901234567890", otp: "2"),
    (counter: 1, digits: 1, algorithm: "SHA256", secret: "12345", otp: "1"),
    (counter: 1, digits: 1, algorithm: "SHA256", secret: "1234567890", otp: "8"),
    (counter: 1, digits: 1, algorithm: "SHA256", secret: "12345678901234567890", otp: "4"),
    (counter: 1, digits: 1, algorithm: "SHA384", secret: "12345", otp: "9"),
    (counter: 1, digits: 1, algorithm: "SHA384", secret: "1234567890", otp: "6"),
    (counter: 1, digits: 1, algorithm: "SHA384", secret: "12345678901234567890", otp: "5"),
    (counter: 1, digits: 1, algorithm: "SHA512", secret: "12345", otp: "2"),
    (counter: 1, digits: 1, algorithm: "SHA512", secret: "1234567890", otp: "7"),
    (counter: 1, digits: 1, algorithm: "SHA512", secret: "12345678901234567890", otp: "7"),
    (counter: 1, digits: 2, algorithm: "SHA1", secret: "12345", otp: "88"),
    (counter: 1, digits: 2, algorithm: "SHA1", secret: "1234567890", otp: "20"),
    (counter: 1, digits: 2, algorithm: "SHA1", secret: "12345678901234567890", otp: "82"),
    (counter: 1, digits: 2, algorithm: "SHA256", secret: "12345", otp: "41"),
    (counter: 1, digits: 2, algorithm: "SHA256", secret: "1234567890", otp: "28"),
    (counter: 1, digits: 2, algorithm: "SHA256", secret: "12345678901234567890", otp: "74"),
    (counter: 1, digits: 2, algorithm: "SHA384", secret: "12345", otp: "39"),
    (counter: 1, digits: 2, algorithm: "SHA384", secret: "1234567890", otp: "76"),
    (counter: 1, digits: 2, algorithm: "SHA384", secret: "12345678901234567890", otp: "75"),
    (counter: 1, digits: 2, algorithm: "SHA512", secret: "12345", otp: "52"),
    (counter: 1, digits: 2, algorithm: "SHA512", secret: "1234567890", otp: "87"),
    (counter: 1, digits: 2, algorithm: "SHA512", secret: "12345678901234567890", otp: "47"),
    (counter: 1, digits: 3, algorithm: "SHA1", secret: "12345", otp: "488"),
    (counter: 1, digits: 3, algorithm: "SHA1", secret: "1234567890", otp: "420"),
    (counter: 1, digits: 3, algorithm: "SHA1", secret: "12345678901234567890", otp: "082"),
    (counter: 1, digits: 3, algorithm: "SHA256", secret: "12345", otp: "141"),
    (counter: 1, digits: 3, algorithm: "SHA256", secret: "1234567890", otp: "928"),
    (counter: 1, digits: 3, algorithm: "SHA256", secret: "12345678901234567890", otp: "374"),
    (counter: 1, digits: 3, algorithm: "SHA384", secret: "12345", otp: "639"),
    (counter: 1, digits: 3, algorithm: "SHA384", secret: "1234567890", otp: "476"),
    (counter: 1, digits: 3, algorithm: "SHA384", secret: "12345678901234567890", otp: "675"),
    (counter: 1, digits: 3, algorithm: "SHA512", secret: "12345", otp: "252"),
    (counter: 1, digits: 3, algorithm: "SHA512", secret: "1234567890", otp: "887"),
    (counter: 1, digits: 3, algorithm: "SHA512", secret: "12345678901234567890", otp: "147"),
    (counter: 1, digits: 4, algorithm: "SHA1", secret: "12345", otp: "2488"),
    (counter: 1, digits: 4, algorithm: "SHA1", secret: "1234567890", otp: "3420"),
    (counter: 1, digits: 4, algorithm: "SHA1", secret: "12345678901234567890", otp: "7082"),
    (counter: 1, digits: 4, algorithm: "SHA256", secret: "12345", otp: "9141"),
    (counter: 1, digits: 4, algorithm: "SHA256", secret: "1234567890", otp: "4928"),
    (counter: 1, digits: 4, algorithm: "SHA256", secret: "12345678901234567890", otp: "7374"),
    (counter: 1, digits: 4, algorithm: "SHA384", secret: "12345", otp: "9639"),
    (counter: 1, digits: 4, algorithm: "SHA384", secret: "1234567890", otp: "0476"),
    (counter: 1, digits: 4, algorithm: "SHA384", secret: "12345678901234567890", otp: "0675"),
    (counter: 1, digits: 4, algorithm: "SHA512", secret: "12345", otp: "2252"),
    (counter: 1, digits: 4, algorithm: "SHA512", secret: "1234567890", otp: "8887"),
    (counter: 1, digits: 4, algorithm: "SHA512", secret: "12345678901234567890", otp: "2147"),
    (counter: 1, digits: 5, algorithm: "SHA1", secret: "12345", otp: "62488"),
    (counter: 1, digits: 5, algorithm: "SHA1", secret: "1234567890", otp: "63420"),
    (counter: 1, digits: 5, algorithm: "SHA1", secret: "12345678901234567890", otp: "87082"),
    (counter: 1, digits: 5, algorithm: "SHA256", secret: "12345", otp: "39141"),
    (counter: 1, digits: 5, algorithm: "SHA256", secret: "1234567890", otp: "84928"),
    (counter: 1, digits: 5, algorithm: "SHA256", secret: "12345678901234567890", otp: "47374"),
    (counter: 1, digits: 5, algorithm: "SHA384", secret: "12345", otp: "89639"),
    (counter: 1, digits: 5, algorithm: "SHA384", secret: "1234567890", otp: "60476"),
    (counter: 1, digits: 5, algorithm: "SHA384", secret: "12345678901234567890", otp: "80675"),
    (counter: 1, digits: 5, algorithm: "SHA512", secret: "12345", otp: "22252"),
    (counter: 1, digits: 5, algorithm: "SHA512", secret: "1234567890", otp: "48887"),
    (counter: 1, digits: 5, algorithm: "SHA512", secret: "12345678901234567890", otp: "42147"),
    (counter: 1, digits: 6, algorithm: "SHA1", secret: "12345", otp: "662488"),
    (counter: 1, digits: 6, algorithm: "SHA1", secret: "1234567890", otp: "263420"),
    (counter: 1, digits: 6, algorithm: "SHA1", secret: "12345678901234567890", otp: "287082"),
    (counter: 1, digits: 6, algorithm: "SHA256", secret: "12345", otp: "639141"),
    (counter: 1, digits: 6, algorithm: "SHA256", secret: "1234567890", otp: "884928"),
    (counter: 1, digits: 6, algorithm: "SHA256", secret: "12345678901234567890", otp: "247374"),
    (counter: 1, digits: 6, algorithm: "SHA384", secret: "12345", otp: "789639"),
    (counter: 1, digits: 6, algorithm: "SHA384", secret: "1234567890", otp: "560476"),
    (counter: 1, digits: 6, algorithm: "SHA384", secret: "12345678901234567890", otp: "080675"),
    (counter: 1, digits: 6, algorithm: "SHA512", secret: "12345", otp: "422252"),
    (counter: 1, digits: 6, algorithm: "SHA512", secret: "1234567890", otp: "848887"),
    (counter: 1, digits: 6, algorithm: "SHA512", secret: "12345678901234567890", otp: "342147"),
    (counter: 1, digits: 7, algorithm: "SHA1", secret: "12345", otp: "6662488"),
    (counter: 1, digits: 7, algorithm: "SHA1", secret: "1234567890", otp: "3263420"),
    (counter: 1, digits: 7, algorithm: "SHA1", secret: "12345678901234567890", otp: "4287082"),
    (counter: 1, digits: 7, algorithm: "SHA256", secret: "12345", otp: "1639141"),
    (counter: 1, digits: 7, algorithm: "SHA256", secret: "1234567890", otp: "0884928"),
    (counter: 1, digits: 7, algorithm: "SHA256", secret: "12345678901234567890", otp: "2247374"),
    (counter: 1, digits: 7, algorithm: "SHA384", secret: "12345", otp: "1789639"),
    (counter: 1, digits: 7, algorithm: "SHA384", secret: "1234567890", otp: "9560476"),
    (counter: 1, digits: 7, algorithm: "SHA384", secret: "12345678901234567890", otp: "6080675"),
    (counter: 1, digits: 7, algorithm: "SHA512", secret: "12345", otp: "6422252"),
    (counter: 1, digits: 7, algorithm: "SHA512", secret: "1234567890", otp: "9848887"),
    (counter: 1, digits: 7, algorithm: "SHA512", secret: "12345678901234567890", otp: "9342147"),
    (counter: 1, digits: 8, algorithm: "SHA1", secret: "12345", otp: "56662488"),
    (counter: 1, digits: 8, algorithm: "SHA1", secret: "1234567890", otp: "13263420"),
    (counter: 1, digits: 8, algorithm: "SHA1", secret: "12345678901234567890", otp: "94287082"),
    (counter: 1, digits: 8, algorithm: "SHA256", secret: "12345", otp: "51639141"),
    (counter: 1, digits: 8, algorithm: "SHA256", secret: "1234567890", otp: "80884928"),
    (counter: 1, digits: 8, algorithm: "SHA256", secret: "12345678901234567890", otp: "32247374"),
    (counter: 1, digits: 8, algorithm: "SHA384", secret: "12345", otp: "31789639"),
    (counter: 1, digits: 8, algorithm: "SHA384", secret: "1234567890", otp: "99560476"),
    (counter: 1, digits: 8, algorithm: "SHA384", secret: "12345678901234567890", otp: "46080675"),
    (counter: 1, digits: 8, algorithm: "SHA512", secret: "12345", otp: "96422252"),
    (counter: 1, digits: 8, algorithm: "SHA512", secret: "1234567890", otp: "79848887"),
    (counter: 1, digits: 8, algorithm: "SHA512", secret: "12345678901234567890", otp: "69342147"),
    (counter: 1000, digits: 1, algorithm: "SHA1", secret: "12345", otp: "5"),
    (counter: 1000, digits: 1, algorithm: "SHA1", secret: "1234567890", otp: "6"),
    (counter: 1000, digits: 1, algorithm: "SHA1", secret: "12345678901234567890", otp: "0"),
    (counter: 1000, digits: 1, algorithm: "SHA256", secret: "12345", otp: "0"),
    (counter: 1000, digits: 1, algorithm: "SHA256", secret: "1234567890", otp: "3"),
    (counter: 1000, digits: 1, algorithm: "SHA256", secret: "12345678901234567890", otp: "8"),
    (counter: 1000, digits: 1, algorithm: "SHA384", secret: "12345", otp: "7"),
    (counter: 1000, digits: 1, algorithm: "SHA384", secret: "1234567890", otp: "5"),
    (counter: 1000, digits: 1, algorithm: "SHA384", secret: "12345678901234567890", otp: "3"),
    (counter: 1000, digits: 1, algorithm: "SHA512", secret: "12345", otp: "0"),
    (counter: 1000, digits: 1, algorithm: "SHA512", secret: "1234567890", otp: "0"),
    (counter: 1000, digits: 1, algorithm: "SHA512", secret: "12345678901234567890", otp: "1"),
    (counter: 1000, digits: 2, algorithm: "SHA1", secret: "12345", otp: "75"),
    (counter: 1000, digits: 2, algorithm: "SHA1", secret: "1234567890", otp: "56"),
    (counter: 1000, digits: 2, algorithm: "SHA1", secret: "12345678901234567890", otp: "30"),
    (counter: 1000, digits: 2, algorithm: "SHA256", secret: "12345", otp: "00"),
    (counter: 1000, digits: 2, algorithm: "SHA256", secret: "1234567890", otp: "23"),
    (counter: 1000, digits: 2, algorithm: "SHA256", secret: "12345678901234567890", otp: "38"),
    (counter: 1000, digits: 2, algorithm: "SHA384", secret: "12345", otp: "67"),
    (counter: 1000, digits: 2, algorithm: "SHA384", secret: "1234567890", otp: "75"),
    (counter: 1000, digits: 2, algorithm: "SHA384", secret: "12345678901234567890", otp: "73"),
    (counter: 1000, digits: 2, algorithm: "SHA512", secret: "12345", otp: "70"),
    (counter: 1000, digits: 2, algorithm: "SHA512", secret: "1234567890", otp: "70"),
    (counter: 1000, digits: 2, algorithm: "SHA512", secret: "12345678901234567890", otp: "11"),
    (counter: 1000, digits: 3, algorithm: "SHA1", secret: "12345", otp: "475"),
    (counter: 1000, digits: 3, algorithm: "SHA1", secret: "1234567890", otp: "356"),
    (counter: 1000, digits: 3, algorithm: "SHA1", secret: "12345678901234567890", otp: "130"),
    (counter: 1000, digits: 3, algorithm: "SHA256", secret: "12345", otp: "400"),
    (counter: 1000, digits: 3, algorithm: "SHA256", secret: "1234567890", otp: "823"),
    (counter: 1000, digits: 3, algorithm: "SHA256", secret: "12345678901234567890", otp: "738"),
    (counter: 1000, digits: 3, algorithm: "SHA384", secret: "12345", otp: "867"),
    (counter: 1000, digits: 3, algorithm: "SHA384", secret: "1234567890", otp: "375"),
    (counter: 1000, digits: 3, algorithm: "SHA384", secret: "12345678901234567890", otp: "073"),
    (counter: 1000, digits: 3, algorithm: "SHA512", secret: "12345", otp: "870"),
    (counter: 1000, digits: 3, algorithm: "SHA512", secret: "1234567890", otp: "470"),
    (counter: 1000, digits: 3, algorithm: "SHA512", secret: "12345678901234567890", otp: "611"),
    (counter: 1000, digits: 4, algorithm: "SHA1", secret: "12345", otp: "9475"),
    (counter: 1000, digits: 4, algorithm: "SHA1", secret: "1234567890", otp: "3356"),
    (counter: 1000, digits: 4, algorithm: "SHA1", secret: "12345678901234567890", otp: "0130"),
    (counter: 1000, digits: 4, algorithm: "SHA256", secret: "12345", otp: "7400"),
    (counter: 1000, digits: 4, algorithm: "SHA256", secret: "1234567890", otp: "9823"),
    (counter: 1000, digits: 4, algorithm: "SHA256", secret: "12345678901234567890", otp: "9738"),
    (counter: 1000, digits: 4, algorithm: "SHA384", secret: "12345", otp: "5867"),
    (counter: 1000, digits: 4, algorithm: "SHA384", secret: "1234567890", otp: "2375"),
    (counter: 1000, digits: 4, algorithm: "SHA384", secret: "12345678901234567890", otp: "0073"),
    (counter: 1000, digits: 4, algorithm: "SHA512", secret: "12345", otp: "9870"),
    (counter: 1000, digits: 4, algorithm: "SHA512", secret: "1234567890", otp: "4470"),
    (counter: 1000, digits: 4, algorithm: "SHA512", secret: "12345678901234567890", otp: "6611"),
    (counter: 1000, digits: 5, algorithm: "SHA1", secret: "12345", otp: "69475"),
    (counter: 1000, digits: 5, algorithm: "SHA1", secret: "1234567890", otp: "93356"),
    (counter: 1000, digits: 5, algorithm: "SHA1", secret: "12345678901234567890", otp: "50130"),
    (counter: 1000, digits: 5, algorithm: "SHA256", secret: "12345", otp: "87400"),
    (counter: 1000, digits: 5, algorithm: "SHA256", secret: "1234567890", otp: "69823"),
    (counter: 1000, digits: 5, algorithm: "SHA256", secret: "12345678901234567890", otp: "59738"),
    (counter: 1000, digits: 5, algorithm: "SHA384", secret: "12345", otp: "75867"),
    (counter: 1000, digits: 5, algorithm: "SHA384", secret: "1234567890", otp: "92375"),
    (counter: 1000, digits: 5, algorithm: "SHA384", secret: "12345678901234567890", otp: "00073"),
    (counter: 1000, digits: 5, algorithm: "SHA512", secret: "12345", otp: "29870"),
    (counter: 1000, digits: 5, algorithm: "SHA512", secret: "1234567890", otp: "04470"),
    (counter: 1000, digits: 5, algorithm: "SHA512", secret: "12345678901234567890", otp: "96611"),
    (counter: 1000, digits: 6, algorithm: "SHA1", secret: "12345", otp: "069475"),
    (counter: 1000, digits: 6, algorithm: "SHA1", secret: "1234567890", otp: "593356"),
    (counter: 1000, digits: 6, algorithm: "SHA1", secret: "12345678901234567890", otp: "450130"),
    (counter: 1000, digits: 6, algorithm: "SHA256", secret: "12345", otp: "287400"),
    (counter: 1000, digits: 6, algorithm: "SHA256", secret: "1234567890", otp: "169823"),
    (counter: 1000, digits: 6, algorithm: "SHA256", secret: "12345678901234567890", otp: "959738"),
    (counter: 1000, digits: 6, algorithm: "SHA384", secret: "12345", otp: "975867"),
    (counter: 1000, digits: 6, algorithm: "SHA384", secret: "1234567890", otp: "992375"),
    (counter: 1000, digits: 6, algorithm: "SHA384", secret: "12345678901234567890", otp: "700073"),
    (counter: 1000, digits: 6, algorithm: "SHA512", secret: "12345", otp: "929870"),
    (counter: 1000, digits: 6, algorithm: "SHA512", secret: "1234567890", otp: "004470"),
    (counter: 1000, digits: 6, algorithm: "SHA512", secret: "12345678901234567890", otp: "796611"),
    (counter: 1000, digits: 7, algorithm: "SHA1", secret: "12345", otp: "3069475"),
    (counter: 1000, digits: 7, algorithm: "SHA1", secret: "1234567890", otp: "5593356"),
    (counter: 1000, digits: 7, algorithm: "SHA1", secret: "12345678901234567890", otp: "2450130"),
    (counter: 1000, digits: 7, algorithm: "SHA256", secret: "12345", otp: "0287400"),
    (counter: 1000, digits: 7, algorithm: "SHA256", secret: "1234567890", otp: "4169823"),
    (counter: 1000, digits: 7, algorithm: "SHA256", secret: "12345678901234567890", otp: "7959738"),
    (counter: 1000, digits: 7, algorithm: "SHA384", secret: "12345", otp: "1975867"),
    (counter: 1000, digits: 7, algorithm: "SHA384", secret: "1234567890", otp: "2992375"),
    (counter: 1000, digits: 7, algorithm: "SHA384", secret: "12345678901234567890", otp: "7700073"),
    (counter: 1000, digits: 7, algorithm: "SHA512", secret: "12345", otp: "3929870"),
    (counter: 1000, digits: 7, algorithm: "SHA512", secret: "1234567890", otp: "8004470"),
    (counter: 1000, digits: 7, algorithm: "SHA512", secret: "12345678901234567890", otp: "3796611"),
    (counter: 1000, digits: 8, algorithm: "SHA1", secret: "12345", otp: "13069475"),
    (counter: 1000, digits: 8, algorithm: "SHA1", secret: "1234567890", otp: "75593356"),
    (counter: 1000, digits: 8, algorithm: "SHA1", secret: "12345678901234567890", otp: "22450130"),
    (counter: 1000, digits: 8, algorithm: "SHA256", secret: "12345", otp: "80287400"),
    (counter: 1000, digits: 8, algorithm: "SHA256", secret: "1234567890", otp: "24169823"),
    (counter: 1000, digits: 8, algorithm: "SHA256", secret: "12345678901234567890", otp: "77959738"),
    (counter: 1000, digits: 8, algorithm: "SHA384", secret: "12345", otp: "01975867"),
    (counter: 1000, digits: 8, algorithm: "SHA384", secret: "1234567890", otp: "02992375"),
    (counter: 1000, digits: 8, algorithm: "SHA384", secret: "12345678901234567890", otp: "47700073"),
    (counter: 1000, digits: 8, algorithm: "SHA512", secret: "12345", otp: "03929870"),
    (counter: 1000, digits: 8, algorithm: "SHA512", secret: "1234567890", otp: "58004470"),
    (counter: 1000, digits: 8, algorithm: "SHA512", secret: "12345678901234567890", otp: "53796611"),
    (counter: 1000000, digits: 1, algorithm: "SHA1", secret: "12345", otp: "0"),
    (counter: 1000000, digits: 1, algorithm: "SHA1", secret: "1234567890", otp: "9"),
    (counter: 1000000, digits: 1, algorithm: "SHA1", secret: "12345678901234567890", otp: "0"),
    (counter: 1000000, digits: 1, algorithm: "SHA256", secret: "12345", otp: "1"),
    (counter: 1000000, digits: 1, algorithm: "SHA256", secret: "1234567890", otp: "6"),
    (counter: 1000000, digits: 1, algorithm: "SHA256", secret: "12345678901234567890", otp: "8"),
    (counter: 1000000, digits: 1, algorithm: "SHA384", secret: "12345", otp: "7"),
    (counter: 1000000, digits: 1, algorithm: "SHA384", secret: "1234567890", otp: "0"),
    (counter: 1000000, digits: 1, algorithm: "SHA384", secret: "12345678901234567890", otp: "7"),
    (counter: 1000000, digits: 1, algorithm: "SHA512", secret: "12345", otp: "1"),
    (counter: 1000000, digits: 1, algorithm: "SHA512", secret: "1234567890", otp: "3"),
    (counter: 1000000, digits: 1, algorithm: "SHA512", secret: "12345678901234567890", otp: "4"),
    (counter: 1000000, digits: 2, algorithm: "SHA1", secret: "12345", otp: "60"),
    (counter: 1000000, digits: 2, algorithm: "SHA1", secret: "1234567890", otp: "29"),
    (counter: 1000000, digits: 2, algorithm: "SHA1", secret: "12345678901234567890", otp: "80"),
    (counter: 1000000, digits: 2, algorithm: "SHA256", secret: "12345", otp: "31"),
    (counter: 1000000, digits: 2, algorithm: "SHA256", secret: "1234567890", otp: "66"),
    (counter: 1000000, digits: 2, algorithm: "SHA256", secret: "12345678901234567890", otp: "18"),
    (counter: 1000000, digits: 2, algorithm: "SHA384", secret: "12345", otp: "47"),
    (counter: 1000000, digits: 2, algorithm: "SHA384", secret: "1234567890", otp: "50"),
    (counter: 1000000, digits: 2, algorithm: "SHA384", secret: "12345678901234567890", otp: "17"),
    (counter: 1000000, digits: 2, algorithm: "SHA512", secret: "12345", otp: "11"),
    (counter: 1000000, digits: 2, algorithm: "SHA512", secret: "1234567890", otp: "73"),
    (counter: 1000000, digits: 2, algorithm: "SHA512", secret: "12345678901234567890", otp: "94"),
    (counter: 1000000, digits: 3, algorithm: "SHA1", secret: "12345", otp: "260"),
    (counter: 1000000, digits: 3, algorithm: "SHA1", secret: "1234567890", otp: "629"),
    (counter: 1000000, digits: 3, algorithm: "SHA1", secret: "12345678901234567890", otp: "580"),
    (counter: 1000000, digits: 3, algorithm: "SHA256", secret: "12345", otp: "931"),
    (counter: 1000000, digits: 3, algorithm: "SHA256", secret: "1234567890", otp: "266"),
    (counter: 1000000, digits: 3, algorithm: "SHA256", secret: "12345678901234567890", otp: "718"),
    (counter: 1000000, digits: 3, algorithm: "SHA384", secret: "12345", otp: "847"),
    (counter: 1000000, digits: 3, algorithm: "SHA384", secret: "1234567890", otp: "350"),
    (counter: 1000000, digits: 3, algorithm: "SHA384", secret: "12345678901234567890", otp: "117"),
    (counter: 1000000, digits: 3, algorithm: "SHA512", secret: "12345", otp: "111"),
    (counter: 1000000, digits: 3, algorithm: "SHA512", secret: "1234567890", otp: "173"),
    (counter: 1000000, digits: 3, algorithm: "SHA512", secret: "12345678901234567890", otp: "994"),
    (counter: 1000000, digits: 4, algorithm: "SHA1", secret: "12345", otp: "7260"),
    (counter: 1000000, digits: 4, algorithm: "SHA1", secret: "1234567890", otp: "5629"),
    (counter: 1000000, digits: 4, algorithm: "SHA1", secret: "12345678901234567890", otp: "5580"),
    (counter: 1000000, digits: 4, algorithm: "SHA256", secret: "12345", otp: "1931"),
    (counter: 1000000, digits: 4, algorithm: "SHA256", secret: "1234567890", otp: "8266"),
    (counter: 1000000, digits: 4, algorithm: "SHA256", secret: "12345678901234567890", otp: "4718"),
    (counter: 1000000, digits: 4, algorithm: "SHA384", secret: "12345", otp: "6847"),
    (counter: 1000000, digits: 4, algorithm: "SHA384", secret: "1234567890", otp: "3350"),
    (counter: 1000000, digits: 4, algorithm: "SHA384", secret: "12345678901234567890", otp: "6117"),
    (counter: 1000000, digits: 4, algorithm: "SHA512", secret: "12345", otp: "1111"),
    (counter: 1000000, digits: 4, algorithm: "SHA512", secret: "1234567890", otp: "6173"),
    (counter: 1000000, digits: 4, algorithm: "SHA512", secret: "12345678901234567890", otp: "0994"),
    (counter: 1000000, digits: 5, algorithm: "SHA1", secret: "12345", otp: "67260"),
    (counter: 1000000, digits: 5, algorithm: "SHA1", secret: "1234567890", otp: "45629"),
    (counter: 1000000, digits: 5, algorithm: "SHA1", secret: "12345678901234567890", otp: "65580"),
    (counter: 1000000, digits: 5, algorithm: "SHA256", secret: "12345", otp: "51931"),
    (counter: 1000000, digits: 5, algorithm: "SHA256", secret: "1234567890", otp: "28266"),
    (counter: 1000000, digits: 5, algorithm: "SHA256", secret: "12345678901234567890", otp: "34718"),
    (counter: 1000000, digits: 5, algorithm: "SHA384", secret: "12345", otp: "16847"),
    (counter: 1000000, digits: 5, algorithm: "SHA384", secret: "1234567890", otp: "73350"),
    (counter: 1000000, digits: 5, algorithm: "SHA384", secret: "12345678901234567890", otp: "76117"),
    (counter: 1000000, digits: 5, algorithm: "SHA512", secret: "12345", otp: "71111"),
    (counter: 1000000, digits: 5, algorithm: "SHA512", secret: "1234567890", otp: "96173"),
    (counter: 1000000, digits: 5, algorithm: "SHA512", secret: "12345678901234567890", otp: "70994"),
    (counter: 1000000, digits: 6, algorithm: "SHA1", secret: "12345", otp: "167260"),
    (counter: 1000000, digits: 6, algorithm: "SHA1", secret: "1234567890", otp: "145629"),
    (counter: 1000000, digits: 6, algorithm: "SHA1", secret: "12345678901234567890", otp: "665580"),
    (counter: 1000000, digits: 6, algorithm: "SHA256", secret: "12345", otp: "351931"),
    (counter: 1000000, digits: 6, algorithm: "SHA256", secret: "1234567890", otp: "228266"),
    (counter: 1000000, digits: 6, algorithm: "SHA256", secret: "12345678901234567890", otp: "434718"),
    (counter: 1000000, digits: 6, algorithm: "SHA384", secret: "12345", otp: "016847"),
    (counter: 1000000, digits: 6, algorithm: "SHA384", secret: "1234567890", otp: "173350"),
    (counter: 1000000, digits: 6, algorithm: "SHA384", secret: "12345678901234567890", otp: "676117"),
    (counter: 1000000, digits: 6, algorithm: "SHA512", secret: "12345", otp: "971111"),
    (counter: 1000000, digits: 6, algorithm: "SHA512", secret: "1234567890", otp: "096173"),
    (counter: 1000000, digits: 6, algorithm: "SHA512", secret: "12345678901234567890", otp: "070994"),
    (counter: 1000000, digits: 7, algorithm: "SHA1", secret: "12345", otp: "3167260"),
    (counter: 1000000, digits: 7, algorithm: "SHA1", secret: "1234567890", otp: "7145629"),
    (counter: 1000000, digits: 7, algorithm: "SHA1", secret: "12345678901234567890", otp: "3665580"),
    (counter: 1000000, digits: 7, algorithm: "SHA256", secret: "12345", otp: "2351931"),
    (counter: 1000000, digits: 7, algorithm: "SHA256", secret: "1234567890", otp: "8228266"),
    (counter: 1000000, digits: 7, algorithm: "SHA256", secret: "12345678901234567890", otp: "0434718"),
    (counter: 1000000, digits: 7, algorithm: "SHA384", secret: "12345", otp: "5016847"),
    (counter: 1000000, digits: 7, algorithm: "SHA384", secret: "1234567890", otp: "8173350"),
    (counter: 1000000, digits: 7, algorithm: "SHA384", secret: "12345678901234567890", otp: "4676117"),
    (counter: 1000000, digits: 7, algorithm: "SHA512", secret: "12345", otp: "0971111"),
    (counter: 1000000, digits: 7, algorithm: "SHA512", secret: "1234567890", otp: "6096173"),
    (counter: 1000000, digits: 7, algorithm: "SHA512", secret: "12345678901234567890", otp: "7070994"),
    (counter: 1000000, digits: 8, algorithm: "SHA1", secret: "12345", otp: "23167260"),
    (counter: 1000000, digits: 8, algorithm: "SHA1", secret: "1234567890", otp: "17145629"),
    (counter: 1000000, digits: 8, algorithm: "SHA1", secret: "12345678901234567890", otp: "03665580"),
    (counter: 1000000, digits: 8, algorithm: "SHA256", secret: "12345", otp: "02351931"),
    (counter: 1000000, digits: 8, algorithm: "SHA256", secret: "1234567890", otp: "68228266"),
    (counter: 1000000, digits: 8, algorithm: "SHA256", secret: "12345678901234567890", otp: "10434718"),
    (counter: 1000000, digits: 8, algorithm: "SHA384", secret: "12345", otp: "15016847"),
    (counter: 1000000, digits: 8, algorithm: "SHA384", secret: "1234567890", otp: "78173350"),
    (counter: 1000000, digits: 8, algorithm: "SHA384", secret: "12345678901234567890", otp: "24676117"),
    (counter: 1000000, digits: 8, algorithm: "SHA512", secret: "12345", otp: "40971111"),
    (counter: 1000000, digits: 8, algorithm: "SHA512", secret: "1234567890", otp: "26096173"),
    (counter: 1000000, digits: 8, algorithm: "SHA512", secret: "12345678901234567890", otp: "57070994"),
    (counter: 1000000000, digits: 1, algorithm: "SHA1", secret: "12345", otp: "6"),
    (counter: 1000000000, digits: 1, algorithm: "SHA1", secret: "1234567890", otp: "4"),
    (counter: 1000000000, digits: 1, algorithm: "SHA1", secret: "12345678901234567890", otp: "6"),
    (counter: 1000000000, digits: 1, algorithm: "SHA256", secret: "12345", otp: "7"),
    (counter: 1000000000, digits: 1, algorithm: "SHA256", secret: "1234567890", otp: "0"),
    (counter: 1000000000, digits: 1, algorithm: "SHA256", secret: "12345678901234567890", otp: "0"),
    (counter: 1000000000, digits: 1, algorithm: "SHA384", secret: "12345", otp: "0"),
    (counter: 1000000000, digits: 1, algorithm: "SHA384", secret: "1234567890", otp: "2"),
    (counter: 1000000000, digits: 1, algorithm: "SHA384", secret: "12345678901234567890", otp: "8"),
    (counter: 1000000000, digits: 1, algorithm: "SHA512", secret: "12345", otp: "2"),
    (counter: 1000000000, digits: 1, algorithm: "SHA512", secret: "1234567890", otp: "1"),
    (counter: 1000000000, digits: 1, algorithm: "SHA512", secret: "12345678901234567890", otp: "3"),
    (counter: 1000000000, digits: 2, algorithm: "SHA1", secret: "12345", otp: "76"),
    (counter: 1000000000, digits: 2, algorithm: "SHA1", secret: "1234567890", otp: "04"),
    (counter: 1000000000, digits: 2, algorithm: "SHA1", secret: "12345678901234567890", otp: "86"),
    (counter: 1000000000, digits: 2, algorithm: "SHA256", secret: "12345", otp: "47"),
    (counter: 1000000000, digits: 2, algorithm: "SHA256", secret: "1234567890", otp: "40"),
    (counter: 1000000000, digits: 2, algorithm: "SHA256", secret: "12345678901234567890", otp: "00"),
    (counter: 1000000000, digits: 2, algorithm: "SHA384", secret: "12345", otp: "50"),
    (counter: 1000000000, digits: 2, algorithm: "SHA384", secret: "1234567890", otp: "72"),
    (counter: 1000000000, digits: 2, algorithm: "SHA384", secret: "12345678901234567890", otp: "28"),
    (counter: 1000000000, digits: 2, algorithm: "SHA512", secret: "12345", otp: "02"),
    (counter: 1000000000, digits: 2, algorithm: "SHA512", secret: "1234567890", otp: "31"),
    (counter: 1000000000, digits: 2, algorithm: "SHA512", secret: "12345678901234567890", otp: "73"),
    (counter: 1000000000, digits: 3, algorithm: "SHA1", secret: "12345", otp: "076"),
    (counter: 1000000000, digits: 3, algorithm: "SHA1", secret: "1234567890", otp: "404"),
    (counter: 1000000000, digits: 3, algorithm: "SHA1", secret: "12345678901234567890", otp: "286"),
    (counter: 1000000000, digits: 3, algorithm: "SHA256", secret: "12345", otp: "647"),
    (counter: 1000000000, digits: 3, algorithm: "SHA256", secret: "1234567890", otp: "140"),
    (counter: 1000000000, digits: 3, algorithm: "SHA256", secret: "12345678901234567890", otp: "500"),
    (counter: 1000000000, digits: 3, algorithm: "SHA384", secret: "12345", otp: "450"),
    (counter: 1000000000, digits: 3, algorithm: "SHA384", secret: "1234567890", otp: "772"),
    (counter: 1000000000, digits: 3, algorithm: "SHA384", secret: "12345678901234567890", otp: "328"),
    (counter: 1000000000, digits: 3, algorithm: "SHA512", secret: "12345", otp: "702"),
    (counter: 1000000000, digits: 3, algorithm: "SHA512", secret: "1234567890", otp: "031"),
    (counter: 1000000000, digits: 3, algorithm: "SHA512", secret: "12345678901234567890", otp: "873"),
    (counter: 1000000000, digits: 4, algorithm: "SHA1", secret: "12345", otp: "0076"),
    (counter: 1000000000, digits: 4, algorithm: "SHA1", secret: "1234567890", otp: "1404"),
    (counter: 1000000000, digits: 4, algorithm: "SHA1", secret: "12345678901234567890", otp: "2286"),
    (counter: 1000000000, digits: 4, algorithm: "SHA256", secret: "12345", otp: "0647"),
    (counter: 1000000000, digits: 4, algorithm: "SHA256", secret: "1234567890", otp: "8140"),
    (counter: 1000000000, digits: 4, algorithm: "SHA256", secret: "12345678901234567890", otp: "2500"),
    (counter: 1000000000, digits: 4, algorithm: "SHA384", secret: "12345", otp: "4450"),
    (counter: 1000000000, digits: 4, algorithm: "SHA384", secret: "1234567890", otp: "3772"),
    (counter: 1000000000, digits: 4, algorithm: "SHA384", secret: "12345678901234567890", otp: "7328"),
    (counter: 1000000000, digits: 4, algorithm: "SHA512", secret: "12345", otp: "4702"),
    (counter: 1000000000, digits: 4, algorithm: "SHA512", secret: "1234567890", otp: "1031"),
    (counter: 1000000000, digits: 4, algorithm: "SHA512", secret: "12345678901234567890", otp: "8873"),
    (counter: 1000000000, digits: 5, algorithm: "SHA1", secret: "12345", otp: "00076"),
    (counter: 1000000000, digits: 5, algorithm: "SHA1", secret: "1234567890", otp: "51404"),
    (counter: 1000000000, digits: 5, algorithm: "SHA1", secret: "12345678901234567890", otp: "02286"),
    (counter: 1000000000, digits: 5, algorithm: "SHA256", secret: "12345", otp: "70647"),
    (counter: 1000000000, digits: 5, algorithm: "SHA256", secret: "1234567890", otp: "38140"),
    (counter: 1000000000, digits: 5, algorithm: "SHA256", secret: "12345678901234567890", otp: "92500"),
    (counter: 1000000000, digits: 5, algorithm: "SHA384", secret: "12345", otp: "54450"),
    (counter: 1000000000, digits: 5, algorithm: "SHA384", secret: "1234567890", otp: "93772"),
    (counter: 1000000000, digits: 5, algorithm: "SHA384", secret: "12345678901234567890", otp: "47328"),
    (counter: 1000000000, digits: 5, algorithm: "SHA512", secret: "12345", otp: "54702"),
    (counter: 1000000000, digits: 5, algorithm: "SHA512", secret: "1234567890", otp: "01031"),
    (counter: 1000000000, digits: 5, algorithm: "SHA512", secret: "12345678901234567890", otp: "58873"),
    (counter: 1000000000, digits: 6, algorithm: "SHA1", secret: "12345", otp: "300076"),
    (counter: 1000000000, digits: 6, algorithm: "SHA1", secret: "1234567890", otp: "851404"),
    (counter: 1000000000, digits: 6, algorithm: "SHA1", secret: "12345678901234567890", otp: "602286"),
    (counter: 1000000000, digits: 6, algorithm: "SHA256", secret: "12345", otp: "570647"),
    (counter: 1000000000, digits: 6, algorithm: "SHA256", secret: "1234567890", otp: "038140"),
    (counter: 1000000000, digits: 6, algorithm: "SHA256", secret: "12345678901234567890", otp: "992500"),
    (counter: 1000000000, digits: 6, algorithm: "SHA384", secret: "12345", otp: "454450"),
    (counter: 1000000000, digits: 6, algorithm: "SHA384", secret: "1234567890", otp: "893772"),
    (counter: 1000000000, digits: 6, algorithm: "SHA384", secret: "12345678901234567890", otp: "547328"),
    (counter: 1000000000, digits: 6, algorithm: "SHA512", secret: "12345", otp: "054702"),
    (counter: 1000000000, digits: 6, algorithm: "SHA512", secret: "1234567890", otp: "301031"),
    (counter: 1000000000, digits: 6, algorithm: "SHA512", secret: "12345678901234567890", otp: "658873"),
    (counter: 1000000000, digits: 7, algorithm: "SHA1", secret: "12345", otp: "4300076"),
    (counter: 1000000000, digits: 7, algorithm: "SHA1", secret: "1234567890", otp: "7851404"),
    (counter: 1000000000, digits: 7, algorithm: "SHA1", secret: "12345678901234567890", otp: "8602286"),
    (counter: 1000000000, digits: 7, algorithm: "SHA256", secret: "12345", otp: "3570647"),
    (counter: 1000000000, digits: 7, algorithm: "SHA256", secret: "1234567890", otp: "6038140"),
    (counter: 1000000000, digits: 7, algorithm: "SHA256", secret: "12345678901234567890", otp: "4992500"),
    (counter: 1000000000, digits: 7, algorithm: "SHA384", secret: "12345", otp: "2454450"),
    (counter: 1000000000, digits: 7, algorithm: "SHA384", secret: "1234567890", otp: "2893772"),
    (counter: 1000000000, digits: 7, algorithm: "SHA384", secret: "12345678901234567890", otp: "0547328"),
    (counter: 1000000000, digits: 7, algorithm: "SHA512", secret: "12345", otp: "8054702"),
    (counter: 1000000000, digits: 7, algorithm: "SHA512", secret: "1234567890", otp: "5301031"),
    (counter: 1000000000, digits: 7, algorithm: "SHA512", secret: "12345678901234567890", otp: "2658873"),
    (counter: 1000000000, digits: 8, algorithm: "SHA1", secret: "12345", otp: "54300076"),
    (counter: 1000000000, digits: 8, algorithm: "SHA1", secret: "1234567890", otp: "37851404"),
    (counter: 1000000000, digits: 8, algorithm: "SHA1", secret: "12345678901234567890", otp: "78602286"),
    (counter: 1000000000, digits: 8, algorithm: "SHA256", secret: "12345", otp: "33570647"),
    (counter: 1000000000, digits: 8, algorithm: "SHA256", secret: "1234567890", otp: "76038140"),
    (counter: 1000000000, digits: 8, algorithm: "SHA256", secret: "12345678901234567890", otp: "44992500"),
    (counter: 1000000000, digits: 8, algorithm: "SHA384", secret: "12345", otp: "32454450"),
    (counter: 1000000000, digits: 8, algorithm: "SHA384", secret: "1234567890", otp: "32893772"),
    (counter: 1000000000, digits: 8, algorithm: "SHA384", secret: "12345678901234567890", otp: "70547328"),
    (counter: 1000000000, digits: 8, algorithm: "SHA512", secret: "12345", otp: "18054702"),
    (counter: 1000000000, digits: 8, algorithm: "SHA512", secret: "1234567890", otp: "25301031"),
    (counter: 1000000000, digits: 8, algorithm: "SHA512", secret: "12345678901234567890", otp: "12658873"),
]
