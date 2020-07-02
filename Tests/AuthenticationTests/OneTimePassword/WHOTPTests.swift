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
        
        for (counter, secret, algorithm, digits, otp) in testData {
            guard let secret = secret.data(using: .utf8) else { return XCTFail("Invalid secret") }
            guard let algorithm = algorithms[algorithm] else { return XCTFail("Unsupported algorithm") }
            guard let hotp = HOTP(secret: secret, algorithm: algorithm, digits: digits) else { return XCTFail("nil HOTP") }
            guard let whotp = WHOTP(hotp: hotp) else { return XCTFail("nil WHOTP") }

            XCTAssertEqual(whotp.generatePassword(for: Int64(counter)), otp)
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
        ("testGenerateTestDataPasswords", testGenerateTestDataPasswords)
    ]
    
}


// Test data
// One-time passwords generated by the Java reference implementation for multiple counter / secret / algorithm / digits combinations.
fileprivate let testData: [(counter: Int, secret: String, algorithm: String, digits: Int, otp: String)] = [
    (1, "123456", "SHA1", 1, "5"),
    (1, "123456", "SHA1", 2, "35"),
    (1, "123456", "SHA1", 3, "335"),
    (1, "123456", "SHA1", 4, "0335"),
    (1, "123456", "SHA1", 5, "40335"),
    (1, "123456", "SHA1", 6, "340335"),
    (1, "123456", "SHA1", 7, "9340335"),
    (1, "123456", "SHA1", 8, "69340335"),
    (1, "123456", "SHA256", 1, "4"),
    (1, "123456", "SHA256", 2, "64"),
    (1, "123456", "SHA256", 3, "264"),
    (1, "123456", "SHA256", 4, "2264"),
    (1, "123456", "SHA256", 5, "52264"),
    (1, "123456", "SHA256", 6, "552264"),
    (1, "123456", "SHA256", 7, "7552264"),
    (1, "123456", "SHA256", 8, "17552264"),
    (1, "123456", "SHA384", 1, "2"),
    (1, "123456", "SHA384", 2, "92"),
    (1, "123456", "SHA384", 3, "592"),
    (1, "123456", "SHA384", 4, "3592"),
    (1, "123456", "SHA384", 5, "43592"),
    (1, "123456", "SHA384", 6, "843592"),
    (1, "123456", "SHA384", 7, "8843592"),
    (1, "123456", "SHA384", 8, "98843592"),
    (1, "123456", "SHA512", 1, "2"),
    (1, "123456", "SHA512", 2, "02"),
    (1, "123456", "SHA512", 3, "802"),
    (1, "123456", "SHA512", 4, "7802"),
    (1, "123456", "SHA512", 5, "47802"),
    (1, "123456", "SHA512", 6, "447802"),
    (1, "123456", "SHA512", 7, "6447802"),
    (1, "123456", "SHA512", 8, "26447802"),
    (1, "johndoe", "SHA1", 1, "0"),
    (1, "johndoe", "SHA1", 2, "20"),
    (1, "johndoe", "SHA1", 3, "720"),
    (1, "johndoe", "SHA1", 4, "1720"),
    (1, "johndoe", "SHA1", 5, "41720"),
    (1, "johndoe", "SHA1", 6, "741720"),
    (1, "johndoe", "SHA1", 7, "3741720"),
    (1, "johndoe", "SHA1", 8, "83741720"),
    (1, "johndoe", "SHA256", 1, "3"),
    (1, "johndoe", "SHA256", 2, "93"),
    (1, "johndoe", "SHA256", 3, "793"),
    (1, "johndoe", "SHA256", 4, "4793"),
    (1, "johndoe", "SHA256", 5, "54793"),
    (1, "johndoe", "SHA256", 6, "654793"),
    (1, "johndoe", "SHA256", 7, "9654793"),
    (1, "johndoe", "SHA256", 8, "39654793"),
    (1, "johndoe", "SHA384", 1, "0"),
    (1, "johndoe", "SHA384", 2, "90"),
    (1, "johndoe", "SHA384", 3, "890"),
    (1, "johndoe", "SHA384", 4, "8890"),
    (1, "johndoe", "SHA384", 5, "88890"),
    (1, "johndoe", "SHA384", 6, "988890"),
    (1, "johndoe", "SHA384", 7, "6988890"),
    (1, "johndoe", "SHA384", 8, "26988890"),
    (1, "johndoe", "SHA512", 1, "8"),
    (1, "johndoe", "SHA512", 2, "98"),
    (1, "johndoe", "SHA512", 3, "098"),
    (1, "johndoe", "SHA512", 4, "0098"),
    (1, "johndoe", "SHA512", 5, "60098"),
    (1, "johndoe", "SHA512", 6, "460098"),
    (1, "johndoe", "SHA512", 7, "6460098"),
    (1, "johndoe", "SHA512", 8, "36460098"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 1, "6"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 2, "26"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 3, "926"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 4, "4926"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 5, "44926"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 6, "444926"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 7, "5444926"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA1", 8, "95444926"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 1, "7"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 2, "17"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 3, "317"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 4, "5317"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 5, "45317"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 6, "445317"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 7, "3445317"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA256", 8, "43445317"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 1, "7"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 2, "77"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 3, "577"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 4, "6577"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 5, "86577"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 6, "086577"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 7, "5086577"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA384", 8, "15086577"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 1, "4"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 2, "54"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 3, "254"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 4, "4254"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 5, "74254"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 6, "074254"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 7, "1074254"),
    (1, "A quick brown fox jumps over the lazy dog", "SHA512", 8, "91074254"),
    (2147483647, "123456", "SHA1", 1, "9"),
    (2147483647, "123456", "SHA1", 2, "59"),
    (2147483647, "123456", "SHA1", 3, "859"),
    (2147483647, "123456", "SHA1", 4, "5859"),
    (2147483647, "123456", "SHA1", 5, "45859"),
    (2147483647, "123456", "SHA1", 6, "845859"),
    (2147483647, "123456", "SHA1", 7, "5845859"),
    (2147483647, "123456", "SHA1", 8, "35845859"),
    (2147483647, "123456", "SHA256", 1, "3"),
    (2147483647, "123456", "SHA256", 2, "33"),
    (2147483647, "123456", "SHA256", 3, "433"),
    (2147483647, "123456", "SHA256", 4, "1433"),
    (2147483647, "123456", "SHA256", 5, "51433"),
    (2147483647, "123456", "SHA256", 6, "751433"),
    (2147483647, "123456", "SHA256", 7, "7751433"),
    (2147483647, "123456", "SHA256", 8, "77751433"),
    (2147483647, "123456", "SHA384", 1, "1"),
    (2147483647, "123456", "SHA384", 2, "31"),
    (2147483647, "123456", "SHA384", 3, "931"),
    (2147483647, "123456", "SHA384", 4, "1931"),
    (2147483647, "123456", "SHA384", 5, "51931"),
    (2147483647, "123456", "SHA384", 6, "451931"),
    (2147483647, "123456", "SHA384", 7, "4451931"),
    (2147483647, "123456", "SHA384", 8, "74451931"),
    (2147483647, "123456", "SHA512", 1, "4"),
    (2147483647, "123456", "SHA512", 2, "54"),
    (2147483647, "123456", "SHA512", 3, "754"),
    (2147483647, "123456", "SHA512", 4, "3754"),
    (2147483647, "123456", "SHA512", 5, "53754"),
    (2147483647, "123456", "SHA512", 6, "953754"),
    (2147483647, "123456", "SHA512", 7, "8953754"),
    (2147483647, "123456", "SHA512", 8, "98953754"),
    (2147483647, "johndoe", "SHA1", 1, "3"),
    (2147483647, "johndoe", "SHA1", 2, "03"),
    (2147483647, "johndoe", "SHA1", 3, "603"),
    (2147483647, "johndoe", "SHA1", 4, "4603"),
    (2147483647, "johndoe", "SHA1", 5, "44603"),
    (2147483647, "johndoe", "SHA1", 6, "144603"),
    (2147483647, "johndoe", "SHA1", 7, "7144603"),
    (2147483647, "johndoe", "SHA1", 8, "07144603"),
    (2147483647, "johndoe", "SHA256", 1, "5"),
    (2147483647, "johndoe", "SHA256", 2, "55"),
    (2147483647, "johndoe", "SHA256", 3, "255"),
    (2147483647, "johndoe", "SHA256", 4, "4255"),
    (2147483647, "johndoe", "SHA256", 5, "24255"),
    (2147483647, "johndoe", "SHA256", 6, "324255"),
    (2147483647, "johndoe", "SHA256", 7, "0324255"),
    (2147483647, "johndoe", "SHA256", 8, "60324255"),
    (2147483647, "johndoe", "SHA384", 1, "1"),
    (2147483647, "johndoe", "SHA384", 2, "91"),
    (2147483647, "johndoe", "SHA384", 3, "291"),
    (2147483647, "johndoe", "SHA384", 4, "4291"),
    (2147483647, "johndoe", "SHA384", 5, "64291"),
    (2147483647, "johndoe", "SHA384", 6, "864291"),
    (2147483647, "johndoe", "SHA384", 7, "7864291"),
    (2147483647, "johndoe", "SHA384", 8, "07864291"),
    (2147483647, "johndoe", "SHA512", 1, "3"),
    (2147483647, "johndoe", "SHA512", 2, "13"),
    (2147483647, "johndoe", "SHA512", 3, "513"),
    (2147483647, "johndoe", "SHA512", 4, "9513"),
    (2147483647, "johndoe", "SHA512", 5, "59513"),
    (2147483647, "johndoe", "SHA512", 6, "659513"),
    (2147483647, "johndoe", "SHA512", 7, "0659513"),
    (2147483647, "johndoe", "SHA512", 8, "40659513"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 1, "0"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 2, "70"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 3, "670"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 4, "9670"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 5, "79670"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 6, "479670"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 7, "6479670"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA1", 8, "36479670"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 1, "6"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 2, "56"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 3, "556"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 4, "1556"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 5, "31556"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 6, "131556"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 7, "1131556"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA256", 8, "61131556"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 1, "1"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 2, "71"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 3, "471"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 4, "8471"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 5, "78471"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 6, "478471"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 7, "4478471"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA384", 8, "14478471"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 1, "1"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 2, "51"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 3, "651"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 4, "7651"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 5, "87651"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 6, "487651"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 7, "4487651"),
    (2147483647, "A quick brown fox jumps over the lazy dog", "SHA512", 8, "34487651"),
    (9223372036854775807, "123456", "SHA1", 1, "3"),
    (9223372036854775807, "123456", "SHA1", 2, "33"),
    (9223372036854775807, "123456", "SHA1", 3, "533"),
    (9223372036854775807, "123456", "SHA1", 4, "0533"),
    (9223372036854775807, "123456", "SHA1", 5, "20533"),
    (9223372036854775807, "123456", "SHA1", 6, "620533"),
    (9223372036854775807, "123456", "SHA1", 7, "7620533"),
    (9223372036854775807, "123456", "SHA1", 8, "37620533"),
    (9223372036854775807, "123456", "SHA256", 1, "8"),
    (9223372036854775807, "123456", "SHA256", 2, "28"),
    (9223372036854775807, "123456", "SHA256", 3, "628"),
    (9223372036854775807, "123456", "SHA256", 4, "5628"),
    (9223372036854775807, "123456", "SHA256", 5, "45628"),
    (9223372036854775807, "123456", "SHA256", 6, "445628"),
    (9223372036854775807, "123456", "SHA256", 7, "5445628"),
    (9223372036854775807, "123456", "SHA256", 8, "85445628"),
    (9223372036854775807, "123456", "SHA384", 1, "2"),
    (9223372036854775807, "123456", "SHA384", 2, "42"),
    (9223372036854775807, "123456", "SHA384", 3, "842"),
    (9223372036854775807, "123456", "SHA384", 4, "0842"),
    (9223372036854775807, "123456", "SHA384", 5, "40842"),
    (9223372036854775807, "123456", "SHA384", 6, "540842"),
    (9223372036854775807, "123456", "SHA384", 7, "8540842"),
    (9223372036854775807, "123456", "SHA384", 8, "58540842"),
    (9223372036854775807, "123456", "SHA512", 1, "5"),
    (9223372036854775807, "123456", "SHA512", 2, "85"),
    (9223372036854775807, "123456", "SHA512", 3, "885"),
    (9223372036854775807, "123456", "SHA512", 4, "2885"),
    (9223372036854775807, "123456", "SHA512", 5, "12885"),
    (9223372036854775807, "123456", "SHA512", 6, "512885"),
    (9223372036854775807, "123456", "SHA512", 7, "9512885"),
    (9223372036854775807, "123456", "SHA512", 8, "89512885"),
    (9223372036854775807, "johndoe", "SHA1", 1, "4"),
    (9223372036854775807, "johndoe", "SHA1", 2, "74"),
    (9223372036854775807, "johndoe", "SHA1", 3, "474"),
    (9223372036854775807, "johndoe", "SHA1", 4, "7474"),
    (9223372036854775807, "johndoe", "SHA1", 5, "87474"),
    (9223372036854775807, "johndoe", "SHA1", 6, "587474"),
    (9223372036854775807, "johndoe", "SHA1", 7, "8587474"),
    (9223372036854775807, "johndoe", "SHA1", 8, "98587474"),
    (9223372036854775807, "johndoe", "SHA256", 1, "5"),
    (9223372036854775807, "johndoe", "SHA256", 2, "15"),
    (9223372036854775807, "johndoe", "SHA256", 3, "615"),
    (9223372036854775807, "johndoe", "SHA256", 4, "0615"),
    (9223372036854775807, "johndoe", "SHA256", 5, "10615"),
    (9223372036854775807, "johndoe", "SHA256", 6, "710615"),
    (9223372036854775807, "johndoe", "SHA256", 7, "1710615"),
    (9223372036854775807, "johndoe", "SHA256", 8, "51710615"),
    (9223372036854775807, "johndoe", "SHA384", 1, "1"),
    (9223372036854775807, "johndoe", "SHA384", 2, "61"),
    (9223372036854775807, "johndoe", "SHA384", 3, "561"),
    (9223372036854775807, "johndoe", "SHA384", 4, "8561"),
    (9223372036854775807, "johndoe", "SHA384", 5, "08561"),
    (9223372036854775807, "johndoe", "SHA384", 6, "808561"),
    (9223372036854775807, "johndoe", "SHA384", 7, "7808561"),
    (9223372036854775807, "johndoe", "SHA384", 8, "27808561"),
    (9223372036854775807, "johndoe", "SHA512", 1, "0"),
    (9223372036854775807, "johndoe", "SHA512", 2, "30"),
    (9223372036854775807, "johndoe", "SHA512", 3, "430"),
    (9223372036854775807, "johndoe", "SHA512", 4, "2430"),
    (9223372036854775807, "johndoe", "SHA512", 5, "32430"),
    (9223372036854775807, "johndoe", "SHA512", 6, "632430"),
    (9223372036854775807, "johndoe", "SHA512", 7, "1632430"),
    (9223372036854775807, "johndoe", "SHA512", 8, "51632430"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 1, "5"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 2, "05"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 3, "105"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 4, "1105"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 5, "81105"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 6, "581105"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 7, "3581105"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA1", 8, "23581105"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 1, "1"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 2, "51"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 3, "451"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 4, "0451"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 5, "40451"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 6, "140451"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 7, "0140451"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA256", 8, "30140451"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 1, "6"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 2, "46"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 3, "646"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 4, "0646"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 5, "80646"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 6, "980646"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 7, "5980646"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA384", 8, "55980646"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 1, "6"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 2, "86"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 3, "386"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 4, "3386"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 5, "53386"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 6, "553386"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 7, "4553386"),
    (9223372036854775807, "A quick brown fox jumps over the lazy dog", "SHA512", 8, "04553386"),
]
