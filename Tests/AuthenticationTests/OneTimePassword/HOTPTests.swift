//
//  HOTPTests.swift
//  Security
//
//  Created by Michel Tilman on 29/06/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import XCTest
import Authentication

/**
 Tests generation and validation of HOTP passwords.
 */
final class HOTPTests: XCTestCase {

    // MARK: Testing RFC 4226 reference passwords
    
    // Test SHA1 for counters 0 through 9 truncating / padding to 6 digits.
    func testRFC4226() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP(secret: secret, algorithm: .sha1)
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489", ""]

        for i in 0 ... 9 {
            XCTAssertEqual(hotp.generatePassword(counter: Int64(i)), expected[i])
        }
    }
    
}


/**
 Function test suite.
 */
extension HOTPTests {
    static var allTests = [
        ("testRFC4226", testRFC4226)
    ]
    
}
