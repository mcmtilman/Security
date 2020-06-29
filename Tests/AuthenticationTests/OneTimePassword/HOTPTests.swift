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
import CryptoKit

/**
 Tests generation and validation of HOTP passwords.
 */
final class HOTPTests: XCTestCase {

    // MARK: Testing RFC 4226 reference passwords with SHA1, 6 digits and 0 window
    
    // Test SHA1 for counter 0.
    func testRFC4226() {
        guard let secret = "12345678901234567890".data(using: .utf8) else { return XCTFail("nil secret") }
        let hotp = HOTP<Insecure.SHA1>(secret: secret)
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
