//
//  TOTPTestResources.swift
//  Security
//
//  Created by Michel Tilman on 21/07/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import Authentication

/**
 Shared TOTP test data.
 */
struct TOTPTestResources {
    
    /// One-time passwords generated by the RFC6238  Java reference implementation for multiple algorithm / secret / date  combinations.
    static let referenceData: [(algorithm: HOTP.Algorithm, secret: String, dateSeconds: Int, dateString: String, otp: String)] = [
        (.sha1, "12345678901234567890", 59, "1970-01-01 00:00:59", "94287082"),
        (.sha256, "12345678901234567890123456789012", 59, "1970-01-01 00:00:59", "46119246"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 59, "1970-01-01 00:00:59", "90693936"),
        (.sha1, "12345678901234567890", 1111111109, "2005-03-18 01:58:29", "07081804"),
        (.sha256, "12345678901234567890123456789012", 1111111109, "2005-03-18 01:58:29", "68084774"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 1111111109, "2005-03-18 01:58:29", "25091201"),
        (.sha1, "12345678901234567890", 1111111111, "2005-03-18 01:58:31", "14050471"),
        (.sha256, "12345678901234567890123456789012", 1111111111, "2005-03-18 01:58:31", "67062674"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 1111111111, "2005-03-18 01:58:31", "99943326"),
        (.sha1, "12345678901234567890", 1234567890, "2009-02-13 23:31:30", "89005924"),
        (.sha256, "12345678901234567890123456789012", 1234567890, "2009-02-13 23:31:30", "91819424"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 1234567890, "2009-02-13 23:31:30", "93441116"),
        (.sha1, "12345678901234567890", 2000000000, "2033-05-18 03:33:20", "69279037"),
        (.sha256, "12345678901234567890123456789012", 2000000000, "2033-05-18 03:33:20", "90698825"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 2000000000, "2033-05-18 03:33:20", "38618901"),
        (.sha1, "12345678901234567890", 20000000000, "2603-10-11 11:33:20", "65353130"),
        (.sha256, "12345678901234567890123456789012", 20000000000, "2603-10-11 11:33:20", "77737706"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 20000000000, "2603-10-11 11:33:20", "47863826")
    ]

}
