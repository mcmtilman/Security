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
enum TOTPTestResources {
    
    /// One-time passwords listed by the RFC6238 using the Java reference implementation for multiple date  / secret / algorithm combinations.
    /// Also incudes date in seconds since 00:00:00 UTC on 01/01/1970. Divided by the TOTP period this yields the counter.
    static let referenceData: [(date: String, seconds: Int, secret: String, algorithm: HOTP.Algorithm, otp: String)] = [
        ("1970-01-01 00:00:59", 59, "12345678901234567890", .sha1, "94287082"),
        ("1970-01-01 00:00:59", 59, "12345678901234567890123456789012", .sha256, "46119246"),
        ("1970-01-01 00:00:59", 59, "1234567890123456789012345678901234567890123456789012345678901234", .sha512, "90693936"),
        ("2005-03-18 01:58:29", 1111111109, "12345678901234567890", .sha1, "07081804"),
        ("2005-03-18 01:58:29", 1111111109, "12345678901234567890123456789012", .sha256, "68084774"),
        ("2005-03-18 01:58:29", 1111111109, "1234567890123456789012345678901234567890123456789012345678901234", .sha512, "25091201"),
        ("2005-03-18 01:58:31", 1111111111, "12345678901234567890", .sha1, "14050471"),
        ("2005-03-18 01:58:31", 1111111111, "12345678901234567890123456789012", .sha256, "67062674"),
        ("2005-03-18 01:58:31", 1111111111, "1234567890123456789012345678901234567890123456789012345678901234", .sha512, "99943326"),
        ("2009-02-13 23:31:30", 1234567890, "12345678901234567890", .sha1, "89005924"),
        ("2009-02-13 23:31:30", 1234567890, "12345678901234567890123456789012", .sha256, "91819424"),
        ("2009-02-13 23:31:30", 1234567890, "1234567890123456789012345678901234567890123456789012345678901234", .sha512, "93441116"),
        ("2033-05-18 03:33:20", 2000000000, "12345678901234567890", .sha1, "69279037"),
        ("2033-05-18 03:33:20", 2000000000, "12345678901234567890123456789012", .sha256, "90698825"),
        ("2033-05-18 03:33:20", 2000000000, "1234567890123456789012345678901234567890123456789012345678901234", .sha512, "38618901"),
        ("2603-10-11 11:33:20", 20000000000, "12345678901234567890", .sha1, "65353130"),
        ("2603-10-11 11:33:20", 20000000000, "12345678901234567890123456789012", .sha256, "77737706"),
        ("2603-10-11 11:33:20", 20000000000, "1234567890123456789012345678901234567890123456789012345678901234", .sha512, "47863826")
    ]

}