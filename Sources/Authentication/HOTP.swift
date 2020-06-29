//
//  HOTP.swift
//
//  Created by Michel Tilman on 29/06/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import CryptoKit
import Foundation

/**
 HOTP algorithm.
 [RFC 4226](https://tools.ietf.org/html/rfc4226)
 */

// Pre-computed powers of ten, one for each number of digits.
fileprivate let powersOfTen = [ 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 ]

public struct HOTP<H> where H: HashFunction {
    
    // MARK: Private stored properties
    
    private let digits: Int

    private let secret: Data

    private let window: Int64

    // MARK: Initializing
    
    public init(secret: Data, digits: Int = 6, window: Int = 0) {
        precondition((1 ... powersOfTen.count).contains(digits))
        precondition((0 ... 5).contains(window))

        self.digits = digits
        self.secret = secret
        self.window = Int64(window)
    }

    // MARK: Generating
    
    public func generatePassword(counter: Int64) -> String {
        let data = withUnsafeBytes(of: counter.bigEndian) { Array($0) }
        let hash = HMAC<H>.authenticationCode(for: data, using: SymmetricKey(data: secret))
        let password = (extractPassword(from: hash).bigEndian & 0x7FFF_FFFF) % UInt32(powersOfTen[digits])

        return String(format: "%0*u", digits, password)
    }

    // MARK: Validating
    
    /// Answers if the password is valid.
    /// Try matching the counter. If not possible, try previous and next counters in the window.
    public func isValidPassword(password: String, counter: Int64) -> Bool {
        if generatePassword(counter: counter) == password { return true }
        
        for c in counter - window ... counter + window where c != counter {
            if generatePassword(counter: c) == password { return true }
        }
        
        return false
    }
    
    // MARK: Private validating
    
    private func extractPassword(from hash: HashedAuthenticationCode<H>) -> UInt32 {
        hash.withUnsafeBytes { hashPtr -> UInt32 in
            let offset = hashPtr[hash.byteCount - 1] & 0x0f
            let passwordPtr = hashPtr.baseAddress! + Int(offset)

            return passwordPtr.bindMemory(to: UInt32.self, capacity: 1).pointee
        }
    }

}
