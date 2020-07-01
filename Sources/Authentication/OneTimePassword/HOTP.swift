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
Basic HOTP algorithm (RFC 4226)
Reference: https://tools.ietf.org/html/rfc4226.
*/
public struct HOTP {
    
    /**
     Supported hashing algorithms.
     */
    public enum Algorithm: String {
        
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha384 = "SHA384"
        case sha512 = "SHA512"
        
        /// Answers if the algorithm is deemed secure.
        public var isSecure: Bool {
            self != .sha1
        }
        
    }
    
    // MARK: Private static stored properties
    
    // Pre-computed powers of ten for 1 through 9.
    private static let powersOfTen = [ 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 ]

    // MARK: Private stored properties
    
    private let algorithm: Algorithm

    private let digits: Int

    private let key: SymmetricKey

    // MARK: Initializing
    
    /// Initializes the algorithm.
    /// Fails if number of digits is out of range.
    public init(secret: Data, algorithm: Algorithm = .sha256, digits: Int = 6) {
        precondition((1 ... Self.powersOfTen.count).contains(digits))

        self.algorithm = algorithm
        self.digits = digits
        self.key = SymmetricKey(data: secret)
    }

    // MARK: Generating
    
    /// Answers the password for given counter using the specified algorithm and secret.
    public func generatePassword(for counter: Int64) -> String {
        let password = hash(for: counter) % UInt32(Self.powersOfTen[digits - 1])

        return String(format: "%0*u", digits, password)
    }

    // MARK: Validating
    
    /// Answers if the password is valid for given counter.
    public func isValidPassword(_ password: String, for counter: Int64) -> Bool {
        generatePassword(for: counter) == password
    }
    
    // MARK: Private generating
    
    // Computes the hash for given algorithm and secret, and extracts the relevant part.
    // Reference: https://tools.ietf.org/html/rfc4226.
    private func hash(for counter: Int64) -> UInt32 {        
        func hash<H>(using: H.Type) -> UInt32 where H: HashFunction {
            let data = withUnsafeBytes(of: counter.bigEndian) { Array($0) }
            let code = HMAC<H>.authenticationCode(for: data, using: key)

            return code.withUnsafeBytes { bytes in
                let offset = Int(bytes[bytes.count - 1] & 0x0f)
                
                return ((UInt32(bytes[offset]) & 0x7f) << 24) |
                        (UInt32(bytes[offset + 1]) << 16) |
                        (UInt32(bytes[offset + 2]) << 8) |
                        (UInt32(bytes[offset + 3]))
            }
        }
        
        switch algorithm {
        case .sha1: return hash(using: Insecure.SHA1.self)
        case .sha256: return hash(using: SHA256.self)
        case .sha384: return hash(using: SHA384.self)
        case .sha512: return hash(using: SHA512.self)
        }
    }
    
}
