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
    public enum Algorithm {
        
        case md5, sha1, sha256, sha384, SHA512
        
        /// Answers if the algorithm is deemed secure.
        public var isSecure: Bool {
            self != .md5 && self != .sha1
        }
        
    }
    
    // MARK: Private static stored properties
    
    // Pre-computed powers of ten for 0 through 9.
    private static let powersOfTen = [ 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 ]

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
    
    /// Answers the password for given counter using specified algorithm and secret.
    public func generatePassword(counter: Int64) -> String {
        let data = withUnsafeBytes(of: counter.bigEndian) { Array($0) }
        let password = hash(for: data).bigEndian & 0x7FFF_FFFF

        return String(format: "%0*u", digits, password % UInt32(Self.powersOfTen[digits]))
    }

    // MARK: Validating
    
    /// Answers if the password is valid for given counter.
    public func isValidPassword(password: String, counter: Int64) -> Bool {
        generatePassword(counter: counter) == password
    }
    
    // MARK: Private generating
    
    // Computes the hash for given algorithm and extracts the relevant part.
    private func hash(for data: [UInt8]) -> UInt32 {
        struct Hasher<H> where H: HashFunction {
            static func hash(_ data: [UInt8], _ key: SymmetricKey) -> UInt32 {
                let code = HMAC<H>.authenticationCode(for: data, using: key)

                return code.withUnsafeBytes { ptr -> UInt32 in
                    let offset = ptr[code.byteCount - 1] & 0x0f
                    let hashPtr = ptr.baseAddress! + Int(offset)

                    return hashPtr.bindMemory(to: UInt32.self, capacity: 1).pointee
                }
            }
        }
        
        switch algorithm {
        case .md5: return Hasher<Insecure.MD5>.hash(data, key)
        case .sha1: return Hasher<Insecure.SHA1>.hash(data, key)
        case .sha256: return Hasher<SHA256>.hash(data, key)
        case .sha384: return Hasher<SHA384>.hash(data, key)
        case .SHA512: return Hasher<SHA512>.hash(data, key)
        }
    }
    
}
