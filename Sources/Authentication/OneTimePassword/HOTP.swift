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
 Basic HOTP algorithm ([RFC 4226](https://tools.ietf.org/html/rfc4226))
 */
public struct HOTP {
    
    /**
     Supported hashing algorithms.
     */
    public enum Algorithm {
        
        case sha1, sha256, sha384, sha512
        
        
        // MARK: Computed properties
        
        /// Answers the number of bytes of the corresponding hash.
        public var byteCount: Int {
            switch self {
            case .sha1: return Insecure.SHA1.byteCount
            case .sha256: return SHA256.byteCount
            case .sha384: return SHA384.byteCount
            case .sha512: return SHA512.byteCount
            }
        }

    }
    
    // MARK: Private static stored properties
    
    // Pre-computed powers of ten for 1 through 9.
    private static let powersOfTen = [ 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 ]

    // MARK: Stored properties
    
    /// The hashing algorithm.
    /// Default is SHA1.
    let algorithm: Algorithm

    /// The number of truncation digits.
    /// The range is: `1 ... 9`.
    /// Default is 6.
    let digits: Int

    /// The optional truncation offset:
    /// - If nil, use dynamic truncation.
    /// - If non-nil, the range is: `0 ..< algorithm.byteCount - 4`.
    /// Default is nil.
    let offset: Int?

    /// Defines the optional range of counters that may be used to validate a password for a given counter.
    /// Given a non-nil window, the counter range is: `counter - window ... counter + window`, where the window range is: `1 ... 5`.
    /// If the window is nil, validation requires the password to match the specified counter.
    /// Default is nil.
    let window: Int?

    // MARK: Private stored properties
    
    private let key: SymmetricKey

    // MARK: Initializing
    
    /// Initializes the algorithm.
    /// Fails if the number of digits, the optional truncation offset or the window is out of range.
    /// When using dynamic truncation the algorithm must have a byte count of at least 20, which is  true for all Algorithm cases.
    public init?(secret: Data, algorithm: Algorithm = .sha1, digits: Int = 6, offset: Int? = nil, window: Int? = nil) {
        guard (1 ... Self.powersOfTen.count).contains(digits) else { return nil }
        guard (0 ..< algorithm.byteCount - 4).contains(offset ?? 0) else { return nil }
        if let window = window, !(1 ... 5).contains(window) { return nil }

        self.key = SymmetricKey(data: secret)
        self.algorithm = algorithm
        self.digits = digits
        self.offset = offset
        self.window = window
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
        guard let window = window else { return generatePassword(for: counter) == password }
        
        return (-window ... window).contains { i in generatePassword(for: counter + Int64(i)) == password }
    }
    
    // MARK: Private generating
    
    // Computes the hash for given algorithm and secret, and extracts the relevant part.
    private func hash(for counter: Int64) -> UInt32 {        
        func hash<H>(with: H.Type) -> UInt32 where H: HashFunction {
            let data = withUnsafeBytes(of: counter.bigEndian) { Array($0) }
            let code = HMAC<H>.authenticationCode(for: data, using: key)

            return code.withUnsafeBytes { bytes in
                let offset = self.offset ?? Int(bytes[bytes.count - 1] & 0x0f)
                
                return ((UInt32(bytes[offset]) & 0x7f) << 24) |
                        (UInt32(bytes[offset + 1]) << 16) |
                        (UInt32(bytes[offset + 2]) << 8) |
                        (UInt32(bytes[offset + 3]))
            }
        }
        
        switch algorithm {
        case .sha1: return hash(with: Insecure.SHA1.self)
        case .sha256: return hash(with: SHA256.self)
        case .sha384: return hash(with: SHA384.self)
        case .sha512: return hash(with: SHA512.self)
        }
    }
    
}
