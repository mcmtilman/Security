//
//  HOTP.swift
//  Security
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
    
    /// Supported hashing algorithms.
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
    
    /// HOTP configuration.
    public struct Configuration {
        
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

        /// Defines the range of counters that may be used to match a given password.
        /// The counter range is: `counter - window ... counter + window`, where the window range is: `0 ... 5`.
        /// Default is 0.
        let window: Int

        // MARK: Initializing
        
        /// Initializes and validates the configuration.
        /// Clamp the number of digits, the optional truncation offset and the window to their respective ranges.
        /// When using dynamic truncation the algorithm must have a byte count of at least 20, which is  true for all Algorithm cases.
        public init(algorithm: Algorithm = .sha1, digits: Int = 6, offset: Int? = nil, window: Int = 0) {
            self.algorithm = algorithm
            self.digits = (1 ... 9).clamp(digits)
            self.offset = (0 ... algorithm.byteCount - 5).clamp(offset)
            self.window = (0 ... 5).clamp(window)
        }
        
    }
    
    // MARK: Private static stored properties
    
    // Pre-computed powers of ten for 1 through maximum number of digits (9).
    private static let powersOfTen = [ 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 ]

    // MARK: Stored properties
    
    /// The configuration.
    /// Default uses SHA1, 6 digits, no offset and no window.
    let configuration: Configuration

    // MARK: Private stored properties
    
    // The secret key.
    private let key: SymmetricKey

    // MARK: Initializing
    
    /// Initializes the service with given secret and (default) configuration.
    public init(secret: Data, configuration: Configuration = .init()) {
        self.key = SymmetricKey(data: secret)
        self.configuration = configuration
    }

    // MARK: Generating
    
    /// Answers the password for given counter using the specified algorithm and secret.
    public func generatePassword(for counter: Int64) -> String {
        let password = hash(for: counter) % UInt32(Self.powersOfTen[configuration.digits - 1])

        return String(format: "%0*u", configuration.digits, password)
    }

    // MARK: Validating
    
    /// Answers if the password is valid for given counter.
    /// The password must match the password for a counter in the range `counter - window ... counter + window`.
    public func isValidPassword(_ password: String, for counter: Int64) -> Bool {
        skew(counter: counter, password: password) != nil
    }
    
    /// Answers the *skew* of a valid password / counter combination, or nil if the combination is not valid.
    /// A non-nil skew is the offset from given counter for a counter in the range `counter - window ... counter + window` with given password.
    public func skew(counter: Int64, password: String) -> Int? {
        for i in 0 ... configuration.window {
            if i > 0, generatePassword(for: counter - Int64(i)) == password { return -i }
            if generatePassword(for: counter + Int64(i)) == password { return i }
        }
        
        return nil
    }
    
    // MARK: Private generating
    
    // Computes the hash for given algorithm and secret, and extracts the relevant part.
    private func hash(for counter: Int64) -> UInt32 {        
        func hash<H>(function: H.Type) -> UInt32 where H: HashFunction {
            let data = withUnsafeBytes(of: counter.bigEndian) { Array($0) }
            let code = HMAC<H>.authenticationCode(for: data, using: key)

            return code.withUnsafeBytes { bytes in
                let offset = configuration.offset ?? Int(bytes[bytes.count - 1] & 0x0f)
                
                return ((UInt32(bytes[offset]) & 0x7f) << 24) |
                        (UInt32(bytes[offset + 1]) << 16) |
                        (UInt32(bytes[offset + 2]) << 8) |
                        (UInt32(bytes[offset + 3]))
            }
        }
        
        switch configuration.algorithm {
        case .sha1: return hash(function: Insecure.SHA1.self)
        case .sha256: return hash(function: SHA256.self)
        case .sha384: return hash(function: SHA384.self)
        case .sha512: return hash(function: SHA512.self)
        }
    }
    
}


/**
 Adds support to clamp a value to a closed range.
 */
extension ClosedRange {
    
    /// Answers the value clamped to the range.
    func clamp(_ value: Bound) -> Bound {
        Swift.min(Swift.max(value, lowerBound), upperBound)
    }
    
    /// Answers the optional value clamped to the range if non-nil.
    func clamp(_ value: Bound?) -> Bound? {
        value.map(clamp)
    }
    
}
