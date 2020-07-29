//
//  TOTP.swift
//  Security
//
//  Created by Michel Tilman on 21/07/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import Foundation

/**
 Basic TOTP algorithm based on the HOTP algorithm ([RFC 4226](https://tools.ietf.org/html/rfc6238))
 */
public struct TOTP {
    
    /**
     TOTP configuration.
     */
    public struct Configuration {
        
        // MARK: Stored properties
        
        /// Dates in the same period represent the same counter.
        /// The counter is calculated as the date's timeinterval in seconds since 00:00:00 UTC on 01/01/1970 divided by the period.
        /// The range is: `TimeInterval(1) ... TimeInterval(120)`.
        /// Default is 30 seconds.
        let period: TimeInterval

        // MARK: Initializing
        
        /// Initializes and validates the configuration.
        /// Clamps the period to the range 1... 120 seconds.
        public init(period: TimeInterval = 30) {
            self.period = (1 ... 120).clamp(period)
        }
        
    }

    // MARK: Stored properties
    
    /// The configuration.
    /// Default uses a period of 30 seconds.
    let configuration: Configuration
    
    // MARK: Private stored properties
    
    // The basic HTOP service
    private let hotp: HOTP

    // MARK: Initializing
    
    /// Initializes the service with given HOTP service and (default) configuration.
    public init(hotp: HOTP, configuration: Configuration = .init()) {
        self.hotp = hotp
        self.configuration = configuration
    }

    // MARK: Generating
    
    /// Answers the password for given date using specified algorithm and secret.
    /// The password is the same for all dates in the same period.
    public func generatePassword(for date: Date) -> String {
        hotp.generatePassword(for: counter(from: date))
    }
    
    // MARK: Validating
    
    /// Verifies if the password is valid for given date.
    /// The password must match any of the passwords corresponding to dates yielding counters in the range `counter - window ... counter + window`, where `counter` is the counter for given date.
    public func isValidPassword(_ password: String, for date: Date) -> Bool {
        hotp.isValidPassword(password, for: counter(from: date))
    }
    
    /// Answers the *skew* of a valid password / date combination, or nil if the combination is not valid.
    /// For a valid combination the skew is the offset of the counter derived from the date in the range `counter - window ... counter + window` matching the password. For a default window, the skew is 0.
    public func skew(date: Date, password: String) -> Int? {
        hotp.skew(counter: counter(from: date), password: password)
    }
    
    // MARK: Private converting
    
    // Converts the date into a counter, which is the same for all dates in the same period.
    private func counter(from date: Date) -> Int64 {
        Int64(date.timeIntervalSince1970 / configuration.period)
    }
    
}
