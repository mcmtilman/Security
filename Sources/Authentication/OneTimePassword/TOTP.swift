//
//  TOTP.swift
//
//  Created by Michel Tilman on 21/07/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import Foundation

/**
 Basic TOTP algorithm with optional window support for skewed clocks  ([RFC 4226](https://tools.ietf.org/html/rfc6238))
 */
public struct TOTP {
    
    // MARK: Stored properties
    
    /// Number of seconds a date represents by the same counter.
    /// The range is: `TimeInterval(1) ... TimeInterval(120)`.
    /// Default is 30 seconds.
    let period: TimeInterval
    
    /// Underlying HOTP service.
    let hotp: HOTP

    // MARK: Initializing
    
    /// Initializes the algorithm, clamping the period if necessary.
    public init(hotp: HOTP, period: TimeInterval = 30) {
        self.hotp = hotp
        self.period = (1 ... 120).clamp(period)
    }

    // MARK: Generating
    
    /// Answers the password for given date using specified algorithm and secret.
    /// The password is the same for all dates in the same period.
    public func generatePassword(for date: Date) -> String {
        hotp.generatePassword(for: counter(from: date))
    }
    
    // MARK: Validating
    
    /// Answers if the password is valid by validating the derived counter.
    /// If a window is specified, tries matching a counter in the range `counter - window ... counter + window`,
    public func isValidPassword(_ password: String, for date: Date) -> Bool {
        hotp.isValidPassword(password, for: counter(from: date))
    }
    
    // MARK: Private converting
    
    // Converts the date into a counter, which is the same for all dates in the same period.
    private func counter(from date: Date) -> Int64 {
        Int64(date.timeIntervalSince1970 / period)
    }
    
}
