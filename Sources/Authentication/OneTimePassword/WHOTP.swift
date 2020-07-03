//
//  WHOTP.swift
//
//  Created by Michel Tilman on 30/06/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

/**
Basic HOTP algorithm extended with window support.
Reference: https://tools.ietf.org/html/rfc4226.
*/
public struct WHOTP {
    
    // MARK: Stored properties
    
    /// Defines the range of counters that may be used to validate a password for a given counter.
    /// The range is: counter - window ... counter + window.
    let window: Int64

    // MARK: Private stored properties
    
    private let hotp: HOTP

    // MARK: Initializing
    
    /// Initializes the algorithm.
    /// Fails if window is out of range.
    public init?(hotp: HOTP, window: Int = 1) {
        guard (1 ... 5).contains(window) else { return nil }

        self.hotp = hotp
        self.window = Int64(window)
    }

    // MARK: Generating
    
    /// Answers the password for given counter using specified algorithm and secret.
    public func generatePassword(for counter: Int64) -> String {
        hotp.generatePassword(for: counter)
    }
    
    // MARK: Validating
    
    /// Answers if the password is valid by locating a matching counter in the range counter - window ... counter + window.
    /// Try given counter first, followed by progressively more distant counters.
    public func isValidPassword(_ password: String, for counter: Int64) -> Bool {
        hotp.isValidPassword(password, for: counter)
            || (1 ... window).contains { i in hotp.isValidPassword(password, for: counter - i) || hotp.isValidPassword(password, for: counter + i) }
    }
    
}
