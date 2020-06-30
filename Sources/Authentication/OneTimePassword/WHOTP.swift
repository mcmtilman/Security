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
    
    // MARK: Private stored properties
    
    private let hotp: HOTP

    private let window: Int64

    // MARK: Initializing
    
    /// Initializes the algorithm.
    /// Fails if window is out of range.
    public init(hotp: HOTP, window: Int = 1) {
        precondition((0 ... 5).contains(window))

        self.hotp = hotp
        self.window = Int64(window)
    }

    // MARK: Generating
    
    /// Answers the password for given counter using specified algorithm and secret.
    public func generatePassword(counter: Int64) -> String {
        hotp.generatePassword(counter: counter)
    }
    
    // MARK: Validating
    
    /// Answers if the password is valid.
    /// Try matching the counter. If not possible, try previous and next counters in the window.
    public func isValidPassword(password: String, counter: Int64) -> Bool {
        if hotp.isValidPassword(password: password, counter: counter) { return true }
        
        for c in counter - window ... counter + window where c != counter {
            if hotp.isValidPassword(password: password, counter: c) { return true }
        }
        
        return false
    }
    
}
