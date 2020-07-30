//
//  Extensions.swift
//  Security
//
//  Created by Michel Tilman on 30/07/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

/**
 Extends ClosedRange with support to clamp a value to the range.
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
