//
//  ExtensionsTests.swift
//  Security
//
//  Created by Michel Tilman on 30/07/2020.
//  Copyright © 2020 Dotted.Pair.
//  Licensed under Apache License v2.0.
//

import XCTest
@testable import Authentication

/**
 Tests ClosedRange extension.
 */
class ClosedRangeTests: XCTestCase {
    
    // MARK: Testing ClosedRange clamping
    
    // Test clamping non-optional values.
    func testClampNonOptionalValues() {
        let range = 1 ... 10
        
        for (value, expected) in [(0, 1), (1, 1), (2, 2), (9, 9), (10, 10), (11, 10)] {
            XCTAssertEqual(range.clamp(value), expected)
        }
    }
    
    // Test clamping optional values.
    func testClampOptionalValues() {
        let range = 1 ... 10
        
        for (value, expected) in [(nil, nil), (0, 1), (1, 1), (2, 2), (9, 9), (10, 10), (11, 10)] {
            XCTAssertEqual(range.clamp(value), expected)
        }
    }

}
