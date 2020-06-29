import XCTest

import SecurityTests

var tests = [XCTestCaseEntry]()
tests += SecurityTests.allTests()
XCTMain(tests)
