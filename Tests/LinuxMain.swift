import XCTest

import AuthenticationTests

var tests = [XCTestCaseEntry]()

tests += HOTPTests.allTests()
tests += TOTPTests.allTests()

XCTMain(tests)
