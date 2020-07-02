import XCTest

import AuthenticationTests

var tests = [XCTestCaseEntry]()

tests += HOTPTests.allTests()
tests += WHOTPTests.allTests()

XCTMain(tests)
