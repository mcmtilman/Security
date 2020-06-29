import XCTest

import AuthenticationTests

var tests = [XCTestCaseEntry]()
tests += HOTPTests.allTests()
XCTMain(tests)
