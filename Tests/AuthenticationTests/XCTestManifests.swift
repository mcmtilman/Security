import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(HOTPTests.allTests),
        testCase(WHOTPTests.allTests),
    ]
}
#endif
