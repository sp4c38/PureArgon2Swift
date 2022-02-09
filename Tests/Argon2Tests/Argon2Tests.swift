import XCTest
@testable import Argon2

final class Argon2Tests: XCTestCase {
    struct StandardFehler: Error {
        let beschreibung: String
        init(_ beschreibung: String) {
        self.beschreibung = beschreibung
        }
    }
    
    func testListeAufteilen() throws {
        XCTAssertTrue([1, 2, 3, 4, 5, 6, 7, 8].aufteilen(jede: 3) == [[1, 2, 3], [4, 5, 6], [7, 8]])
        XCTAssertTrue([1, 2, 3, 4, 5, 6, 7, 8].aufteilen(jede: 7) == [[1, 2, 3, 4, 5, 6, 7], [8]])
        XCTAssertTrue(Array<Int>().aufteilen(jede: 10) == [])
    }
}
