import XCTest
@testable import Argon2

final class Argon2Tests: XCTestCase {
    struct StandardFehler: Error {
        let beschreibung: String
        init(_ beschreibung: String) {
        self.beschreibung = beschreibung
        }
    }
    
    func testPermutationMatrix() throws {
        var zufälligeBytes = [UInt8](repeating: 0, count: 8*16)
        guard SecRandomCopyBytes(kSecRandomDefault, zufälligeBytes.count, &zufälligeBytes) == 0 else { throw StandardFehler("Zufällige Bytes konnten nicht generiert werden.") }
        let zufälligeBytesEingabe = zufälligeBytes.aufteilen(jede: 16).map { Data($0) }
        let bytesMatrix = permutationMatrixErstellen(eingabeDaten: zufälligeBytesEingabe)
        var start = 0
        for reihe in bytesMatrix {
            for eingabeByte in reihe.aufteilen(jede: 2) {
                let separierteBytes = [zufälligeBytesEingabe[start][8...15], zufälligeBytesEingabe[start][0...7]]
                XCTAssertTrue(eingabeByte == separierteBytes)
                start += 1
            }
        }
    }
    
    func testListeAufteilen() throws {
        XCTAssertTrue([1, 2, 3, 4, 5, 6, 7, 8].aufteilen(jede: 3) == [[1, 2, 3], [4, 5, 6], [7, 8]])
        XCTAssertTrue([1, 2, 3, 4, 5, 6, 7, 8].aufteilen(jede: 7) == [[1, 2, 3, 4, 5, 6, 7], [8]])
        XCTAssertTrue(Array<Int>().aufteilen(jede: 10) == [])
    }
}
