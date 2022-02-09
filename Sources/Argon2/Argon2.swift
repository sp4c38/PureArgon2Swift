//
//  Argon2.swift
//  Argon2
//
//  Erstellt von Léon Becker am 29.12.21.
//

// Die Projektdatein von https://github.com/tgymnich/BitwiseRotate müssen eigens hinzugefügt werden. Die Datein werden als Hilfsmittel für das Rotieren von Bits benutzt.

import BigInt
import Blake2
import Foundation

/*
 H: BLAKE2b Hashfunktion
 H$: Hashfunktion variabler Länge, die auf H aufbaut.
 G: interne Kompressionsfunktion
 GB: Permutationsfunktion
 */


// MARK: Hashfunktion H

/// Berechnet einen Hashwert mit der variable Hashfunktion H (BLAKE2b).
/// - Parameters:
///   - daten: Die Daten die verschlüsselt werden sollen.
///   - ausgabelänge: Die Ausgabelänge des Hashes.
/// - Returns: den Hash
func hashfunktionHBerechnen(von daten: Data, ausgabelänge: Int) -> Data {
    do {
        return try Blake2.hash(.b2b, size: ausgabelänge, data: daten)
    } catch {
        print("Fehler beim Ausführen der BLAKE2b Hashfunktion: \(error)).")
        exit(1)
    }
}


// MARK: Hashfunktion H$

/// Durch diese Funktion können Ausgaben der H Funktion (BLAKE2b) produziert werden, die über das Limit von 64 Byte hinausgehen.
///
/// - Parameters:
///   - daten: Die Daten die verschlüsselt werden sollen.
///   - ausgabelänge: Die Ausgabelänge des Hashes.
/// - Returns: den Hash
func hashfunktionH$Berechnen(von daten: Data, ausgabelänge: UInt32) -> Data {
    if ausgabelänge <= 64 {
        var blake2b = try! Blake2(.b2b, size: Int(ausgabelänge))
        blake2b.update(withUnsafeBytes(of: UInt32(ausgabelänge).littleEndian) { Data($0) })
        blake2b.update(daten)
        return try! blake2b.finalize()
    } else {
        var ergebnis = Data()
        
        var blake2b = try! Blake2(.b2b, size: 64)
        blake2b.update(withUnsafeBytes(of: UInt32(ausgabelänge).littleEndian) { Data($0) })
        blake2b.update(daten)
        var v_block = try! blake2b.finalize()
        ergebnis.append(v_block[0..<32])
        
        var remainingLength = Int(ausgabelänge)-32
        
        while remainingLength > 64 {
            v_block = try! Blake2.hash(.b2b, size: 64, data: v_block)
            ergebnis.append(v_block[0..<32])
            remainingLength -= 32
        }

        v_block = try! Blake2.hash(.b2b, size: remainingLength, data: v_block)
        ergebnis.append(v_block)
        return ergebnis
    }
}

/// Wendet die Permutations auf die Daten an.
/// - Parameter eingabe: Eine Liste von 4 Elementen je 8 Byte groß.
func permutationGBBerechnen(_ v: inout [BigUInt], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
    let zweiHoch64 = BigUInt(2).power(64)
    for durchgang in (1...2) {
        v[a] = (v[a] + v[b] + 2 * (v[a].serializeLittleEndian().prefix(4).bigUInt * v[b].serializeLittleEndian().prefix(4).bigUInt) ) % zweiHoch64
        v[d] = BigUInt((v[d] ^ v[a]).serializeLittleEndian().uint64 >>> (durchgang == 1 ? 32 : 16))
        v[c] = (v[c] + v[d] + 2 * (v[c].serializeLittleEndian().prefix(4).bigUInt * v[d].serializeLittleEndian().prefix(4).bigUInt) ) % zweiHoch64
        v[b] = BigUInt((v[b] ^ v[c]).serializeLittleEndian().uint64 >>> (durchgang == 1 ? 24 : 63))
    }
}

/// Führt die Argon2 Permutation (von lateinisch permutare 'vertauschen') durch.
/// - Parameter eingabe: Acht 16-Byte Blöcke.
/// mit dem Exit-Code 1.
func permutationBerechnen(_ eingabeDaten: [Data]) -> [Data] {
    var v = [BigUInt]()
    for i in 0...7 {
        v.append(eingabeDaten[i][0...7].bigUInt)
        v.append(eingabeDaten[i][8...15].bigUInt)
    }

    permutationGBBerechnen(&v, 0, 4, 8, 12)
    permutationGBBerechnen(&v, 1, 5, 9, 13)
    permutationGBBerechnen(&v, 2, 6, 10, 14)
    permutationGBBerechnen(&v, 3, 7, 11, 15)

    permutationGBBerechnen(&v, 0, 5, 10, 15)
    permutationGBBerechnen(&v, 1, 6, 11, 12)
    permutationGBBerechnen(&v, 2, 7, 8, 13)
    permutationGBBerechnen(&v, 3, 4, 9, 14)

    var result = [Data]()
    for i in 0...7 {
        result.append(
            v[2*i].serializeLittleEndian() +
            v[2*i+1].serializeLittleEndian()
        )
    }
    print(result.map { $0.hexWert })
//    return permutationMatrixZusammenführen(aus: matrix)
    return []
}

/// Berechnet den Kompressionswert.
/// - Parameters:
///   - x: Erster 1024-Byte Block.
///   - y: Zweiter 1024-Byte Block.
/// - Returns: Das Ergebnis als 1024-Byte Block.
func kompressionGBerechnen(x: Data, y: Data) -> Data {
    // x XOR y
    let R = (x.bigUInt ^ y.bigUInt).serializeLittleEndian().padded(to: 1024, padDirection: .right)
    var Q = [Data]()
    
    // Permutation auf jede Reihe anwenden.
    for i in stride(from: 0, through: 56, by: 8) {
        var inputs: [Data] = [
            R[    i*16..<(i+1)*16],
            R[(i+1)*16..<(i+2)*16],
            R[(i+2)*16..<(i+3)*16],
            R[(i+3)*16..<(i+4)*16],
            R[(i+4)*16..<(i+5)*16],
            R[(i+5)*16..<(i+6)*16],
            R[(i+6)*16..<(i+7)*16],
            R[(i+7)*16..<(i+8)*16]
        ]
        inputs = inputs.map { Data($0) }
        
        Q.append(contentsOf:
            permutationBerechnen(inputs)
        )
        exit(0)
    }
    print(Q)
//
//    // Permutation auf jede Spalte anwenden.
//    for elementIndex in (0...7) {
//        let spalte = matrix.map { $0[elementIndex] }
//        let permutation = permutationBerechnen(eingabeDaten: spalte)
//        for permutationIndex in permutation.indices {
//            matrix[permutationIndex][elementIndex] = permutation[permutationIndex]
//        }
//    }
//
//    // Matrix zusammenführen
//    let z = matrix.reduce(Data()) { $0 + $1.reduce(Data()) { $0 + $1 } }
//
//    // z XOR r
//    let ergebnis = (z.bigUInt ^ R.bigUInt).serializeLittleEndian().padded(to: 1024, padDirection: .right)
//
//    return ergebnis
    return Data(repeating: 100, count: 1024)
}

// MARK: Startwert- und Blockberechnung

/// Der Startwert H0 wird mit H (der BLAKE2b Hashfunktion) gebildet.
///
/// Für die BLAKE2b Funktion wird aktuell eine externe Bibliothek genutzt.
/// - Parameter eingabe: Die Argon2 Eingabewerte.
func startwertH0Berechnen(eingabe: Argon2Eingabewerte) -> Data {
    var blake2b = try! Blake2(.b2b, size: 64)
    
    [eingabe.parallelität,
     eingabe.ausgabelänge,
     eingabe.speichernutzung,
     eingabe.durchgänge,
     eingabe.version,
     eingabe.typ.rawValue
    ].forEach { (element: UInt32) in
        blake2b.update(withUnsafeBytes(of: element.littleEndian) { Data($0) })
    }
    
    blake2b.update(withUnsafeBytes(of: UInt32(eingabe.passwort.utf8.count)) { Data($0) })
    blake2b.update(eingabe.passwort.data(using: .utf8)!)

    blake2b.update(withUnsafeBytes(of: UInt32(eingabe.salt.utf8.count).littleEndian) { Data($0) })
    blake2b.update(eingabe.salt.data(using: .utf8)!)
    
    blake2b.update(withUnsafeBytes(of: UInt32(eingabe.geheimerWert.utf8.count).littleEndian) { Data($0) })
    blake2b.update(eingabe.geheimerWert.data(using: .utf8)!)

    blake2b.update(withUnsafeBytes(of: UInt32(eingabe.zugehörigeDaten.utf8.count).littleEndian) { Data($0) })
    blake2b.update(eingabe.zugehörigeDaten.data(using: .utf8)!)
    
    let h0Data = try! blake2b.finalize()
    print(h0Data.hexWert)
    
    return h0Data
}


/// Diese Funktion berechnet B[i][fürIndexInReihe] für jede Reihe.
///
/// Für die Berechnung wird die H$ Hashfunktion genutzt.
func startBlöckeInMatrixBerechnen(matrix: inout [[Data]], startwertH0: Data) {
    for i in matrix.indices {
        for j in [0, 1] {
            var data = Data()
            data.append(startwertH0)
            data.append(withUnsafeBytes(of: UInt32(j).littleEndian) { Data($0) })
            data.append(withUnsafeBytes(of: UInt32(i).littleEndian) { Data($0) })
            let hash = hashfunktionH$Berechnen(von: data, ausgabelänge: 1024)
            matrix[i][j] = hash
            
//            print("\n\(i) \(j): \(hash.hexWert)\n")
        }
    }
}

/// Berechnet die Position des referenzierten Blockes in der Matrix, welcher als zweiter Wert in die Kompressionsfunktion gegeben wird.
///
/// - Parameter spalteIndex: Der Index der Spalte, für den der Referenzblock ermittlet werden soll. Dieser Index muss im Segment segmentBereiche[segmentIndex] liegen.
func referenzBlockPositionBerechnen(
    matrix: Matrix<Data>, matrixSpaltenAnzahl: Int, durchgang: UInt32, i: Int, j: Int, segmentBereiche: [ClosedRange<Int>], segmentIndex: Int, parallelism: UInt32
) -> (Int, Int) {
    // MARK: J1 & J2
    let previousColumn = matrix[i][negativesModulo(a: j-1, b: matrixSpaltenAnzahl)]
    let J_1 = previousColumn[0...3].uint64.littleEndian
    let J_2 = previousColumn[4...7].uint32.littleEndian

    // MARK: Row l
    let row = segmentIndex == 0 && durchgang == 1 ? i : Int(J_2 % parallelism)

    // MARK: Column z
    var areaSize: Int? = nil
    if durchgang == 1 {
        if row == i {
            areaSize = j - 1
        }
    }
    guard let areaSize = areaSize else { exit(1) }
    
    let x = Int((J_1 * J_1) >> 32)
    let y = (areaSize * x) >> 32
    let relativePosition = areaSize - 1 - y
    
    var startPosition = 0
    startPosition = (startPosition + relativePosition) % matrixSpaltenAnzahl
    
    return (row, startPosition)
}

/// Diese Funktion berechnet alle weiteren Blöcke in der Matrix B[i][j], wobei 0<=i<=p und 2<=j<=Anzahl Spalten.
func weitereBlöckeInMatrixBerechnen(matrix: Matrix<Data>, matrixSpaltenAnzahl: Int, durchgänge: UInt32, parallelism: UInt32) -> Matrix<Data> {
    var matrix = matrix
    let segmentGröße = matrixSpaltenAnzahl / 4
    let segments = (0...3).map {
        ($0*segmentGröße)...(($0+1)*segmentGröße-1)
    }
    
    let dispatchQueue = DispatchQueue.global(qos: .userInitiated)
    let dispatchGroup = DispatchGroup()
    let schloss = NSLock()
    
    for durchgang in 1...durchgänge {
        for segmentIndex in segments.indices {
            var segment = segments[segmentIndex]

            if durchgang == 1, segment.upperBound == 1 {
                continue
            }
            if durchgang == 1, segment.lowerBound == 0 {
                segment = (segment.lowerBound+2)...segment.upperBound
            }
            
            for i in matrix.indices {
//                dispatchGroup.enter()
                
//                dispatchQueue.async {
                    for j in segment {
                        let berechnungSpalte = negativesModulo(a: j-1, b: matrixSpaltenAnzahl)
                        let berechnungBlock = matrix[i][berechnungSpalte] // Block bei B[i][j-1]
                        
                        let referenzBlockPosition = referenzBlockPositionBerechnen(
                            matrix: matrix, matrixSpaltenAnzahl: matrixSpaltenAnzahl, durchgang: durchgang, i: i, j: j, segmentBereiche: segments, segmentIndex: segmentIndex, parallelism: parallelism
                        )

                        print("\(i) \(j): \(referenzBlockPosition)")
                        let referenzBlock = matrix[referenzBlockPosition.0][referenzBlockPosition.1]
                        
                        var ergebnis: Data? = nil
                        if durchgang == 1 {
                            ergebnis = kompressionGBerechnen(x: berechnungBlock, y: referenzBlock)
//                            print(ergebnis!.hexWert)
                        } else {
                            let vorläufigesErgebnis = kompressionGBerechnen(x: berechnungBlock, y: referenzBlock)
                            ergebnis = (BigUInt(vorläufigesErgebnis) ^ BigUInt(matrix[i][j])).serialize()
                        }
                        
                        print()
                        schloss.lock()
                        matrix[i][j] = ergebnis!
                        schloss.unlock()
                    }
//                    dispatchGroup.leave()
//                }
                
            }
            
//            dispatchGroup.wait()
        }
    }
    return matrix
}

/// Fügt alle letzten Blöcke jeder Reihe zusammen, indem die Werte mit XOR kombiniert werden.
/// - Parameter matrix: Die Matrix, in der jedes Element 1024-Byte groß ist.
/// - Returns: Die zusammengeführten 1024-Byte
func matrixFinaleBlöckeZusammenrechnen(matrix: inout Matrix<Data>) -> Data {
    let ergebnis = matrix.reduce(BigUInt(0)) { zwischenErgebnis, reihe in
        zwischenErgebnis ^ BigUInt(reihe.last!)
    }
    return ergebnis.serialize()
}


// MARK: Hashwert berechnen (Koordination)

/// Dies ist die Hauptfunktion, welche die Eingabewerte erhält und den fertigen Hashwert ausgibt.
/// - Parameter eingabe: Die Argon2 Eingabewerte.
func hashwertBerechnen(eingabe: Argon2Eingabewerte) -> Data {
    // MARK: 3.2 (1)
    let startwertH0 = startwertH0Berechnen(eingabe: eingabe)

    // MARK: 3.2 (2)
    // m' = 4 * p * floor (m / 4p)
    // Diese Gleichung rechnet die benötigte Speichermenge für die späteren Berechnungen aus. Dieser Wert ist wohlmöglich
    // unterschiedlich, als die eingegebene Speichermenge. Sie stellt sicher, dass die Menge an Blöcken/Spalten pro Reihe
    // in der später gebildeten zweidimensionalen Matrix durch 4 teilbar ist und, dass jede Reihe gleich viele Spalten besitzt.

    let benötigterSpeicherKiB: UInt32 = ( // Speichermenge in Kibibyte Anzahl
        4 * eingabe.parallelität * (eingabe.speichernutzung / (4 * eingabe.parallelität))
    )
    print(benötigterSpeicherKiB)
    
//    let benötigterSpeicherByte = benötigterSpeicherKiB*1024
//    print("Benötigter Speicher beträgt \(benötigterSpeicherByte) Byte.")
    
    // Matrix erstellen
    let spaltenAnzahl = benötigterSpeicherKiB / eingabe.parallelität
    var matrix: Matrix = (1...eingabe.parallelität).compactMap { _ in
        (1...spaltenAnzahl).compactMap { _ in
            Data(capacity: 1024)
        }
    }
    print(matrix.count, matrix[0].count)
//    print("Zwei dimensionale Matrix aus \(eingabe.parallelität) Reihe(n) mit je \(spaltenAnzahl) Spalten wurde gebildet.")

    // MARK: 3.2 (3) und 3.2 (4)
    startBlöckeInMatrixBerechnen(matrix: &matrix, startwertH0: startwertH0)

    // MARK: 3.2 (5)
    matrix = weitereBlöckeInMatrixBerechnen(matrix: matrix, matrixSpaltenAnzahl: Int(spaltenAnzahl), durchgänge: eingabe.durchgänge, parallelism: eingabe.parallelität)
//
//    let matrixErgebnis = matrixFinaleBlöckeZusammenrechnen(matrix: &matrix)
//    let hashwert = hashfunktionH$Berechnen(von: matrixErgebnis, ausgabelänge: eingabe.ausgabelänge)
//
//    return hashwert
    return Data()
}
