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
        
        var remainingLength = Int(ausgabelänge) - 32
        while remainingLength > 64 {
            v_block = try! Blake2.hash(.b2b, size: 64, data: v_block)
            ergebnis.append(v_block[0..<32])
            remainingLength -= 32
        }
        v_block = try! Blake2.hash(.b2b, size: remainingLength, data: v_block)
        ergebnis.append(v_block[0..<32])
        
        return ergebnis
    }
}


// MARK: Permutation

/// Erstellt die Matrix, die für die Permutation benötigt wird.
/// - Parameter eingabe: Acht 16-Byte Blöcke.
/// - Returns: Eine 4x4 Matrix 8-Byte großen Blöcken.
func permutationMatrixErstellen(eingabeDaten: [Data]) -> Matrix<Data> {
    let summeByteAnzahlEingabeDaten = eingabeDaten.reduce(0) { $0+($1.count) }
    guard !eingabeDaten.isEmpty || eingabeDaten.count == 8 || summeByteAnzahlEingabeDaten == 8*16 else { print("Eingaben zur Erstellung der Matrix für die Permutation sind ungültig."); exit(1) }
    
    var matrix = Matrix<Data>()
    var count = 0
    for eingabe in eingabeDaten {
        let reiheIndex = count%4 == 0 ? matrix.endIndex : matrix.endIndex-1
        if matrix[sicher: reiheIndex] == nil { matrix.insert([], at: reiheIndex) }
        matrix[reiheIndex].append(eingabe[8...15])
        matrix[reiheIndex].append(eingabe[0...7])
        count += 2
    }

    return matrix
}

typealias MatrixEintragPath = WritableKeyPath<Matrix<Data>, Data>
/// Wendet die Permutations auf die Daten an.
/// - Parameter eingabe: Eine Liste von 4 Elementen je 8 Byte groß.
func permutationGBBerechnen(matrix m: inout Matrix<Data>, a aPath: MatrixEintragPath, b bPath: MatrixEintragPath, c cPath: MatrixEintragPath, d dPath: MatrixEintragPath) {
    var (a, b, c, d) = (m[keyPath: aPath].bigUInt, m[keyPath: bPath].bigUInt, m[keyPath: cPath].bigUInt, m[keyPath: dPath].bigUInt)
    
    let zweiHoch64 = BigUInt(2).power(64)
    for durchgang in (1...2) {
        a = ( a + b + 2 * (a.serializeLittleEndian().prefix(4).bigUInt * b.serializeLittleEndian().prefix(4).bigUInt) ) % zweiHoch64
        d = BigUInt((d ^ a).serializeLittleEndian().uint64 >>> (durchgang == 1 ? 32 : 16))
        c = ( c + d + 2 * (c.serializeLittleEndian().prefix(4).bigUInt * d.serializeLittleEndian().prefix(4).bigUInt) ) % zweiHoch64
        b = BigUInt((b ^ c).serializeLittleEndian().uint64 >>> (durchgang == 1 ? 24 : 63))
    }
    
    m[keyPath: aPath] = a.serializeLittleEndian().padded(to: 8, padDirection: .right)
    m[keyPath: bPath] = b.serializeLittleEndian().padded(to: 8, padDirection: .right)
    m[keyPath: cPath] = c.serializeLittleEndian().padded(to: 8, padDirection: .right)
    m[keyPath: dPath] = d.serializeLittleEndian().padded(to: 8, padDirection: .right)
}

/// Führt die Werte aus der Permutations-Matrix wieder zusammen.
/// - Returns: Acht 16-Byte Blöcke.
func permutationMatrixZusammenführen(aus matrix: Matrix<Data>) -> [Data] {
    var ausgabeWerte = [Data]()
    for reihe in matrix {
        for aufgeteilterWert in reihe.aufteilen(jede: 2) {
            ausgabeWerte.append(aufgeteilterWert[1] + aufgeteilterWert[0])
        }
    }
    return ausgabeWerte
}

/// Führt die Argon2 Permutation (von lateinisch permutare 'vertauschen') durch.
/// - Parameter eingabe: Acht 16-Byte Blöcke.
/// mit dem Exit-Code 1.
func permutationBerechnen(eingabeDaten: [Data]) -> [Data] {
    var matrix = permutationMatrixErstellen(eingabeDaten: eingabeDaten)
    typealias M = Matrix<Data>

    permutationGBBerechnen(matrix: &matrix, a: \M[0][0], b: \M[1][0], c: \M[2][0], d: \M[3][0])
    permutationGBBerechnen(matrix: &matrix, a: \M[0][1], b: \M[1][1], c: \M[2][1], d: \M[3][1])
    permutationGBBerechnen(matrix: &matrix, a: \M[0][2], b: \M[1][2], c: \M[2][2], d: \M[3][2])
    permutationGBBerechnen(matrix: &matrix, a: \M[0][3], b: \M[1][3], c: \M[2][3], d: \M[3][3])
    
    permutationGBBerechnen(matrix: &matrix, a: \M[0][0], b: \M[1][1], c: \M[2][2], d: \M[3][3])
    permutationGBBerechnen(matrix: &matrix, a: \M[0][1], b: \M[1][2], c: \M[2][3], d: \M[3][0])
    permutationGBBerechnen(matrix: &matrix, a: \M[0][2], b: \M[1][3], c: \M[2][0], d: \M[3][1])
    permutationGBBerechnen(matrix: &matrix, a: \M[0][3], b: \M[1][0], c: \M[2][1], d: \M[3][2])

    return permutationMatrixZusammenführen(aus: matrix)
}


// MARK: Kompressionsfunktion G

/// Erstellt die Matrix, die für die Kompressionsfunktion gebraucht wird.
/// - Parameter daten: Die 1024-Byte langen Daten.
/// - Returns: Eine 8x8 Matrix mit 16-Byte großen Blöcken.
func kompressionMatrixErstellen(daten: Data) -> Matrix<Data> {
    let aufgeteilteDaten = daten.aufteilen(jede: 16)
    var matrix = Matrix<Data>()
    for reihe in (1...8) {
        matrix.append([])
        let endIndex = (reihe * 8) - 1
        let startIndex = endIndex - 7
        
        for index in startIndex...endIndex {
            let daten = Data(aufgeteilteDaten[index])
            matrix[reihe - 1].append(daten)
        }
    }
    return matrix
}

/// Berechnet den Kompressionswert.
/// - Parameters:
///   - x: Erster 1024-Byte Block.
///   - y: Zweiter 1024-Byte Block.
/// - Returns: Das Ergebnis als 1024-Byte Block.
func kompressionGBerechnen(x: Data, y: Data) -> Data {
    // x XOR y
    let r = (x.bigUInt ^ y.bigUInt).serializeLittleEndian().padded(to: 1024, padDirection: .right)
    
    var matrix = kompressionMatrixErstellen(daten: r)
    
    // Permutation auf jede Reihe anwenden.
    for reiheIndex in matrix.indices {
        matrix[reiheIndex] = permutationBerechnen(eingabeDaten: matrix[reiheIndex])
    }

    // Permutation auf jede Spalte anwenden.
    for elementIndex in (0...7) {
        let spalte = matrix.map { $0[elementIndex] }
        let permutation = permutationBerechnen(eingabeDaten: spalte)
        for permutationIndex in permutation.indices {
            matrix[permutationIndex][elementIndex] = permutation[permutationIndex]
        }
    }
    
    // Matrix zusammenführen
    let z = matrix.reduce(Data()) { $0 + $1.reduce(Data()) { $0 + $1 } }

    // z XOR r
    let ergebnis = (z.bigUInt ^ r.bigUInt).serializeLittleEndian().padded(to: 1024, padDirection: .right)
    
    return ergebnis
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
            matrix[i][0] = hash
            
            print("\n\(i) \(j): \(hash.hexWert)\n")
        }
    }
}

/// Berechnet die Position des referenzierten Blockes in der Matrix, welcher als zweiter Wert in die Kompressionsfunktion gegeben wird.
///
/// - Parameter spalteIndex: Der Index der Spalte, für den der Referenzblock ermittlet werden soll. Dieser Index muss im Segment segmentBereiche[segmentIndex] liegen.
func referenzBlockPositionBerechnen(
    matrix: Matrix<Data>, matrixSpaltenAnzahl: Int, durchgang: UInt32, reiheIndex: Int, spalteIndex: Int, segmentBereiche: [ClosedRange<Int>], segmentIndex: Int
) -> (Int, Int) {
    // J1 und J2 ermitteln.
    let vorherigerBlockSpalte = negativesModulo(a: spalteIndex-1, b: matrixSpaltenAnzahl)
    let vorherigerBlock = matrix[reiheIndex][vorherigerBlockSpalte]

    let J_1 = vorherigerBlock[0...3].uint64
    let J_2 = vorherigerBlock[4...7].uint64

    let reihe = segmentIndex == 0 && durchgang == 1 ? reiheIndex : Int(J_2 % UInt64(matrix.count))

    var spaltenIndizes = [Int]() // Speichert alle möglichen Indizes der Spalten, aus denen später eine ausgewählt wird.

    segmentBereiche.indices.filter { prüfenderSegmentIndex in // Überprüfen, welche Segmente zu den letzten drei Segmenten gehören.
        if durchgang == 1 {
            return prüfenderSegmentIndex >= segmentIndex-3 && prüfenderSegmentIndex < segmentIndex
        } else {
            return prüfenderSegmentIndex >= negativesModulo(a: segmentIndex-3, b: 4) || prüfenderSegmentIndex < segmentIndex
        }
    }.forEach { spaltenIndizes.append(contentsOf: segmentBereiche[$0]) }

    let aktuellesSegment = segmentBereiche[segmentIndex]
    if reihe == reiheIndex {
        spaltenIndizes.append(contentsOf: aktuellesSegment.filter { $0 < (spalteIndex-1) })
    } else {
        if spalteIndex == aktuellesSegment.lowerBound {
            spaltenIndizes.removeLast()
        }
    }

    let indizesMenge: UInt64 = UInt64(spaltenIndizes.count)
    let x = (J_1 * J_1) >> 32
    let y = (indizesMenge * x) >> 32
    let zz = indizesMenge - 1 - y

    let spalte = spaltenIndizes[Int(zz)]

    return (reihe, spalte)
}

/// Diese Funktion berechnet alle weiteren Blöcke in der Matrix B[i][j], wobei 0<=i<=p und 2<=j<=Anzahl Spalten.
func weitereBlöckeInMatrixBerechnen(matrix: Matrix<Data>, matrixSpaltenAnzahl: Int, durchgänge: UInt32) -> Matrix<Data> {
    var matrix = matrix
    let segmentGröße = matrixSpaltenAnzahl / 4
    let segmentBereiche = (0...3).map {
        ($0*segmentGröße)...(($0+1)*segmentGröße-1)
    }
    
    let dispatchQueue = DispatchQueue.global(qos: .userInitiated)
    let dispatchGroup = DispatchGroup()
    let schloss = NSLock()
    
    for durchgang in 1...durchgänge {
        for segmentIndex in segmentBereiche.indices {
//            print("Segment \(segmentIndex) wird berechnet.")
            
            var segmentBereichAbgeändert = segmentBereiche[segmentIndex]
            if durchgang == 1, segmentBereichAbgeändert.upperBound == 1 {
                continue
            }
            if durchgang == 1, segmentBereichAbgeändert.lowerBound == 0 {
                segmentBereichAbgeändert = (segmentBereichAbgeändert.lowerBound+2)...segmentBereichAbgeändert.upperBound
            }
            
            for reiheIndex in matrix.indices {
                dispatchGroup.enter()
                dispatchQueue.async {
                    for spalteIndex in segmentBereichAbgeändert {
                        let berechnungSpalte = negativesModulo(a: spalteIndex-1, b: matrixSpaltenAnzahl)
                        let berechnungBlock = matrix[reiheIndex][berechnungSpalte] // Block bei B[i][j-1]

                        let referenzBlockPosition = referenzBlockPositionBerechnen(
                            matrix: matrix, matrixSpaltenAnzahl: matrixSpaltenAnzahl, durchgang: durchgang, reiheIndex: reiheIndex, spalteIndex: spalteIndex, segmentBereiche: segmentBereiche, segmentIndex: segmentIndex
                        )
                        let referenzBlock = matrix[referenzBlockPosition.0][referenzBlockPosition.1]
                        
                        var ergebnis: Data? = nil
                        if durchgang == 1 {
                            ergebnis = kompressionGBerechnen(x: berechnungBlock, y: referenzBlock)
                        } else {
                            let vorläufigesErgebnis = kompressionGBerechnen(x: berechnungBlock, y: referenzBlock)
                            ergebnis = (BigUInt(vorläufigesErgebnis) ^ BigUInt(matrix[reiheIndex][spalteIndex])).serialize()
                        }
                        
                        schloss.lock()
                        matrix[reiheIndex][spalteIndex] = ergebnis!
                        schloss.unlock()
                    }
                    dispatchGroup.leave()
                }
            }
            
            dispatchGroup.wait()
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
//    matrix = weitereBlöckeInMatrixBerechnen(matrix: matrix, matrixSpaltenAnzahl: Int(spaltenAnzahl), durchgänge: eingabe.durchgänge)
//
//    let matrixErgebnis = matrixFinaleBlöckeZusammenrechnen(matrix: &matrix)
//    let hashwert = hashfunktionH$Berechnen(von: matrixErgebnis, ausgabelänge: Int(eingabe.ausgabelänge))
    
//    return hashwert
    return Data()
}
