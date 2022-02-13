//
//  Hilfsmittel.swift
//  
//
//  Created by Léon Becker on 31.12.21.
//

import Foundation
import BigInt

// MARK: Erweiterung Collection
extension Collection {
    public subscript (sicher index: Index) -> Element? {
        return indices.contains(index) ? self[index] : nil
    }

    public func aufteilen(jede größe: UInt) -> [[Element]] {
        var ergebnis = [[Element]]()
        for (elementIndex, element) in self.enumerated() {
            let index = Int(floor(Double(elementIndex) / Double(größe)))
            if ergebnis[sicher: index] == nil {
                ergebnis.insert([], at: index)
            }
            ergebnis[index].append(element)
        }
        return ergebnis
    }
}

// MARK: Andere Erweiterungen Data
extension Data {
    /// Der Hexwert von den Daten.
    public var hexWert: String {
        return self.map { String(format: "%02X", $0) }.joined()
    }

    /// Die zugrunde liegenden Daten werden als UInt64 gelesen.
    public var uint64: UInt64 {
        self.padded(to: 8, padDirection: .right).withUnsafeBytes { $0.load(as: UInt64.self) }
    }
    
    /// Die zugrunde liegenden Daten werden als UInt32 gelesen.
    public var uint32: UInt32 {
        self.withUnsafeBytes { $0.load(as: UInt32.self) }
    }
    
    /// Die zugrunde liegenden Daten werden als BigUInt gelesen.
    public var bigUInt: BigUInt {
        // BigUInt kann die Daten nur in big-endian lesen, weshalb sie vorher von little-endian in dieses umgewandelt werden müssen.
        BigUInt(Data(self.reversed()))
    }
    
    public enum PadDirection { case right, left }
    public func padded(to bytesCount: Int, padDirection: PadDirection) -> Data {
        var data = self
        let missingBytesCount = bytesCount - data.count
        guard missingBytesCount > 0 else { return data }
        
        let missingBytes: [UInt8] = Array(repeating: 0, count: missingBytesCount)
        switch padDirection {
        case .right:
            data.append(contentsOf: missingBytes)
        case .left:
            data.insert(contentsOf: missingBytes, at: 0)
        }
        return data
    }
}

// MARK: BigUInt Erweiterungen
extension BigUInt {
    public func serializeLittleEndian() -> Data {
        let data = self.serialize()
        return Data(data.reversed())
    }
}

// MARK: Erweiterung Array
extension Array where Element == [Data] {
    /// Dies gibt eine Darstellung einer zweidimensionalen Matrix formattiert in einem String zurück.
    ///
    /// Dies eignet sich gut, um eine Matrix in die Kommandozeile auszugeben.
    /// - Parameter matrix: Die Matrix.
    /// - Returns: Die Matrix-Darsellung als String.
    public var matrixStringDarstellung: String {
        var ausgabeString = ""
        for reiheIndex in self.indices {
            if reiheIndex != 0 {
                ausgabeString += "\n"
            }
            ausgabeString += "Reihe \(reiheIndex): "
            for spalte in self[reiheIndex] {
                ausgabeString += "[\(spalte.hexWert)]" + String(repeating: " ", count: 1) // 12*" " wird für bessere Lessbarkeit hinzugefügt.
            }
        }
        return ausgabeString
    }
}

// MARK: Matrix
public typealias Matrix<T> = [[T]]

// MARK: Modulo
public func negativeModulo(a: Int, b: Int) -> Int {
    let ergebnis = a % b
    return ergebnis < 0 ? b + ergebnis : ergebnis
}

// MARK: Zeit messen
public func measureTime<T>(_ codeBlock: () -> (T)) -> (TimeInterval, T) {
    let startZeit = Date()
    let ausgabe = codeBlock()
    let endZeit = Date()
    let timeDifference = endZeit.timeIntervalSince(startZeit)
    return (timeDifference, ausgabe)
}


extension String {
    
    /// Create `Data` from hexadecimal string representation
    ///
    /// This creates a `Data` object from hex string. Note, if the string has any spaces or non-hex characters (e.g. starts with '<' and with a '>'), those are ignored and only hex characters are processed.
    ///
    /// - returns: Data represented by this hexadecimal string.
    
    public var hexadecimal: Data? {
        var data = Data(capacity: count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }
        
        guard data.count > 0 else { return nil }
        
        return data
    }
    
}

// MARK: FileHandle
public var standardError = FileHandle.standardError

extension FileHandle: TextOutputStream {
  public func write(_ string: String) {
    let data = Data(string.utf8)
    self.write(data)
  }
}
