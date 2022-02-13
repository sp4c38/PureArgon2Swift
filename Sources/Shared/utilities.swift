//
//  Hilfsmittel.swift
//  
//
//  Created by Léon Becker on 31.12.21.
//

import Foundation
import BigInt

extension Data {
    public var hex: String {
        return self.map { String(format: "%02X", $0) }.joined()
    }

    /// The underlying data interpreted as an UInt64.
    ///
    /// The number will be different depending if the machine runs in little-endian or in big-endian.
    public var uint64: UInt64 {
        self.padded(to: 8, padDirection: .dependingOnEndian).withUnsafeBytes { $0.load(as: UInt64.self) }
    }
    
    /// The underlying data interpreted as an UInt32.
    public var uint32: UInt32 {
        self.padded(to: 4, padDirection: .dependingOnEndian).withUnsafeBytes { $0.load(as: UInt32.self) }
    }
    
    /// The underlying data interpreted as an BigUInt.
    public var bigUInt: BigUInt {
        if CFByteOrderGetCurrent() == CFByteOrderBigEndian.rawValue {
            return BigUInt(self)
        } else {
            return BigUInt(Data(self.reversed()))
        }
    }
    
    public enum PadDirection { case right, left, dependingOnEndian }
    public func padded(to bytesCount: Int, padDirection: PadDirection) -> Data {
        var data = self
        let missingBytesCount = bytesCount - data.count
        guard missingBytesCount > 0 else { return data }
        
        let missingBytes: [UInt8] = Array(repeating: 0, count: missingBytesCount)
        
        if padDirection == .right || (padDirection == .dependingOnEndian && CFByteOrderGetCurrent() == CFByteOrderLittleEndian.rawValue) {
            data.append(contentsOf: missingBytes)
        } else if padDirection == .left || (padDirection == .dependingOnEndian && CFByteOrderGetCurrent() == CFByteOrderBigEndian.rawValue) {
            data.insert(contentsOf: missingBytes, at: 0)
        }
        return data
    }
}

extension BigUInt {
    public func serializeLittleEndian() -> Data {
        let data = self.serialize()
        return Data(data.reversed())
    }
}

public typealias Matrix<T> = [[T]]

extension Array where Element == [Data] {
    /// Returns a representation of a matrix as a string.
    public var matrixStringDisplay: String {
        var result = ""
        for rowIndex in self.indices {
            if rowIndex != 0 {
                result += "\n"
            }
            result += "Reihe \(rowIndex): "
            for column in self[rowIndex] {
                result += "[\(column.hex)]" + String(repeating: " ", count: 1) // 12*" " wird für bessere Lessbarkeit hinzugefügt.
            }
        }
        return result
    }
}

public func negativeModulo(a: Int, b: Int) -> Int {
    let result = a % b
    return result < 0 ? b + result : result
}

public func measureTime<T>(_ codeBlock: () -> (T)) -> (TimeInterval, T) {
    let startTime = Date()
    let result = codeBlock()
    let endTime = Date()
    let timeDifference = endTime.timeIntervalSince(startTime)
    return (timeDifference, result)
}

public var standardError = FileHandle.standardError

extension FileHandle: TextOutputStream {
  public func write(_ string: String) {
    let data = Data(string.utf8)
    self.write(data)
  }
}
