//
//  Argon2.swift
//  Argon2
//
//  Created by Léon Becker am 29.12.21.
//

// Based on https://www.rfc-editor.org/rfc/rfc9106.pdf.
// Inspired by https://github.com/bwesterb/argon2pure.

import BigInt
import BitwiseRotate
import Blake2
import Foundation
import Shared

/*
 G: interne Kompressionsfunktion
 GB: Permutationsfunktion
 */


// MARK: Variable length hash function H$ (referenced as H' in RFC)
func calculateH$(of data: Data, tagLength: UInt32) -> Data {
    if tagLength <= 64 {
        var blake2b = try! Blake2(.b2b, size: Int(tagLength))
        blake2b.update(withUnsafeBytes(of: UInt32(tagLength).littleEndian) { Data($0) })
        blake2b.update(data)
        return try! blake2b.finalize()
    } else {
        var result = Data()
        
        var blake2b = try! Blake2(.b2b, size: 64)
        blake2b.update(withUnsafeBytes(of: UInt32(tagLength).littleEndian) { Data($0) })
        blake2b.update(data)
        var v_block = try! blake2b.finalize()
        result.append(v_block[0..<32])
        
        var remainingLength = Int(tagLength)-32
        while remainingLength > 64 {
            v_block = try! Blake2.hash(.b2b, size: 64, data: v_block)
            result.append(v_block[0..<32])
            remainingLength -= 32
        }

        v_block = try! Blake2.hash(.b2b, size: remainingLength, data: v_block)
        result.append(v_block)
        return result
    }
}

// MARK: Permutation
func calculatePermutationGB(_ v: inout [BigUInt], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
    let twoPower64 = BigUInt(2).power(64)
    for round in (1...2) {
        v[a] = (v[a] + v[b] + 2 * (v[a].serializeLittleEndian().prefix(4).bigUInt * v[b].serializeLittleEndian().prefix(4).bigUInt) ) % twoPower64
        v[d] = BigUInt((v[d] ^ v[a]).serializeLittleEndian().uint64 >>> (round == 1 ? 32 : 16))
        v[c] = (v[c] + v[d] + 2 * (v[c].serializeLittleEndian().prefix(4).bigUInt * v[d].serializeLittleEndian().prefix(4).bigUInt) ) % twoPower64
        v[b] = BigUInt((v[b] ^ v[c]).serializeLittleEndian().uint64 >>> (round == 1 ? 24 : 63))
    }
}

/// - Parameter data: Eight 16-Byte blocks.
func calculatePermutation(_ data: [Data]) -> [Data] {
    var v = [BigUInt]()
    for i in 0...7 {
        v.append(data[i][0...7].bigUInt)
        v.append(data[i][8...15].bigUInt)
    }

    calculatePermutationGB(&v, 0, 4, 8, 12)
    calculatePermutationGB(&v, 1, 5, 9, 13)
    calculatePermutationGB(&v, 2, 6, 10, 14)
    calculatePermutationGB(&v, 3, 7, 11, 15)

    calculatePermutationGB(&v, 0, 5, 10, 15)
    calculatePermutationGB(&v, 1, 6, 11, 12)
    calculatePermutationGB(&v, 2, 7, 8, 13)
    calculatePermutationGB(&v, 3, 4, 9, 14)

    let result = (0...7).map { i -> Data in
        [v[2*i], v[2*i+1]]
            .map { $0.serializeLittleEndian() }
            .map { $0.padded(to: 8, padDirection: .right) }
            .reduce(Data()) { $0 + $1 }
    }

    return result
}

/// - Parameters:
///   - x: First 1024-byte block.
///   - y: Second 1024-byte block.
func calculateCompression(x: Data, y: Data) -> Data {
    // x XOR y
    let RInt = (BigUInt(x) ^ BigUInt(y))
    let R = RInt.serialize().padded(to: 1024, padDirection: .left)
    
    // Apply permutation on each row.
    var Q = [Data]()
    for l in stride(from: 0, through: 56, by: 8) {
        var inputs = [Data]()
        for m in 0...7 {
            inputs.append(
                R[(l+m)*16..<(l+m+1)*16]
            )
        }

        inputs = inputs.map { Data($0) }
        
        Q.append(contentsOf:
            calculatePermutation(inputs)
        )
    }

    // Apply permutation on each column.
    var Z = Array(repeating: Data(), count: 64)
    for l in 0...7 {
        var inputs = [Data]()
        for m in 0...7 {
            inputs.append(Q[l+m*8])
        }
        
        let permutation = calculatePermutation(inputs)
        
        for m in 0...7 {
            Z[l+m*8] = permutation[m]
        }
    }

    let ZInt = BigUInt(Z.reduce(Data()) { $0 + $1 })
    
    let result = (RInt ^ ZInt).serialize().padded(to: 1024, padDirection: .left)
    
    return result
}

// MARK: H0 and block calculation
func calculateH0(context: Argon2Context) -> Data {
    var blake2b = try! Blake2(.b2b, size: 64)
    
    [context.parallelism,
     context.tagLength,
     context.memoryCost,
     context.timeCost,
     context.version,
     context.type.rawValue
    ].forEach { (element: UInt32) in
        blake2b.update(withUnsafeBytes(of: element.littleEndian) { Data($0) })
    }
    
    blake2b.update(withUnsafeBytes(of: UInt32(context.password.utf8.count)) { Data($0) })
    blake2b.update(context.password.data(using: .utf8)!)

    blake2b.update(withUnsafeBytes(of: UInt32(context.salt.utf8.count).littleEndian) { Data($0) })
    blake2b.update(context.salt.data(using: .utf8)!)
    
    blake2b.update(withUnsafeBytes(of: UInt32(context.secret.utf8.count).littleEndian) { Data($0) })
    blake2b.update(context.secret.data(using: .utf8)!)

    blake2b.update(withUnsafeBytes(of: UInt32(context.associatedData.utf8.count).littleEndian) { Data($0) })
    blake2b.update(context.associatedData.data(using: .utf8)!)
    
    let h0Data = try! blake2b.finalize()
    
    return h0Data
}


/// Calculates B[i][0] and B[i][1] for each lane.
func calculateStartingBlocks(matrix: inout [[Data]], H0: Data) {
    for i in matrix.indices {
        for j in [0, 1] {
            var data = Data()
            data.append(H0)
            data.append(withUnsafeBytes(of: UInt32(j).littleEndian) { Data($0) })
            data.append(withUnsafeBytes(of: UInt32(i).littleEndian) { Data($0) })
            
            let hash = calculateH$(of: data, tagLength: 1024)
            matrix[i][j] = hash
        }
    }
}

func calculateReferenceBlockPosition(
    matrix: Matrix<Data>, i: Int, j: Int, columnCount: Int, round: UInt32, sliceIndex: Int, segmentLength: Int, indexInSegment: Int, parallelism: UInt32
) -> (Int, Int) {
    // MARK: J1 & J2
    let previousColumn = matrix[i][negativeModulo(a: j-1, b: columnCount)]
    let J_1 = previousColumn[0...3].uint64.littleEndian
    let J_2 = previousColumn[4...7].uint64.littleEndian

    // MARK: Row l

    let row = sliceIndex == 0 && round == 1 ? i : Int(J_2 % UInt64(parallelism))

    // MARK: Column z
    var areaSize: Int? = nil
    
    // +1 is needed, as the index (which starts at 0) needs to be converted to the count/area size (which starts at 1).
    if round == 1 {
        if row == i {
            areaSize = j - 2 + 1
        } else if indexInSegment == 0 {
            areaSize = sliceIndex * segmentLength - 2 + 1
        } else {
            areaSize = sliceIndex * segmentLength - 1 + 1
        }
    } else {
        if row == i {
            areaSize = 3 * segmentLength - 1 + indexInSegment - 1 + 1
        } else if indexInSegment == 0 {
            areaSize = 3 * segmentLength - 2 + 1
        } else {
            areaSize = 3 * segmentLength - 1 + 1
        }
    }
    guard let areaSize = areaSize else { exit(1) }

    let x = Int((J_1 * J_1) >> 32)
    let y = (areaSize * x) >> 32
    let relativePosition = areaSize - 1 - y
    
    var startPosition = 0
    if round != 1, sliceIndex != 3 {
        startPosition = (sliceIndex + 1) * segmentLength
    }
    let column = (startPosition + relativePosition) % columnCount

    return (row, column)
}

func calculateRemainingBlocks(matrix: Matrix<Data>, columnCount: Int, timeCost: UInt32, parallelism: UInt32) -> Matrix<Data> {
    var matrix = matrix
    let segmentLength = columnCount / 4
    
    let dispatchQueue = DispatchQueue.global(qos: .userInitiated)
    let dispatchGroup = DispatchGroup()
    let lock = NSLock()
    
    for round in 1...timeCost {
        for sliceIndex in 0...3 {
            if round == 1, sliceIndex == 0, segmentLength == 2 {
                continue
            }
            
            for i in matrix.indices {
                dispatchGroup.enter()
                
                dispatchQueue.async {
                    for indexInSegment in 0..<segmentLength {
                        let j = sliceIndex * segmentLength + indexInSegment
                        if j < 2, round == 1 {
                            continue
                        }
                        let calculationBlock = matrix[i][negativeModulo(a: j-1, b: columnCount)]
                        
                        let referenceBlockPosition = calculateReferenceBlockPosition(matrix: matrix, i: i, j: j, columnCount: columnCount, round: round, sliceIndex: sliceIndex, segmentLength: segmentLength, indexInSegment: indexInSegment, parallelism: parallelism)
                        let referenceBlock = matrix[referenceBlockPosition.0][referenceBlockPosition.1]
                        
                        var result = calculateCompression(x: calculationBlock, y: referenceBlock)
                        if round != 0 {
                            result = (BigUInt(result) ^ BigUInt(matrix[i][j])).serialize().padded(to: 1024, padDirection: .left)
                        }
                        
                        lock.lock()
                        matrix[i][j] = result
                        lock.unlock()
                    }
                    dispatchGroup.leave()
                }
            }
            dispatchGroup.wait()
        }
    }
    return matrix
}

// MARK: Argon2 inputs
public enum Argon2Type: UInt32 {
    case argon2d = 0
//    case argon2i = 1
//    case argon2id = 2
    
}

public class Argon2Context {
    public let password: String
    public let salt: String
    public let parallelism: UInt32
    public let tagLength: UInt32 // in Byte
    public let memoryCost: UInt32 // in Kibibyte
    public let timeCost: UInt32
    public let secret: String
    public let associatedData: String
    public let version: UInt32 = 0x13
    public let type: Argon2Type
    
    public init(password: String, salt: String, type: Argon2Type, parallelism: UInt32, tagLength: UInt32, memoryCost: UInt32, timeCost: UInt32, secret: String?, associatedData: String?) {
        self.password = password
        self.salt = salt
        self.parallelism = parallelism
        self.tagLength = tagLength
        self.memoryCost = memoryCost
        self.timeCost = timeCost
        self.secret = secret ?? ""
        self.associatedData = associatedData ?? ""
        self.type = type
    }
}

// MARK: Hashwert berechnen (Koordination)
public func calculateHash(_ context: Argon2Context) -> Data {
    // Implementation from https://www.rfc-editor.org/rfc/rfc9106.pdf.
    
    // MARK: 3.2 (1)
    let H0 = calculateH0(context: context)

    // MARK: 3.2 (2)
    let requiredMemoryKiB: UInt32 = (
        4 * context.parallelism * (context.memoryCost / (4 * context.parallelism))
    )
    
    // Create the matrix
    let columnCount = requiredMemoryKiB / context.parallelism
    var matrix: Matrix = (1...context.parallelism).compactMap { _ in
        (1...columnCount).compactMap { _ in
            Data(capacity: 1024)
        }
    }

    // MARK: 3.2 (3, 4)
    calculateStartingBlocks(matrix: &matrix, H0: H0)

    // MARK: 3.2 (5, 6)
    matrix = calculateRemainingBlocks(matrix: matrix, columnCount: Int(columnCount), timeCost: context.timeCost, parallelism: context.parallelism)

    // MARK: 3.2 (7)
    let combinedLastColumns = matrix
        .map { $0[Int(columnCount)-1] }
        .map { BigUInt($0) }
        .reduce(BigUInt()) { $0 ^ $1 }
        .serialize()
    
    // MARK: 3.2 (8)
    let hash = calculateH$(of: combinedLastColumns, tagLength: context.tagLength)

    return hash
}
