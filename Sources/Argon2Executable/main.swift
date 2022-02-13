//
//  File.swift
//  
//
//  Created by Léon Becker on 13.02.22.
//

import Argon2
import ArgumentParser
import Foundation
import Shared

public enum Argon2TypeParameter: UInt32, EnumerableFlag {
    case argon2d = 0
    
    func toArgon2Type() -> Argon2Type {
        switch self {
        case .argon2d:
            return Argon2Type.argon2d
        }
    }
    
    static func fromArgon2Type(_ type: Argon2Type) -> Argon2TypeParameter {
        switch type {
        case .argon2d:
            return Argon2TypeParameter.argon2d
        }
    }
    
    func toString() -> String {
        switch self {
        case .argon2d:
            return "Argon2d"
        }
    }
}

struct Argon2CommandLineUtility: ParsableCommand {
    @Flag(exclusivity: .exclusive, help: "Sets the Argon2 type (default argon2d)")
    var argon2TypeParameter: Argon2TypeParameter?
    
    @Option(name: .short, help: "Sets the number of iterations to N (default 3)")
    var timeCost: UInt32?
    
    @Option(name: .short, help: "Sets the memory usage of 2^N KiB (default 12)")
    var memoryCostPower2: UInt32?
    
    @Option(name: .short, help: "Sets the memory usage of N KiB (default 4096)")
    var kibMemoryCost: UInt32?
    
    @Option(name: .short, help: "Sets parallelism to N threads (default 1)")
    var parallelism: UInt32?
    
    @Option(name: .short, help: "Sets hash output length to N bytes (default 32)")
    var lengthOutput: UInt32?
    
    @Option(name: .short, help: "Includes a secret in the hash calculation")
    var secret: String?
    
    @Option(name: .short, help: "Includes associated data in the hash calculation")
    var associatedData: String?
    
    @Argument(help: "The salt to use, at least 8 characters.")
    var salt: String
    
    func processInputs() -> Argon2Context? {
        let timeCost = timeCost ?? 3
        let parallelism = parallelism ?? 1
        let tagLength = lengthOutput ?? 32
        let type = argon2TypeParameter?.toArgon2Type() ?? .argon2d
        
        var memoryCost: UInt32
        if let memoryCostPower2 = memoryCostPower2 {
            memoryCost = UInt32(pow(Double(2), Double(memoryCostPower2)))
        } else if let kibMemoryCost = kibMemoryCost {
            memoryCost = kibMemoryCost
        } else  {
            memoryCost = 4096
        }
        
        guard let password = readLine() else { print("Password is invalid.", to: &standardError); return nil }
        
        let context = Argon2Context(password: password, salt: salt, type: type, parallelism: parallelism, tagLength: tagLength, memoryCost: memoryCost, timeCost: timeCost, secret: secret, associatedData: associatedData)
        return context
    }
    
    func run() throws {
        guard let context = processInputs() else { return }
        
        let (time, hash): (TimeInterval, Data) = measureTime {
            Argon2.calculateHash(context)
        }

        var encodedHash = ""
        encodedHash += "$argon2d$"
        encodedHash += "v=19$"
        encodedHash += "m=\(context.memoryCost),"
        encodedHash += "t=\(context.timeCost),"
        encodedHash += "p=\(context.parallelism)$"
        encodedHash += "\(context.salt.data(using: .utf8)!.base64EncodedString().replacingOccurrences(of: "=", with: ""))$"
        encodedHash += "\(hash.base64EncodedString().replacingOccurrences(of: "=", with: ""))"
        
        print("Type: \(Argon2TypeParameter.fromArgon2Type(context.type).toString())")
        print("Iterations: \(context.timeCost)")
        print("Memory: \(context.memoryCost) KiB")
        print("Parallelism: \(context.parallelism)")
        print("Hash: \(hash.hexWert.lowercased())")
        print("Encoded: \(encodedHash)")
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.minimumFractionDigits = 3
        formatter.decimalSeparator = "."
        print("\(formatter.string(from: NSNumber(value: time)) ?? "nil") seconds")
    }
}

Argon2CommandLineUtility.main()
