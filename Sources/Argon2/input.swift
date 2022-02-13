//
//  main.swift
//  
//
//  Created by Léon Becker on 28.12.21.
//

import Foundation

public enum Argon2Typ: UInt32 {
    case argon2d = 0
    case argon2i = 1
    case argon2id = 2
    
}

public struct Argon2Eingabewerte {
    /*
     P: Passwort
     S: Salt
     p: Parallelität
     T: Ausgabelänge (tag length)
     m: Speichernutzung (memory size)
     t: Durchgänge
     v: Versionsnummer
     y: Argon2-Typ
     */
    
    public let passwort: String
    public let salt: String
    public let parallelität: UInt32
    public let ausgabelänge: UInt32 // in Byte
    public let speichernutzung: UInt32 // in Kibibyte
    public let durchgänge: UInt32
    public let geheimerWert: String = ""
    public let zugehörigeDaten: String = ""
    public let version: UInt32 = 0x13
    public let typ: Argon2Typ = .argon2d
    
    public init(passwort: String, salt: String, parallelität: UInt32, ausgabelänge: UInt32, speichernutzung: UInt32, durchgänge: UInt32) {
        self.passwort = passwort
        self.salt = salt
        self.parallelität = parallelität
        self.ausgabelänge = ausgabelänge
        self.speichernutzung = speichernutzung
        self.durchgänge = durchgänge
    }
}
