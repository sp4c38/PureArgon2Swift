//
//  main.swift
//  
//
//  Created by Léon Becker on 28.12.21.
//

import Foundation

enum Argon2Typ: UInt32 {
    case argon2d = 0
    case argon2i = 1
    case argon2id = 2
    
}

struct Argon2Eingabewerte {
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
    
    let passwort: String
    let salt: String
    let parallelität: UInt32
    let ausgabelänge: UInt32 // in Byte
    let speichernutzung: UInt32 // in Kibibyte
    let durchgänge: UInt32
    let geheimerWert: String = ""
    let zugehörigeDaten: String = ""
    let version: UInt32 = 0x13
    let typ: Argon2Typ = .argon2d
}

/// Liest die Eingabe von den Kommandozeile-Argumenten.
func eingabeVonKommandozeileLesen() -> Argon2Eingabewerte? {
//    Bitte geben Sie das Passwort *P* ein:
//    Bitte geben Sie den Salt *S* ein, den Sie für das Passwort nutzen möchten:
//    Bitte geben Sie den Grad an Parallelität *p* ein (1 <= p <= 2^(24)-1)
//    Bitte geben Sie die Länge des ausgegebenen Hashwertes *T* in Byte an (4 <= T <= 2^(32)-1)
//    Bitte geben Sie die Menge an Speicher *m* in Kibibytes an, die genutzt werden soll (8*p <= m <= 2^(32)-1)

    guard CommandLine.arguments.count > 1, CommandLine.arguments[1] == "eingabe" else { return nil }
    
    var passwort: String? = nil
    var salt: String? = nil
    var parallelität: UInt32? = nil
    var ausgabelänge: UInt32? = nil
    var speichernutzung: UInt32? = nil
    var durchgänge: UInt32? = nil
    
    for eingabe in CommandLine.arguments.dropFirst(2) {
        let eingabeGeteilt = eingabe.split(separator: ":")
        guard eingabeGeteilt.count == 2 else { return nil }
        
        if "passwort" == eingabeGeteilt[0] {
            passwort = String(eingabeGeteilt[1])
        
        } else if "salt" == eingabeGeteilt[0] {
            salt = String(eingabeGeteilt[1])
            
        } else if "parallelität" == eingabeGeteilt[0] {
            parallelität = UInt32(eingabeGeteilt[1])
        
        } else if "ausgabelänge" == eingabeGeteilt[0] {
            ausgabelänge = UInt32(eingabeGeteilt[1])
        
        } else if "speichernutzung" == eingabeGeteilt[0] {
            speichernutzung = UInt32(eingabeGeteilt[1])
        
        } else if "durchgänge" == eingabeGeteilt[0] {
            durchgänge = UInt32(eingabeGeteilt[1])
        }
    }
    
    guard let passwort = passwort, let salt = salt, let parallelität = parallelität, let ausgabelänge = ausgabelänge, let speichernutzung = speichernutzung, let durchgänge = durchgänge else {
        return nil
    }
    
    return Argon2Eingabewerte(
        passwort: passwort,
        salt: salt,
        parallelität: parallelität,
        ausgabelänge: ausgabelänge,
        speichernutzung: speichernutzung,
        durchgänge: durchgänge
    )
}
import Blake2
func main() {    
//    guard let eingabe = eingabeVonKommandozeileLesen() else {
//        print("Eingabe ist ungültig.")
//        exit(1)
//    }
    
    let eingabe = Argon2Eingabewerte(passwort: "Passwort", salt: "Salt12345", parallelität: 1, ausgabelänge: 64, speichernutzung: 8, durchgänge: 1)

    let hashwert = Argon2.hashwertBerechnen(eingabe: eingabe)

    var ausgabe = ""
    ausgabe += "$argon2i$"
    ausgabe += "v=19$"
    ausgabe += "m=\(eingabe.speichernutzung),"
    ausgabe += "t=\(eingabe.durchgänge),"
    ausgabe += "p=\(eingabe.parallelität)$"
    ausgabe += "\(eingabe.salt.data(using: .utf8)!.base64EncodedString())$"
    ausgabe += "\(hashwert.base64EncodedString())"

    print("Hash: \(hashwert.hexWert)")
    print("{\"hash\": \"\(ausgabe)\"}")
}

main()
