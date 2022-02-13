//
//  File.swift
//  
//
//  Created by Léon Becker on 13.02.22.
//

import Argon2
import Foundation
//import Shared

/// Liest die Eingabe von den Kommandozeile-Argumenten.
func eingabeVonKommandozeileLesen() -> Argon2Eingabewerte? {
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
        
        if "password" == eingabeGeteilt[0] {
            passwort = String(eingabeGeteilt[1])
        
        } else if "salt" == eingabeGeteilt[0] {
            salt = String(eingabeGeteilt[1])
            
        } else if "parallelism" == eingabeGeteilt[0] {
            parallelität = UInt32(eingabeGeteilt[1])
        
        } else if "tagLength" == eingabeGeteilt[0] {
            ausgabelänge = UInt32(eingabeGeteilt[1])
        
        } else if "memoryCost" == eingabeGeteilt[0] {
            speichernutzung = UInt32(eingabeGeteilt[1])
        
        } else if "timeCost" == eingabeGeteilt[0] {
            durchgänge = UInt32(eingabeGeteilt[1])
            
        } else {
            print("Input \(eingabe) invalid.")
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


func main() {
    guard let eingabe = eingabeVonKommandozeileLesen() else {
        exit(1)
    }

    let hashwert = Argon2.hashwertBerechnen(eingabe: eingabe)

    var ausgabe = ""
    ausgabe += "$argon2d$"
    ausgabe += "v=19$"
    ausgabe += "m=\(eingabe.speichernutzung),"
    ausgabe += "t=\(eingabe.durchgänge),"
    ausgabe += "p=\(eingabe.parallelität)$"
    ausgabe += "\(eingabe.salt.data(using: .utf8)!.base64EncodedString().replacingOccurrences(of: "=", with: ""))$"
    ausgabe += "\(hashwert.base64EncodedString().replacingOccurrences(of: "=", with: ""))"

    print("Hash: \(hashwert.hexWert.lowercased())")
    print("{\"hash\": \"\(ausgabe)\"}")
}

main()
