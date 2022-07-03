//
//  File.swift
//  
//
//  Created by Hannes Furmans on 03.07.22.
//

import Foundation
import XCTest
import Crypto
@testable import SwiftDoubleRatchet

final class AeadTests: XCTestCase {
    func testEncryptDecrypt() throws {
        let keyData = Data.init(count: 32)
        let key = SymmetricKey.init(data: keyData)
        let plaintext = Data.init(count: .random(in: 0...500))
        let ad = Data.init(count: .random(in: 0...500))
        let encrypted = try encrypt(mk: key, plaintext: plaintext, ad: ad)
        let decrypted = try decrypt(mk: key, ciphertext: encrypted, ad: ad)
        XCTAssertEqual(decrypted, plaintext, "Decryption failed")
    }
}
