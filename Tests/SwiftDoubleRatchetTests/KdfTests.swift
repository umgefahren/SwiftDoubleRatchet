//
//  File.swift
//
//
//  Created by Hannes Furmans on 03.07.22.
//

import Crypto
import Foundation
import XCTest

@testable import SwiftDoubleRatchet

final class KdfTests: XCTestCase {
    func testKdfRk() throws {
        let privateA = Curve25519.KeyAgreement.PrivateKey.init()
        let privateB = Curve25519.KeyAgreement.PrivateKey.init()
        let shared = try privateA.sharedSecretFromKeyAgreement(with: privateB.publicKey)
        
        let (rk, ck) = kdfRk(
            rk: SymmetricKey(data: Data(count: 32)), dhOut: shared, info: Data.init(count: 32))
        XCTAssertEqual(rk.bitCount / 8, 32, "Root Key is of invalid length")
        XCTAssertEqual(ck.bitCount / 8, 32, "Chain Key is of invalid length")
    }
    
    func testKdfCk() throws {
        let (ck, mk) = kdfCk(ck: .init(data: Data(count: 32)))
        XCTAssertEqual(ck.bitCount / 8, 32, "Chain key is of invalid length")
        XCTAssertEqual(mk.bitCount / 8, 32, "Message key is of invalid length")
    }
}
