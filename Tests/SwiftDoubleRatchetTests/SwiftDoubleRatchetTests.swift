import Crypto
import XCTest

@testable import SwiftDoubleRatchet

extension Data {
    init(randomLength: UInt) {
        self = .init(capacity: Int(randomLength))
        for _ in 0..<randomLength {
            self.append(contentsOf: [.random(in: UInt8.min...UInt8.max)])
        }
    }
}

final class SwiftDoubleRatchetTests: XCTestCase {
    
    func testHeaderEncodeDecode() throws {
        let privateKey = Crypto.Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        let header = Ratchet<Curve25519.KeyAgreement>.Header.init(
            publicKey: publicKeyData, PN: 100, Ns: 50)
        let headerBytes = header.encoded
        let decoded = try Ratchet<Curve25519.KeyAgreement>.Header.init(data: headerBytes)
        XCTAssertEqual(decoded, header, "Decoded and encoded are not equal")
    }
    
    func testBasicCurve25519() throws {
        let aPrivate = Curve25519.KeyAgreement.Prv.init()
        let bPrivate = Curve25519.KeyAgreement.Prv.init()
        let shared = try aPrivate.aggreement(pub: bPrivate.publicKey)
        var bobRatchet = try Ratchet<Curve25519.KeyAgreement>.init(sk: .init(data: shared))
        var aliceRatchet = try Ratchet<Curve25519.KeyAgreement>.init(
            sk: .init(data: shared), bobPublicKey: bobRatchet.sendingPublicKey)
        let message = Data.init(randomLength: 100)
        let ad = Data.init(randomLength: 10)
        let (header, encrypted) = try aliceRatchet.ratchetEncrypt(plaintext: message, ad: ad)
        let decrypted = try bobRatchet.ratchetDecrypt(header: header, ciphertext: encrypted, ad: ad)
        XCTAssertEqual(decrypted, message, "decrypted message and encrypted message are not equal")
    }
    
    func testBasicP256() throws {
        let aPrivate = P256.KeyAgreement.Prv.init()
        let bPrivate = P256.KeyAgreement.Prv.init()
        let shared = try aPrivate.aggreement(pub: bPrivate.publicKey)
        var bobRatchet = try Ratchet<P256.KeyAgreement>.init(sk: .init(data: shared))
        var aliceRatchet = try Ratchet<P256.KeyAgreement>.init(
            sk: .init(data: shared), bobPublicKey: bobRatchet.sendingPublicKey)
        let message = Data.init(randomLength: 100)
        let ad = Data.init(randomLength: 10)
        let (header, encrypted) = try aliceRatchet.ratchetEncrypt(plaintext: message, ad: ad)
        let decrypted = try bobRatchet.ratchetDecrypt(header: header, ciphertext: encrypted, ad: ad)
        XCTAssertEqual(decrypted, message, "decrypted message and encrypted message are not equal")
    }
}
