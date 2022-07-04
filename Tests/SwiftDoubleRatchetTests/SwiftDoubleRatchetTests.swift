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
    
    func testManyCurve25519() throws {
        let aPrivate = Curve25519.KeyAgreement.Prv.init()
        let bPrivate = Curve25519.KeyAgreement.Prv.init()
        let shared = try aPrivate.aggreement(pub: bPrivate.publicKey)
        var bobRatchet = try Ratchet<Curve25519.KeyAgreement>.init(sk: .init(data: shared))
        var aliceRatchet = try Ratchet<Curve25519.KeyAgreement>.init(
            sk: .init(data: shared), bobPublicKey: bobRatchet.sendingPublicKey)
        for _ in 0...1000 {
            let aliceMessage = Data.init(randomLength: 100)
            let aliceAd = Data.init(randomLength: 10)
            let (aliceHeader, aliceEncrypted) = try aliceRatchet.ratchetEncrypt(plaintext: aliceMessage, ad: aliceAd)
            let aliceDecrypted = try bobRatchet.ratchetDecrypt(header: aliceHeader, ciphertext: aliceEncrypted, ad: aliceAd)
            XCTAssertEqual(aliceDecrypted, aliceMessage, "decrypted message and encrypted message are not equal")
            let bobMessage = Data.init(randomLength: 100)
            let bobAd = Data.init(randomLength: 10)
            let (bobHeader, bobEncrypted) = try bobRatchet.ratchetEncrypt(plaintext: bobMessage, ad: bobAd)
            let bobDecrypted = try aliceRatchet.ratchetDecrypt(header: bobHeader, ciphertext: bobEncrypted, ad: bobAd)
            XCTAssertEqual(bobDecrypted, bobMessage, "decrypted message and encrypted message are not equal")
        }
    }
    
    func testThrow() throws {
        let aPrivate = Curve25519.KeyAgreement.Prv.init()
        let bPrivate = Curve25519.KeyAgreement.Prv.init()
        let shared = try aPrivate.aggreement(pub: bPrivate.publicKey)
        var bobRatchet = try Ratchet<Curve25519.KeyAgreement>.init(sk: .init(data: shared))
        var aliceRatchet = try Ratchet<Curve25519.KeyAgreement>.init(
            sk: .init(data: shared), bobPublicKey: bobRatchet.sendingPublicKey)
        let message = Data.init(randomLength: 100)
        let ad = Data.init(randomLength: 10)
        var header: Ratchet<Curve25519.KeyAgreement>.Header? = nil
        var encrypted: Data? = nil
        for _ in 0...11 {
            (header, encrypted) = try aliceRatchet.ratchetEncrypt(plaintext: message, ad: ad)
        }
        
        do {
            let _ = try bobRatchet.ratchetDecrypt(header: header!, ciphertext: encrypted!, ad: ad)
        } catch {
            XCTAssertEqual(error as! Ratchet<Curve25519.KeyAgreement>.RatchetError, Ratchet<Curve25519.KeyAgreement>.RatchetError.skippedToMany, "didn't fail with to many skips")
        }
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
