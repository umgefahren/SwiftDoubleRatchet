import Foundation
import Crypto

let infoMessage: Data = "MyRatchet".data(using: .utf8)!

public struct Ratchet<C: Curve> {
    struct PublicKeyNumber: Hashable {
        static func == (lhs: PublicKeyNumber, rhs: PublicKeyNumber) -> Bool {
            lhs.n == rhs.n && lhs.p == rhs.p
        }
        
        func hash(into hasher: inout Hasher) {
            p.hash(into: &hasher)
            n.hash(into: &hasher)
        }
        
        let p: Data
        let n: UInt

    }
    
    public enum RatchetError: Error {
        case noSendingChainKey
        case noReceiveChainKey
        case skippedToMany
        case noRecieveReceiveChain
    }
    
    public struct Header: Codable, Equatable {
        let publicKey: Data
        let PN, Ns: UInt64
        
        init(publicKey: Data, PN: UInt64, Ns: UInt64) {
            self.publicKey = publicKey
            self.PN = PN
            self.Ns = Ns
        }
        
        init(data: Data) throws {
            let publicKeyLengthData = data[0..<8]
            let publicKeyLength = try UInt64(array: Array.init(publicKeyLengthData)) + 8
            publicKey = data[8..<publicKeyLength]
            let PNData = data[publicKeyLength..<(publicKeyLength + 8)]
            PN = try .init(array: Array.init(PNData))
            let NsData = data[(publicKeyLength + 8)..<(publicKeyLength + 16)]
            Ns = try .init(array: Array.init(NsData))
        }
        
        var encoded: Data {
            let publicKeyLength = UInt64(publicKey.count)
            var ret = Data()
            ret.append(Data(publicKeyLength.encodedBytes))
            ret.append(publicKey)
            ret.append(Data(PN.encodedBytes))
            ret.append(Data(Ns.encodedBytes))
            return ret
        }
    }
    
    var DHs: Pair<C>
    var DHr: C.Pub? = nil
    var RK: SymmetricKey
    var CKs: SymmetricKey? = nil
    var CKr: SymmetricKey? = nil
    var Ns: UInt = .zero
    var Nr: UInt = .zero
    var PN: UInt = .zero
    var Mkskipped: [PublicKeyNumber : SymmetricKey] = .init()
    public var MaxSkip: UInt = 10
    
    public init(sk: SymmetricKey, bobPublicKey: C.Pub) throws {
        DHs = .init()
        DHr = bobPublicKey
        (RK, CKs) = try kdfRk(rk: sk, dhOut: DHs.dH(pub: bobPublicKey), info: infoMessage)
    }
    
    public init(sk: SymmetricKey) throws {
        DHs = .init()
        RK = sk
    }
    
    public mutating func ratchetEncrypt<P: DataProtocol, AD: DataProtocol>(plaintext: P, ad: AD) throws -> (Header, Data) {
        if case let Optional.some(curCKs) = CKs {
            let (newCKs, Mk) = kdfCk(ck: curCKs)
            CKs = newCKs
            let header = Header.init(publicKey: DHs.publicKey.rawRepresentation, PN: .init(PN), Ns: .init(Ns))
            Ns += 1
            var concated = Data.init()
            concated.append(contentsOf: .init(ad))
            concated.append(header.encoded)
            let encrypted = try encrypt(mk: Mk, plaintext: plaintext, ad: concated)
            return (header, encrypted)
        } else {
            throw RatchetError.noSendingChainKey
        }
    }
    
    public mutating func ratchetDecrypt<C: DataProtocol, AD: DataProtocol>(header: Header, ciphertext: C, ad: AD) throws -> Data {
        let plaintext = try trySkippedMessageKeys(header: header, ciphertext: ciphertext, ad: ad)
        if plaintext != nil {
            return plaintext!
        }
        if DHr == nil || header.publicKey != DHr!.rawRepresentation {
            try skipMessageKeys(until: .init(header.PN))
            try DHRatchet(header: header)
        }
        try skipMessageKeys(until: .init(header.Ns))
        var mk: SymmetricKey? = nil
        (CKr, mk) = kdfCk(ck: CKr!)
        Nr += 1
        var concated = Data.init()
        concated.append(contentsOf: .init(ad))
        concated.append(header.encoded)
        return try decrypt(mk: mk!, ciphertext: ciphertext, ad: concated)
    }
    
    private mutating func trySkippedMessageKeys<C: DataProtocol, AD: DataProtocol>(header: Header, ciphertext: C, ad: AD) throws -> Data? {
        let publicKeyNumber = PublicKeyNumber(p: header.publicKey, n: UInt(header.Ns))
        if case let Optional.some(mk) = Mkskipped.removeValue(forKey: publicKeyNumber) {
            var concated = Data.init()
            concated.append(contentsOf: .init(ad))
            concated.append(header.encoded)
            return try decrypt(mk: mk, ciphertext: ciphertext, ad: concated)
        } else {
            return nil
        }
    }
    
    private mutating func skipMessageKeys(until: UInt) throws {
        if Nr + MaxSkip < until {
            throw RatchetError.skippedToMany
        }
        
        if case Optional.some(_) = CKr {
            if case let Optional.some(curDHr) = DHr {
                let curDHrData = curDHr.rawRepresentation
                var mk: SymmetricKey? = nil
                while Nr < until {
                    (CKr, mk) = kdfCk(ck: CKr!)
                    let key = PublicKeyNumber(p: curDHrData, n: Nr)
                    Mkskipped[key] = mk!
                    Nr += 1
                }
            } else {
                throw RatchetError.noRecieveReceiveChain
            }
        }
    }
    
    private mutating func DHRatchet(header: Header) throws {
        PN = Ns
        Ns = 0
        Nr = 0
        DHr = try .init(rawRepresentation: header.publicKey)
        (RK, CKr) = kdfRk(rk: RK, dhOut: try DHs.dH(pub: DHr!), info: infoMessage)
        DHs = .init()
        (RK, CKs) = kdfRk(rk: RK, dhOut: try DHs.dH(pub: DHr!), info: infoMessage)
    }
    
    public var sendingPublicKey: C.Pub {
        DHs.publicKey
    }
}
