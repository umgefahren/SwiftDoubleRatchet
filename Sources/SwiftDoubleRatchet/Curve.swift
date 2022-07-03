//
//  File.swift
//  
//
//  Created by Hannes Furmans on 02.07.22.
//

import Foundation
import Crypto

public protocol Private {
    associatedtype Pub: Public

    init()
    init(rawRepresentation: Data) throws
    var rawRepresentation: Data { get }
    var publicKey: Pub { get }
    func aggreement(pub: Pub) throws -> SharedSecret
}

public protocol Public {
    init(rawRepresentation: Data) throws
    var rawRepresentation: Data { get }
}

public protocol Curve {
    associatedtype Prv: Private where Prv.Pub.Type == Pub.Type
    associatedtype Pub
}

struct Pair<T: Curve> {
    private let privateKey: T.Prv
    public let publicKey: T.Pub
    
    init() {
        privateKey = T.Prv.init()
        publicKey = privateKey.publicKey
    }
    
    func dH(pub: T.Pub) throws -> SharedSecret {
        try self.privateKey.aggreement(pub: pub)
    }
}

extension Curve25519.KeyAgreement.PublicKey: Public {}

extension Curve25519.KeyAgreement.PrivateKey: Private {
    public func aggreement(pub: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
        try self.sharedSecretFromKeyAgreement(with: pub)
    }
}

extension Curve25519.KeyAgreement: Curve {
    public typealias Prv = Curve25519.KeyAgreement.PrivateKey
    public typealias Pub = Curve25519.KeyAgreement.PublicKey
}


extension P256.KeyAgreement.PublicKey: Public {}

extension P256.KeyAgreement.PrivateKey: Private {
    public init() {
        self.init(compactRepresentable: true)
    }
    
    public func aggreement(pub: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try self.sharedSecretFromKeyAgreement(with: pub)
    }
}

extension P256.KeyAgreement: Curve {
    public typealias Prv = P256.KeyAgreement.PrivateKey
    public typealias Pub = P256.KeyAgreement.PublicKey
}
