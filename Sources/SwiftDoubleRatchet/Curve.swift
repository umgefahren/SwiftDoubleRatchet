//
//  File.swift
//
//
//  Created by Hannes Furmans on 02.07.22.
//

import Crypto
import Foundation

/// Behaviour defining a private key
public protocol Private {
    /// Corresponding public key
    associatedtype Pub: Public
    
    /// generate a new random private key
    init()
    /// construct a private key from a binary encoded private key
    init(rawRepresentation: Data) throws
    /// encode the private key to binary data
    var rawRepresentation: Data { get }
    /// derive a public key from a private key
    var publicKey: Pub { get }
    /// perform a key agreement with a public key
    func aggreement(pub: Pub) throws -> SharedSecret
}


/// Behaviour defining a public key
public protocol Public {
    /// construct a public key from a binary encoded private key
    init(rawRepresentation: Data) throws
    /// encode the public key to binary data
    var rawRepresentation: Data { get }
}

/// Behaviour defining a Curve
public protocol Curve {
    /// corresponding private key
    associatedtype Prv: Private where Prv.Pub.Type == Pub.Type
    /// corresponding public key
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

