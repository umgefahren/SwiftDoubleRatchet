//
//  File.swift
//
//
//  Created by Hannes Furmans on 03.07.22.
//

import Crypto
import Foundation

func encrypt<P: DataProtocol, D: DataProtocol>(mk: SymmetricKey, plaintext: P, ad: D) throws -> Data
{
    try AES.GCM.seal(plaintext, using: mk, nonce: .init(), authenticating: ad).combined!
}

func decrypt<C: DataProtocol, D: DataProtocol>(mk: SymmetricKey, ciphertext: C, ad: D) throws
-> Data
{
    try AES.GCM.open(.init(combined: ciphertext), using: mk, authenticating: ad)
}
