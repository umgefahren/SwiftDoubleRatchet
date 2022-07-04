//
//  File.swift
//
//
//  Created by Hannes Furmans on 03.07.22.
//

import Crypto
import Foundation

func kdfRk(rk: SymmetricKey, dhOut: SharedSecret, info: Data) -> (SymmetricKey, SymmetricKey) {
    let rkData = rk.withUnsafeBytes { m in
        Data(m[0..<32])
    }
    let concatedData = dhOut.hkdfDerivedSymmetricKey(
        using: SHA512.self, salt: rkData, sharedInfo: info, outputByteCount: 64)
    return concatedData.withUnsafeBytes { m in
        let rootKeyBytes = m[0..<32]
        let rootKey = SymmetricKey(data: rootKeyBytes)
        let chainKeyBytes = m[32..<64]
        let chainKey = SymmetricKey(data: chainKeyBytes)
        return (rootKey, chainKey)
    }
}

func kdfCk(ck: SymmetricKey) -> (SymmetricKey, SymmetricKey) {
    let messageKeyConstantNum: UInt8 = 0x01
    let messageKeyBytes: Data = Data([messageKeyConstantNum])
    let chainKeyConstantNum: UInt8 = 0x02
    let chainKeyBytes: Data = Data([chainKeyConstantNum])
    let messageNewKey = HMAC<SHA256>.authenticationCode(for: messageKeyBytes, using: ck)
    let messageNewKeyData = SymmetricKey(data: messageNewKey)
    let chainNewKey = HMAC<SHA256>.authenticationCode(for: chainKeyBytes, using: ck)
    let chainNewKeyData = SymmetricKey(data: chainNewKey)
    return (chainNewKeyData, messageNewKeyData)
}
