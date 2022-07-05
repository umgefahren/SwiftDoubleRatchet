//
//  File.swift
//
//
//  Created by Hannes Furmans on 03.07.22.
//

import Foundation

enum UInt64DecodeError: Error {
    case invalidLength
}

extension UInt64 {
    var encodedBytes: Data {
        let value = self.littleEndian
        var ret: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        for index in 0..<8 {
            let offset = 8 * UInt64(index)
            let mask: UInt64 = 0b11111111 << offset
            let maskValue = mask & value
            let backShifted = maskValue >> offset
            ret[index] = UInt8(backShifted)
        }
        return Data(ret)
    }
    
    init<C: Collection>(collection: C) throws where C.Element == UInt8 {
        guard collection.count == 8 else {
            throw UInt64DecodeError.invalidLength
        }
        
        self.init(littleEndian: collection.reduce(0) { partialResult, element in
            (partialResult >> 8) | (UInt64(element) << 56)
        })
    }
}
