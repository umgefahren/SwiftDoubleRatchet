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
        for index in 0...7 {
            let offset = 8 * UInt64(index)
            let mask: UInt64 = 0b11111111 << offset
            let maskValue = mask & value
            let backShifted = maskValue >> offset
            ret[index] = UInt8(backShifted)
        }
        return Data(ret)
    }
    
    init(array: [UInt8]) throws {
        if array.count != 8 {
            throw UInt64DecodeError.invalidLength
        }
        var value: UInt64 = 0
        for index in 0...7 {
            let element = array[index]
            let offset = 8 * UInt64(index)
            let mask: UInt64 = UInt64(element) << offset
            value = value | mask
        }
        self = .init(littleEndian: value)
    }
}
