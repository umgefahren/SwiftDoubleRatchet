//
//  File.swift
//
//
//  Created by Hannes Furmans on 03.07.22.
//

import Foundation
import XCTest

@testable import SwiftDoubleRatchet

final class NumTests: XCTestCase {
    func testEncodeDecode() throws {
        let testNum: UInt64 = .random(in: UInt64.min...UInt64.max)
        let numBytes = testNum.encodedBytes
        let decdodedNum: UInt64 = try .init(collection: numBytes)
        XCTAssertEqual(testNum, decdodedNum, "Encoded and decoded are different")
    }
}
