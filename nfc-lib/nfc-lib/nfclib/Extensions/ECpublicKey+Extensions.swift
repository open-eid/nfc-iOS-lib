//
//  ECpublicKey+Extensions.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import CommonCrypto
import CryptoTokenKit
internal import SwiftECC

extension ECPublicKey {
    convenience init?(domain: Domain, point: Data) throws {
        guard let w = try? domain.decodePoint(Bytes(point)) else { return nil }
        try self.init(domain: domain, w: w)
    }

    func x963Representation() throws -> Bytes  {
        return try domain.encodePoint(w)
    }
}
