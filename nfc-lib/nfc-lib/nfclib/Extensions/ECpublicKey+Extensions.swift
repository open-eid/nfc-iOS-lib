//
//  ECpublicKey+Extensions.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import CommonCrypto
import CryptoTokenKit
import SwiftECC

extension ECPublicKey {
    convenience init?(domain: Domain, tlv: TKTLVRecord) throws {
        guard let w = try? domain.decodePoint(Bytes(tlv.value)) else { return nil }
        try self.init(domain: domain, w: w)
    }

    func x963Representation() throws -> Bytes  {
        return try domain.encodePoint(w)
    }
}
