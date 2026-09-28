// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import CommonCrypto
import CryptoTokenKit
internal import SwiftECC

extension ECPublicKey {
    convenience init?(domain: Domain, point: Data) throws {
        guard let decodePoint = try? domain.decodePoint(Bytes(point)) else { return nil }
        try self.init(domain: domain, w: decodePoint)
    }

    func x963Representation() throws -> Bytes {
        return try domain.encodePoint(w)
    }
}
