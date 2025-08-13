//
//  TKBERTLVRecord+Extensions.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import CryptoTokenKit
internal import SwiftECC

extension TKBERTLVRecord {
    convenience init<T: DataProtocol>(tag: TKTLVTag, bytes: T) {
        self.init(tag: tag, value: Data(bytes))
    }

    convenience init(tag: TKTLVTag, publicKey: ECPublicKey) throws {
        self.init(tag: tag, bytes: (try publicKey.x963Representation()))
    }
}
