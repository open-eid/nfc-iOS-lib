// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

public final class WebEidData: Sendable {
    public let unverifiedCertificate: String
    public let signingCertificate: String
    public let algorithm: WebEidSignatureAlgorithm
    public let signature: String

    init(unverifiedCertificate: String,
         algorithm: WebEidSignatureAlgorithm,
         signature: String,
         signingCertificate: String) {
        self.unverifiedCertificate = unverifiedCertificate
        self.algorithm = algorithm
        self.signature = signature
        self.signingCertificate = signingCertificate
    }

    public var formattedDescription: String {
        """
        ====
        unverifiedCertificate: \(unverifiedCertificate)
        ====
        algorithm: \(algorithm.rawValue)
        ====
        signature: \(signature)
        ====
        signingCertificate: \(signingCertificate)
        """
    }
}
