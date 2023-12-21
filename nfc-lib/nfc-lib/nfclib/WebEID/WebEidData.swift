//
//  WebEidData.swift
//  nfc-lib
//
//  Created by Riivo Ehrlich on 15.12.2023.
//

import Foundation

public class WebEidData {
    let unverifiedCertificate: String
    let algorithm: String
    let signature: String

    init(unverifiedCertificate: String, algorithm: String, signature: String) {
        self.unverifiedCertificate = unverifiedCertificate
        self.algorithm = algorithm
        self.signature = signature
    }

    public var formattedDescription: String {
        """
        ====
        unverifiedCertificate: \(unverifiedCertificate)
        ====
        algorithm: \(algorithm)
        ====
        signature: \(signature)
        ====
        """
    }
}
