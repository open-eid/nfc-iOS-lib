//
//  WebEidData.swift
//  nfc-lib
//
//  Created by Riivo Ehrlich on 15.12.2023.
//

import Foundation

public class WebEidData {
    public let unverifiedCertificate: String
    public let signingCertificate: String
    public let algorithm: String
    public let signature: String

    init(unverifiedCertificate: String, 
         algorithm: String,
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
        algorithm: \(algorithm)
        ====
        signature: \(signature)
        ====
        signingCertificate: \(signingCertificate)
        """
    }
}
