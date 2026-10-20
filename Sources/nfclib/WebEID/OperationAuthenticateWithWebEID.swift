// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Security

public enum AuthenticateWithWebEidError: Error {
    case failedToReadPublicKey
    case failedToDetermineAlgorithm
    case failedToMapAlgorithm
    case failedCertificateExpired
    case failedCertificateNotYetValid
}

@MainActor
public class OperationAuthenticateWithWebEID {
    public init() {}

    public func startReading(CAN: String, pin1: SecureData, challenge: String, origin: String) async throws -> WebEidData {
        try await NFCConnection.run(onError: Self.failure) { connection in
            let cardCommands = try await connection.connect(
                CAN: CAN,
                message: alertMessage(step: 0),
                detectedMessage: alertMessage(step: 2)
            )
            connection.message(alertMessage(step: 3))
            let certBytes = try await cardCommands.readAuthenticationCertificate()
            let authCertificate = try convertBytesToX509Certificate(certBytes)

            let (notBefore, notAfter) = try validateCertificateStructure(authCertificate)
            guard Date() >= notBefore else {
                throw AuthenticateWithWebEidError.failedCertificateNotYetValid
            }
            guard Date() <= notAfter else {
                throw AuthenticateWithWebEidError.failedCertificateExpired
            }
            guard let publicKey = SecCertificateCopyKey(authCertificate) else {
                throw AuthenticateWithWebEidError.failedToReadPublicKey
            }

            let algorithm = try WebEidSignatureAlgorithm.forAuthenticationKey(publicKey)
            let hashLength = algorithm.hashLength

            let originHash = sha(hashLength: hashLength, data: Bytes(origin.utf8))
            let challengeHash = sha(hashLength: hashLength, data: Bytes(challenge.utf8))
            let webEidHash = sha(hashLength: hashLength, data: originHash + challengeHash)

            connection.message(alertMessage(step: 4))
            try Task.checkCancellation()
            let authResult = try await cardCommands.authenticate(for: webEidHash, withPin1: pin1)
            let signingCertificateBytes = try await cardCommands.readSignatureCertificate()

            return WebEidData(
                unverifiedCertificate: certBytes.base64EncodedString(),
                algorithm: algorithm,
                signature: authResult.base64EncodedString(),
                signingCertificate: signingCertificateBytes.base64EncodedString()
            )
        }
    }

    private static func failure(_ error: Error) -> (error: Error, message: String) {
        let message = switch error {
        case AuthenticateWithWebEidError.failedCertificateNotYetValid:
            "Certificate not yet valid"
        case AuthenticateWithWebEidError.failedCertificateExpired:
            "Certificate has expired"
        default:
            "Failed to read data"
        }
        return (error, message)
    }

    private func alertMessage(step: Int) -> String {
        let stepMessages = [
            "Please place your ID card against the smart device",
            "Hold your ID card against your smart device until the data is read",
            "Reading data please wait",
            "Authentication in progress please wait"
        ]

        let stepMessage = stepMessages[min(step, stepMessages.count - 1)]
        let progressBar = ProgressBar(currentStep: step)
        return "\(stepMessage)\n\n\(progressBar.generate())"
    }
}
