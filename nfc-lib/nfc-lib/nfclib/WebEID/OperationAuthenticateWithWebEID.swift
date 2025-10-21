/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
internal import SwiftECC
import BigInt
import Security
internal import X509

public enum AuthenticateWithWebEidError: Error {
    case failedToReadPublicKey
    case failedToDetermineAlgorithm
    case failedToHashData
    case failedToMapAlgorithm
    case failedCertificateExpired
    case failedCertificateNotYetValid
}

@MainActor
public class OperationAuthenticateWithWebEID: NSObject {
    private let CAN: String
    private let pin1: SecureData
    private let challenge: String
    private let origin: String
    private let connection = NFCConnection()

    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<WebEidData, Error>?

    public init(CAN: String, pin1: SecureData, challenge: String, origin: String) {
        self.CAN = CAN
        self.pin1 = pin1
        self.challenge = challenge
        self.origin = origin
    }

    public func startReading() async throws -> WebEidData {
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            guard NFCTagReaderSession.readingAvailable else {
                // TODO: Handle this case properly
                continuation.resume(throwing: IdCardInternalError.nfcNotSupported)
                return
            }
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            // TODO: Use a proper message that is localised
            updateAlertMessage(step: 0)
            session?.begin()
        }
    }

    private func updateAlertMessage(step: Int) {
        let stepMessages = [
            "Palun asetage oma ID-kaart vastu nutiseadet.",
            "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse.",
            "Andmete lugemine käib, palun oodake.",
            "Autentimine käib, palun oodake."
        ]

        let stepMessage = stepMessages[min(step, stepMessages.count - 1)]

        let progressBar = ProgressBar(currentStep: step)

        var message = stepMessage

        message += "\n\n\(progressBar.generate())"

        session?.alertMessage = message
    }
}

extension OperationAuthenticateWithWebEID: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.session = nil
            }

            do {
                updateAlertMessage(step: 1)
                let tag = try await connection.setup(session, tags: tags)
                updateAlertMessage(step: 2)
                let cardCommands = try await connection.getCardCommands(session, tag: tag, CAN: CAN)

                updateAlertMessage(step: 3)
                let certBytes = try await cardCommands.readAuthenticationCertificate()
                let authCertificate = try convertBytesToX509Certificate(certBytes)

                // assuming authCertificate is `Certificate` from Swift-Certificates
                let certificate = try Certificate(authCertificate)
                let notAfter = certificate.notValidAfter
                let notBefore = certificate.notValidBefore

                guard Date() >= notBefore else {
                    let errorMessage = "Sertifikaat pole veel kehtiv"
                    session.invalidate(errorMessage: errorMessage)
                    continuation?.resume(throwing: AuthenticateWithWebEidError.failedCertificateNotYetValid)
                    return
                }

                guard Date() <= notAfter else {
                    let errorMessage = "Sertifikaat on aegunud"
                    session.invalidate(errorMessage: errorMessage)
                    continuation?.resume(throwing: AuthenticateWithWebEidError.failedCertificateExpired)
                    return
                }

                guard let publicKey = SecCertificateCopyKey(authCertificate) else {
                    // TODO: Failed to process public key, handle error
                    let errorMessage = "Andmete lugemine ebaõnnestus"
                    session.invalidate(errorMessage: errorMessage)
                    continuation?.resume(throwing: AuthenticateWithWebEidError.failedToReadPublicKey)
                    return
                }

                guard let keyAlgorithmData = getAlgorithmNameTypeAndLength(from: publicKey) else {
                    // TODO: Implement error handling
                    let errorMessage = "Andmete lugemine ebaõnnestus"
                    session.invalidate(errorMessage: errorMessage)
                    continuation?.resume(throwing: AuthenticateWithWebEidError.failedToDetermineAlgorithm)
                    return
                }

                guard let hashLength = hashLengthFromInt(keyAlgorithmData.keyLength),
                      let originData = origin.data(using: .utf8),
                      let challengeData = challenge.data(using: .utf8),
                      let originHash = sha(hashLength: hashLength, data: originData),
                      let challengeHash = sha(hashLength: hashLength, data: challengeData),
                      let webEidHash = sha(hashLength: hashLength, data: originHash + challengeHash)
                else {
                    let errorMessage = "Andmete lugemine ebaõnnestus"
                    session.invalidate(errorMessage: errorMessage)
                    continuation?.resume(throwing: AuthenticateWithWebEidError.failedToHashData)
                    return
                }

                updateAlertMessage(step: 4)
                let authResult = try await cardCommands.authenticate(for: webEidHash, withPin1: pin1)
                let signingCertificateBytes = try await cardCommands.readSignatureCertificate()

                let webEidData = WebEidData(
                    unverifiedCertificate: certBytes.base64EncodedString(),
                    algorithm: keyAlgorithmData.algorithm,
                    signature: authResult.base64EncodedString(),
                    signingCertificate: signingCertificateBytes.base64EncodedString()
                )
                continuation?.resume(returning: webEidData)
                session.alertMessage = "Andmed loetud"
                session.invalidate()
            } catch {
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                continuation?.resume(throwing: error)
            }
        }
    }

    public func getAlgorithmNameTypeAndLength(from key: SecKey) -> (algorithm: String, keyLength: Int)? {
        // Get the algorithm type from the key
        if let algorithmAttributes = SecKeyCopyAttributes(key) as? [String: Any], let algorithmType =
            algorithmAttributes[kSecAttrKeyType as String] as? String {

            // Get the algorithm name based on the type
            var algorithmName = ""
            var keyLength = 0

            switch algorithmType {
            case String(kSecAttrKeyTypeRSA):
                algorithmName = rsaAlgorithmName
                keyLength = (algorithmAttributes[kSecAttrKeySizeInBits as String] as? Int) ?? 0
            case String(kSecAttrKeyTypeEC):
                algorithmName = ecAlgorithmName
                keyLength = (algorithmAttributes[kSecAttrKeySizeInBits as String] as? Int) ?? 0
            default:
                algorithmName = unknownAlgorithmName
            }

            return (algorithm: algorithmName, keyLength: keyLength)
        } else {
            return nil
        }
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_: NFCTagReaderSession, didInvalidateWithError _: Error) {
        self.session = nil
    }

    public func mapToAlgorithm(algorithm: String, bitLength: Int) -> String? {
        switch algorithm {
        case ecAlgorithmName:
            return "ES\(bitLength)"
        case rsaAlgorithmName:
            return "RS\(bitLength)"
        default:
            return nil
        }
    }
}

public struct SignatureAlgorithmInfo {
    let name: String
    let bitSize: Int
}
