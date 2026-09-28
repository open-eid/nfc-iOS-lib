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
    private var pin1: SecureData?
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
            guard self.continuation == nil else {
                continuation.resume(throwing: IdCardInternalError.operationInProgress)
                return
            }
            self.continuation = continuation
            guard NFCTagReaderSession.readingAvailable else {
                self.finish(.failure(IdCardInternalError.nfcNotSupported))
                return
            }
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: DispatchQueue.main)
            updateAlertMessage(step: 0)
            session?.begin()
        }
    }

    private func updateAlertMessage(step: Int) {
        let stepMessages = [
            "Please place your ID card against the smart device",
            "Hold your ID card against your smart device until the data is read",
            "Reading data please wait",
            "Authentication in progress please wait"
        ]

        let stepMessage = stepMessages[min(step, stepMessages.count - 1)]

        let progressBar = ProgressBar(currentStep: step)

        var message = stepMessage

        message += "\n\n\(progressBar.generate())"

        session?.alertMessage = message
    }

    private func finish(_ result: Result<WebEidData, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        pin1 = nil
        continuation.resume(with: result)
    }
}

extension OperationAuthenticateWithWebEID: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task { @MainActor [weak self] in
            guard let self else { return }
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
                    let errorMessage = "Certificate not yet valid"
                    finish(.failure(AuthenticateWithWebEidError.failedCertificateNotYetValid))
                    session.invalidate(errorMessage: errorMessage)
                    return
                }

                guard Date() <= notAfter else {
                    let errorMessage = "Certificate has expired"
                    finish(.failure(AuthenticateWithWebEidError.failedCertificateExpired))
                    session.invalidate(errorMessage: errorMessage)
                    return
                }

                guard let publicKey = SecCertificateCopyKey(authCertificate) else {
                    let errorMessage = "Failed to read data"
                    finish(.failure(AuthenticateWithWebEidError.failedToReadPublicKey))
                    session.invalidate(errorMessage: errorMessage)
                    return
                }

                guard let keyAlgorithmData = getAlgorithmNameTypeAndLength(from: publicKey) else {
                    let errorMessage = "Failed to read data"
                    finish(.failure(AuthenticateWithWebEidError.failedToDetermineAlgorithm))
                    session.invalidate(errorMessage: errorMessage)
                    return
                }

                guard let hashLength = hashLengthFromInt(keyAlgorithmData.keyLength),
                      let originData = origin.data(using: .utf8),
                      let challengeData = challenge.data(using: .utf8),
                      let originHash = sha(hashLength: hashLength, data: originData),
                      let challengeHash = sha(hashLength: hashLength, data: challengeData),
                      let webEidHash = sha(hashLength: hashLength, data: originHash + challengeHash)
                else {
                    let errorMessage = "Failed to read data"
                    finish(.failure(AuthenticateWithWebEidError.failedToHashData))
                    session.invalidate(errorMessage: errorMessage)
                    return
                }

                updateAlertMessage(step: 4)
                guard let pin1 else { throw IdCardInternalError.pinVerificationFailed(codeType: .pin1) }
                let authResult = try await cardCommands.authenticate(for: webEidHash, withPin1: pin1)
                let signingCertificateBytes = try await cardCommands.readSignatureCertificate()

                let webEidData = WebEidData(
                    unverifiedCertificate: certBytes.base64EncodedString(),
                    algorithm: keyAlgorithmData.algorithm,
                    signature: authResult.base64EncodedString(),
                    signingCertificate: signingCertificateBytes.base64EncodedString()
                )
                finish(.success(webEidData))
                session.alertMessage = "Data read"
                session.invalidate()
            } catch {
                finish(.failure(error))
                session.invalidate(errorMessage: "Failed to read data")
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

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        guard session === self.session else { return }
        self.session = nil
        finish(.failure(IdCardInternalError.mapSessionInvalidation(error)))
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
