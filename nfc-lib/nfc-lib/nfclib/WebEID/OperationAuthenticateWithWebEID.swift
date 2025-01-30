//
//  OperationAuthenticateWithWebEID.swift
//  nfc-lib
//
//  Created by Riivo Ehrlich on 12.12.2023.
//

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
@_implementationOnly import SwiftECC
import BigInt
import Security
@_implementationOnly import X509

enum AuthenticateWithWebEidError: Error {
    case failedToReadPublicKey
    case failedToDetermineAlgorithm
    case failedToHashData
    case failedToMapAlgorithm
}

class OperationAuthenticateWithWebEID: NSObject {
    private let CAN: String
    private let pin1: String
    private let challenge: String
    private let origin: String
    
    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<WebEidData, Error>?
    
    init(CAN: String, pin1: String, challenge: String, origin: String) {
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

extension OperationAuthenticateWithWebEID: NFCTagReaderSessionDelegate {
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            defer {
                self.session = nil
            }

            do {
                updateAlertMessage(step: 1)
                let tag = try await NFCConnection().setup(session, tags: tags)
                guard let (ksEnc, ksMac) = try await OperationAuthenticate().mutualAuthenticate(tag: tag, CAN: CAN) else {
                    let errorMessage = "Could not verify chip's MAC."
                    continuation?.resume(throwing: IdCardInternalError.couldNotVerifyChipsMAC)
                    session.invalidate(errorMessage: errorMessage)
                    return
                }

                updateAlertMessage(step: 2)
                let idCard = NFCIdCard(ksEnc: ksEnc, ksMac: ksMac, SSC: Bytes(repeating: 0x00, count: AES.BlockSize))

                do {
                    updateAlertMessage(step: 3)
                    let certBytes = try await idCard.readCert(tag: tag, usage: CertificateUsage.auth)
                    let authCertificate = try convertBytesToX509Certificate(certBytes)
                    let authCertificateSignatureAlgorithmInfo = try getAlgorithmInfoFromCertificate(authCertificate)

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
                          let signatureHashLenght = hashLengthFromInt(authCertificateSignatureAlgorithmInfo.bitSize),
                          let originHash = sha(hashLength: signatureHashLenght, data: originData),
                          let challengeHash = sha(hashLength: signatureHashLenght, data: challengeData),
                          let webEidHash = sha(hashLength: hashLength, data: originHash + challengeHash),
                          let pin1Data = self.pin1.data(using: .utf8) else {
                        let errorMessage = "Andmete lugemine ebaõnnestus"
                        session.invalidate(errorMessage: errorMessage)
                        continuation?.resume(throwing: AuthenticateWithWebEidError.failedToHashData)
                        return
                    }

                    do {
                        updateAlertMessage(step: 4)
                        let authResult = try await idCard.authenticate(tag: tag, pin1: pin1Data, token: webEidHash)
                        let signingCertificateBytes = try await idCard.readCert(tag: tag, usage: .sign)

                        let webEidData = WebEidData(unverifiedCertificate: certBytes.base64EncodedString(),
                                                    algorithm: authCertificateSignatureAlgorithmInfo.name,
                                                    signature: authResult.base64EncodedString(),
                                                    signingCertificate: signingCertificateBytes.base64EncodedString())
                        continuation?.resume(returning: webEidData)
                        session.alertMessage = "Andmed loetud"
                        session.invalidate()
                    } catch {
                        session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                        continuation?.resume(throwing: error)
                    }
                } catch {
                    session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                    continuation?.resume(throwing: error)
                }
                // Done with the session, invalidate
            } catch {
                continuation?.resume(throwing: error)
            }
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
        }
    }

    func getAlgorithmInfoFromCertificate(_ secCertificate: SecCertificate) throws -> SignatureAlgorithmInfo {
        let certificate = try Certificate(secCertificate)

        switch certificate.signatureAlgorithm {
        case .ecdsaWithSHA256:
            return SignatureAlgorithmInfo(name: "ES256", bitSize: 256)
        case .ecdsaWithSHA384:
            return SignatureAlgorithmInfo(name: "ES384", bitSize: 384)
        case .ecdsaWithSHA512:
            return SignatureAlgorithmInfo(name: "ES512", bitSize: 512)
        case .sha256WithRSAEncryption:
            return SignatureAlgorithmInfo(name: "RS256", bitSize: 256)
        case .sha384WithRSAEncryption:
            return SignatureAlgorithmInfo(name: "RS384", bitSize: 384)
        case .sha512WithRSAEncryption:
            return SignatureAlgorithmInfo(name: "RS512", bitSize: 512)
        default:
            return SignatureAlgorithmInfo(name: unknownAlgorithmName, bitSize: 0)
        }
    }

    func getAlgorithmNameTypeAndLength(from key: SecKey) -> (algorithm: String, keyLength: Int)? {
        // Get the algorithm type from the key
        if let algorithmAttributes = SecKeyCopyAttributes(key) as? [String: Any], let algorithmType = algorithmAttributes[kSecAttrKeyType as String] as? String {
            
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
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // TODO: Anyhing we want to do here?
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
    }

    func mapToAlgorithm(algorithm: String, bitLength: Int) -> String? {
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

struct SignatureAlgorithmInfo {
    let name: String
    let bitSize: Int
}
