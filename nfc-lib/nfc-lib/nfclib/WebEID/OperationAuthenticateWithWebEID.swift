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
import SwiftECC
import BigInt
import Security

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
            session?.alertMessage = "Palun asetage oma ID-kaart vastu nutiseadet."
            session?.begin()
        }
    }
}

extension OperationAuthenticateWithWebEID: NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            defer {
                self.session = nil
            }

            do {
                session.alertMessage = "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse."
                let tag = try await NFCConnection().setup(session, tags: tags)
                guard let (ksEnc, ksMac) = try await OperationAuthenticate().mutualAuthenticate(tag: tag, CAN: CAN) else {
                    let errorMessage = "Could not verify chip's MAC."
                    continuation?.resume(throwing: IdCardInternalError.couldNotVerifyChipsMAC)
                    session.invalidate(errorMessage: errorMessage)
                    return
                }

                let idCard = NFCIdCard(ksEnc: ksEnc, ksMac: ksMac, SSC: Bytes(repeating: 0x00, count: AES.BlockSize))

                do {
                    let certBytes = try await idCard.readCert(tag: tag, usage: CertificateUsage.auth)
                    let x509Certificate = try convertBytesToX509Certificate(certBytes)

                    guard let publicKey = SecCertificateCopyKey(x509Certificate) else {
                        // TODO: Failed to process public key, handle error
                        let errorMessage = "Andmete lugemine ebaõnnestus"
                        session.invalidate(errorMessage: errorMessage)
                        continuation?.resume(throwing: AuthenticateWithWebEidError.failedToReadPublicKey)
                        return
                    }

                    guard let algorithmData = getAlgorithmNameTypeAndLength(from: publicKey) else {
                        // TODO: Implement error handling
                        let errorMessage = "Andmete lugemine ebaõnnestus"
                        session.invalidate(errorMessage: errorMessage)
                        continuation?.resume(throwing: AuthenticateWithWebEidError.failedToDetermineAlgorithm)
                        return
                    }
                    
                    guard let hashLength = hashLengthFromInt(algorithmData.keyLength),
                          let originData = origin.data(using: .utf8),
                          let challengeData = challenge.data(using: .utf8),
                          let originHash = sha(hashLength: hashLength, data: originData),
                          let challengeHash = sha(hashLength: hashLength, data: challengeData),
                          let webEidHash = sha(hashLength: hashLength, data: originHash + challengeHash),
                          let pin1Data = self.pin1.data(using: .utf8) else {
                        let errorMessage = "Andmete lugemine ebaõnnestus"
                        session.invalidate(errorMessage: errorMessage)
                        continuation?.resume(throwing: AuthenticateWithWebEidError.failedToHashData)
                        return
                    }

                    do {
                        let authResult = try await idCard.authenticate(tag: tag, pin1: pin1Data, token: webEidHash)

                        // TODO: Encapsulate the result and publish it
                        guard let webEidAlg = mapToAlgorithm(algorithm: algorithmData.algorithm, bitLength: algorithmData.keyLength) else {
                            let errorMessage = "Andmete lugemine ebaõnnestus"
                            session.invalidate(errorMessage: errorMessage)
                            continuation?.resume(throwing: AuthenticateWithWebEidError.failedToMapAlgorithm)
                            return
                        }
                        let signingCertificate = try await idCard.readCert(tag: tag, usage: .sign).base64EncodedString()
                        let webEidData = WebEidData(unverifiedCertificate: certBytes.base64EncodedString(),
                                                    algorithm: webEidAlg,
                                                    signature: authResult.base64EncodedString(),
                                                    signingCertificate: signingCertificate)
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
    
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // TODO: Anyhing we want to do here?
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
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
