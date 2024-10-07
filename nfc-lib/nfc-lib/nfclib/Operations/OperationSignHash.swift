//
//  OperationSignHash.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 03.12.2023.
//

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
@_implementationOnly import SwiftECC
import BigInt
import CryptoKit

enum SignHashError: Error {
    case general
}

class OperationSignHash: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var PIN: String = ""
    private var hashToSign: Data?
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
    private var continuation: CheckedContinuation<Data, Error>?
    private var connection = NFCConnection()

    public func startSigning(CAN: String, PIN2: String, hash: Data) async throws -> Data {

        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                // TODO: Handle this case properly
                continuation.resume(throwing: IdCardInternalError.nfcNotSupported)
                return
            }
            self.CAN = CAN
            self.PIN = PIN2
            self.hashToSign = hash

            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }
}

extension OperationSignHash: NFCTagReaderSessionDelegate {
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
     
        Task {
            do {
                session.alertMessage = "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse."
                let tag = try await connection.setup(session, tags: tags)
                if let (ksEnc, ksMac) = try await OperationAuthenticate().mutualAuthenticate(tag: tag, CAN: CAN) {
                    let card = NFCIdCard(ksEnc: ksEnc, ksMac: ksMac, SSC: Bytes(repeating: 0x00, count: AES.BlockSize))
                    try await card.selectDF(tag: tag, file: Data())
                    try await card.selectDF(tag: tag, file: Data([0xAD, 0xF2]))
                    var pin = Data(repeating: 0xFF, count: 12)
                    pin.replaceSubrange(0..<PIN.count, with: PIN.utf8)
                    // verify PIN2
                    let _ = try await card.sendWrapped(tag: tag, cls: 0x00, ins: 0x20, p1: 0x00, p2: 0x85, data: pin, le: 256)
                    //                    ECDSA - SHA-384
                    let cryptographicMechanismRef = "80"
                    let len = "04"
                    let value = "ff150800"
                    let pkRef = "84"
                    let pkLen = "01"
                    let pkValue = "9f"

                    let secEnvData = Data(hex: cryptographicMechanismRef + len + value + pkRef + pkLen + pkValue)!
                    let _ = try await card.sendWrapped(tag: tag, cls: 0x00, ins: 0x22, p1: 0x41, p2: 0xb6, data: secEnvData, le: 0)
                    guard let hashData = hashToSign else {
                        return
                    }
                    let signatureValue = try await card.sendWrapped(tag: tag, cls:0x00, ins: 0x2A, p1: 0x9E, p2: 0x9A, data: hashData, le: 256);
                    continuation?.resume(with: .success(signatureValue))
                    session.alertMessage = "Andmed loetud"
                    session.invalidate()
                } else {
                    continuation?.resume(throwing: IdCardInternalError.couldNotVerifyChipsMAC)
                }
            } catch let error as IdCardInternalError {
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                if case .sendCommandFailed(message: let message) = error {
                    if let e = NFCIdCard().getPinError(message) {
                        continuation?.resume(throwing: e)
                    }
                } else {
                    continuation?.resume(throwing: error)
                }
            } catch {
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                continuation?.resume(throwing: error)
            }
        }
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // TODO: Anyhing we want to do here?
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
    }
}
