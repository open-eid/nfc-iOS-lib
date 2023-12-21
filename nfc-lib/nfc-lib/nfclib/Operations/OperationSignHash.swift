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
import SwiftECC
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
    private let nfcMessage: String = "Put card against phone"
    private var continuation: CheckedContinuation<Data, Error>?
    private var connection = NFCConnection()

    public func startSigning(CAN: String, PIN2: String, hash: Data) async throws -> Data {

        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                // TODO: Handle this case properly
                continuation.resume(throwing: TagReadingError.nfcNotSupported)
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
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
     
        Task {
            do {
                session.alertMessage = "Authenticating with card."
                let tag = try await connection.setup(session, tags: tags)
                if let (ksEnc, ksMac) = try await OperationAuthenticate().mutualAuthenticate(tag: tag, CAN: CAN) {
                    let card = NFCIdCard(ksEnc: ksEnc, ksMac: ksMac, SSC: Bytes(repeating: 0x00, count: AES.BlockSize))
                    session.alertMessage = "Reading Certificate."
                    try await card.selectDF(tag: tag, file: Data())
                    try await card.selectDF(tag: tag, file: Data([0xAD, 0xF2]))
                    session.alertMessage = "Sign data."
                    var pin = Data(repeating: 0xFF, count: 12)
                    pin.replaceSubrange(0..<PIN.count, with: PIN.utf8)
                    let _ = try await card.sendWrapped(tag: tag, cls: 0x00, ins: 0x22, p1: 0x41, p2: 0xb6, data: Data(hex: "80015484019f")!, le: 256)
                    let _ = try await card.sendWrapped(tag: tag, cls: 0x00, ins: 0x20, p1: 0x00, p2: 0x85, data: pin, le: 256)
                    guard let hashData = hashToSign?.padDataTo48Bytes() else {
                       return
                    }
                    let signatureValue = try await card.sendWrapped(tag: tag, cls:0x00, ins: 0x2A, p1: 0x9E, p2: 0x9A, data: hashData, le: 256);
                    continuation?.resume(with: .success(signatureValue))
                    session.alertMessage = "Signing Done."
                    session.invalidate()
                } else {
                    continuation?.resume(throwing: TagReadingError.couldNotVerifyChipsMAC)
                }
            } catch {
                session.invalidate(errorMessage: "Failed to authenticate with card.")
                throw error
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // TODO: Anyhing we want to do here?
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if let readerError = error as? NFCReaderError,
           readerError.code == .readerSessionInvalidationErrorUserCanceled {
            continuation?.resume(throwing: TagReadingError.cancelledByUser)
        } else {
            continuation?.resume(throwing: TagReadingError.sessionInvalidated)
        }
        self.session = nil
    }
}
