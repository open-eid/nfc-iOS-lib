//
//  Operator.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import Foundation
import Security
import CoreNFC

public struct SignResult {
    public let signedData: Data
    public let signingCertificate: Data
}

public struct Operator {
    public init() {}
}

extension Operator: CardOperations {
    public func isNFCSupported() -> Bool {
        NFCTagReaderSession.readingAvailable
    }
    
    public func readPublicInfo(CAN: String) async throws -> CardInfo {
        do {
            let result = try await OperationReadPublicData().startReading(CAN: CAN)
            return result
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }
    
    public func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .auth)
            return cert
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }

    public func readSigningCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .sign)
            return cert
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }

    public func loadWebEIDAuthenticationData(CAN: String, pin1: String, challenge: String, origin: String) async throws -> WebEidData {
        do {
            let webEidData = try await OperationAuthenticateWithWebEID(CAN: CAN, pin1: pin1, challenge: challenge, origin: origin).startReading()
            return webEidData
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }
    
    public func sign(CAN: String, hash: Data, pin2: String) async throws -> Data {
        do {
            let signature = try await OperationSignHash().startSigning(CAN: CAN, PIN2: pin2, hash: hash)
            return signature
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }
    
    public func pinRetryCounter(CAN: String, pinType: PinType) async throws -> Int {
        do {
            return try await OperationReadPinRetryCount().startReading(CAN: CAN, pinType: pinType)
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }
}
