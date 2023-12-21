//
//  Operator.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import Foundation
import Security

public enum OperationError: Error {
    case failed(message: String)
}

public protocol CardOperations {
    func readPublicInfo(CAN: String) async throws -> CardInfo
    func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate
    func readSigningCertificate(CAN: String) async throws -> SecCertificate
    func authenticateWithWebEID(CAN: String, pin1: String, challenge: String, origin: String) async throws -> WebEidData
    func sign(CAN: String, hash: Data, pin2: String) async throws -> Data
}

public struct Operator {
    public init() {}
}

extension Operator: CardOperations {
    public func readPublicInfo(CAN: String) async throws -> CardInfo {
        do {
            let result = try await OperationReadPublicData().startReading(CAN: CAN)
            return result
        } catch {
            print("Read public info error \(error)")
            throw error
        }
    }
    
    public func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .auth)
            return cert
        } catch {
            print("Auth cert reading error \(error)")
            throw error
        }
    }

    public func readSigningCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .sign)
            return cert
        } catch {
            print("Signing cert reading error: \(error)")
            throw error
        }
    }

    public func authenticateWithWebEID(CAN: String, pin1: String, challenge: String, origin: String) async throws -> WebEidData {
        do {
            let webEidData = try await OperationAuthenticateWithWebEID(CAN: CAN, pin1: pin1, challenge: challenge, origin: origin).startReading()
            print("Web-EID cert: \(webEidData.unverifiedCertificate)")
            print("Web-EID algorithm: \(webEidData.algorithm)")
            print("Web-EID signature: \(webEidData.signature)")
            return webEidData
        } catch {
            print("Web-EID error: \(error)")
            throw error
        }
    }
    
    public func sign(CAN: String, hash: Data, pin2: String) async throws -> Data {
        do {
            let signature = try await OperationSignHash().startSigning(CAN: CAN, PIN2: pin2, hash: hash)
            return signature
        } catch {
            print("signing error: \(error)")
            throw error
        }
    }
}
