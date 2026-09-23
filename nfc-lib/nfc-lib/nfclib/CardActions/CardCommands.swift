// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

public enum CodeType: UInt, Sendable {
    case puk = 0
    case pin1 = 1
    case pin2 = 2
    
    public var name: String {
        switch self {
        case .puk: return "PUK"
        case .pin1: return "PIN1"
        case .pin2: return "PIN2"
        }
    }
}

public enum CodeValidationFailure: Error, Sendable, Equatable {
    case wrongLength(minimum: Int, maximum: Int)
    case notNumeric
}

public extension CodeType {
    var minimumLength: Int {
        switch self {
        case .pin1: return 4
        case .pin2: return 5
        case .puk: return 8
        }
    }

    var maximumLength: Int { 12 }

    var validLength: ClosedRange<Int> { minimumLength...maximumLength }

    func validateFormat(_ code: [UInt8]) -> CodeValidationFailure? {
        guard code.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else {
            return .notNumeric
        }
        guard validLength.contains(code.count) else {
            return .wrongLength(minimum: minimumLength, maximum: maximumLength)
        }
        return nil
    }
}

/**
 * A protocol defining commands for interacting with a smart card.
 */
public protocol CardCommands: Sendable {
    var canChangePUK: Bool { get }
    /**
     * Reads public data from the card.
     *
     * - Throws: An error if the operation fails.
     * - Returns: The personal data read from the card.
     */
    func readPublicData() async throws -> CardInfo

    /**
     * Reads the authentication certificate from the card.
     *
     * - Throws: An error if the operation fails.
     * - Returns: The authentication certificate as `Data`.
     */
    func readAuthenticationCertificate() async throws -> Data

    /**
     * Reads the signature certificate from the card.
     *
     * - Throws: An error if the operation fails.
     * - Returns: The signature certificate as `Data`.
     */
    func readSignatureCertificate() async throws -> Data

    /**
     * Reads the PIN or PUK code counter record.
     *
     * - Parameter type: The type of record to read.
     * - Throws: An error if the operation fails.
     * - Returns: The remaining attempts as an `UInt8`.
     */
    func readCodeTryCounterRecord(_ type: CodeType) async throws -> (retryCount: UInt8, pinActive: Bool)

    /**
     * Changes the PIN or PUK code.
     *
     * - Parameters:
     *   - type: The type of code to change (e.g., `CodeType.Puk`, `CodeType.Pin1`, `CodeType.Pin2`).
     *   - code: The new PIN/PUK code.
     *   - verifyCode: The current PIN or PUK code for verification.
     * - Throws: An error if the operation fails.
     */
    func changeCode(_ type: CodeType, to code: SecureData, verifyCode: SecureData) async throws

    /**
     * Verifies a PIN or PUK code.
     *
     * - Parameters:
     *   - type: The type of code to verify (e.g., `CodeType.Puk`, `CodeType.Pin1`, `CodeType.Pin2`).
     *   - code: The PIN/PUK code to verify.
     * - Throws: An error if the verification fails.
     */
    func verifyCode(_ type: CodeType, code: SecureData) async throws

    /**
     * Unblocks a PIN using the PUK code.
     *
     * - Parameters:
     *   - type: The type of code to unblock (`CodeType.Pin1` or `CodeType.Pin2`).
     *   - puk: The current PUK code for verification.
     *   - newCode: The new PIN code.
     * - Throws: An error if the operation fails.
     */
    func unblockCode(_ type: CodeType, puk: SecureData, newCode: SecureData) async throws

    /**
     * Authenticates using a cryptographic challenge.
     *
     * - Parameters:
     *   - hash: The challenge hash to be signed.
     *   - pin1: PIN 1 for authentication.
     * - Throws: An error if the operation fails.
     * - Returns: The authentication response as `Data`.
     */
    func authenticate(for hash: Data, withPin1 pin1: SecureData) async throws -> Data

    /**
     * Calculates a digital signature for the given hash.
     *
     * - Parameters:
     *   - hash: The hash to be signed.
     *   - pin2: PIN 2 for verification.
     * - Throws: An error if the operation fails.
     * - Returns: The signature as `Data`.
     */
    func calculateSignature(for hash: Data, withPin2 pin2: SecureData) async throws -> Data

    /**
     * Decrypts data using PIN 1.
     *
     * - Parameters:
     *   - hash: The data to be decrypted.
     *   - pin1: PIN 1 for verification.
     * - Throws: An error if the operation fails.
     * - Returns: The decrypted data.
     */
    func decryptData(_ hash: Data, withPin1 pin1: SecureData) async throws -> Data
}
