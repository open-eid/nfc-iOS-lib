//
//  CardOperations.swift
//  nfclib
//
//  Created by Timo Kallaste on 31.01.2024.
//

/// `CardOperations` protocol
///
/// This protocol defines a set of operations for interacting with a card,
/// including NFC support checking, reading card information, and performing
/// authentication and signing operations.

public protocol CardOperations {

    /// Determines if NFC (Near Field Communication) is supported on a device.
    ///
    /// - Returns: A `Bool` indicating whether NFC is supported.
    func isNFCSupported() -> Bool

    /// Asynchronously reads the public information from the card.
    ///
    /// - Parameter CAN: A `String` representing the Card Access Number.
    /// - Returns: A `CardInfo` object containing the read public information.
    /// - Throws: An error if the reading fails.
    func readPublicInfo(CAN: String) async throws -> CardInfo

    /// Asynchronously reads the authentication certificate from the card.
    ///
    /// - Parameter CAN: A `String` representing the Card Access Number.
    /// - Returns: A `SecCertificate` object representing the authentication certificate.
    /// - Throws: An error if the reading fails.
    func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate

    /// Asynchronously reads the signing certificate from the card.
    ///
    /// - Parameter CAN: A `String` representing the Card Access Number.
    /// - Returns: A `SecCertificate` object representing the signing certificate.
    /// - Throws: An error if the reading fails.
    func readSigningCertificate(CAN: String) async throws -> SecCertificate

    /// Fetch data for WebEID authentication using the provided credentials and challenge.
    ///
    /// - Parameters:
    ///   - CAN: A `String` representing the Card Access Number.
    ///   - pin1: A `String` representing PIN1.
    ///   - challenge: A `String` representing the authentication challenge.
    ///   - origin: A `String` representing the origin of the authentication request.
    /// - Returns: A `WebEidData` object containing the result of the authentication.
    /// - Throws: An error if the authentication fails.
    func loadWebEIDAuthenticationData(CAN: String, pin1: String, challenge: String, origin: String) async throws -> WebEidData

    /// Performs a signing operation using the provided hash and PIN.
    ///
    /// - Parameters:
    ///   - CAN: A `String` representing the Card Access Number.
    ///   - hash: A `Data` object representing the hash to be signed.
    ///   - pin2: A `String` representing the second PIN.
    /// - Returns: A `Data` object containing the signature.
    /// - Throws: An error if the signing operation fails.
    func sign(CAN: String, hash: Data, pin2: String) async throws -> Data
    
    /// Returns current retry count for the given PIN type.
    ///
    /// - Parameters:
    ///   - CAN: `String` representing the Card Access Number.
    ///   - pinType: Type of PIN from a fixed set.
    /// - Returns: `Int` that represents the current retry count.
    /// - Throws: <TBD> Define the set of errors to throw
    func pinRetryCounter(CAN: String, pinType: PinType) async throws -> Int
}
