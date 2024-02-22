/*
 * Copyright 2017 - 2023 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

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
}
