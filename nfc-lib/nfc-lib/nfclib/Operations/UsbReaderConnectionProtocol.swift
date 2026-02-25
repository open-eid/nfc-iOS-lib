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
import iR301

/// @mockable
public protocol UsbReaderConnectionProtocol: Actor {
    func startDiscoveringReaders() async
    func stopDiscoveringReaders(with status: UsbReaderStatus) async
    func updateStatus(_ status: UsbReaderStatus) async
    func getHandle() async -> SCARDCONTEXT
    func getCardHandler() throws -> CardCommands
    func setCardHandler(_ handler: CardCommands?)
    func statusStream() -> AsyncStream<UsbReaderStatus>
    func getPublicData() async throws -> CardInfo
    func readAuthenticationCertificate() async throws -> Data
    func readSignatureCertificate() async throws -> Data
    func readCodeTryCounterRecord(for codeType: CodeType) async throws -> (retryCount: UInt8, pinActive: Bool)
    func isPUKChangeable() async throws -> Bool
    func changeCode(_ codeType: CodeType, to newCode: Data, verifyCode: Data) async throws
    func unblockCode(_ codeType: CodeType, puk: Data, newCode: Data) async throws
    func calculateSignature(for dataToSign: Data, pin2: SecureData) async throws -> Data
}
