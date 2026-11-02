// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Security

// MARK: - Local Types

public enum ReadCertificateError: Error {
    case certificateUsageNotSpecified
    case failedToReadCertificate
    case general
}

public enum CertificateUsage {
    case auth
    case sign
}

@MainActor
public class OperationReadCertificate {
    public init() {}

    public func startReading(CAN: String, certUsage: CertificateUsage) async throws -> SecCertificate {
        try await NFCConnection.run { connection in
            let cardCommands = try await connection.connect(
                CAN: CAN,
                message: "Please place your ID card against the smart device",
                detectedMessage: "Hold your ID card against your smart device until the data is read"
            )
            do {
                let cert = switch certUsage {
                case .auth: try await cardCommands.readAuthenticationCertificate()
                case .sign: try await cardCommands.readSignatureCertificate()
                }
                return try convertBytesToX509Certificate(cert)
            } catch {
                throw ReadCertificateError.failedToReadCertificate
            }
        }
    }
}
