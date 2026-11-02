// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

@MainActor
final public class OperationReadPublicData {
    public init() {}

    public func startReading(CAN: String) async throws -> CardInfo {
        try await NFCConnection.run { connection in
            let cardCommands = try await connection.connect(
                CAN: CAN,
                message: "Please place your ID card against the smart device",
                detectedMessage: "Hold your ID card against your smart device until the data is read"
            )
            return try await cardCommands.readPublicData()
        }
    }
}
