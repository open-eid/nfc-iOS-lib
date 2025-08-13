import Foundation

typealias Bytes = [UInt8]

protocol CardReader {
    /**
     * Sends an APDU (Application Protocol Data Unit) command to the smart card and retrieves the response.
     *
     * - Parameter apdu: The APDU command to be sent.
     * - Throws: An error if communication with the card fails.
     * - Returns: A tuple containing:
     *   - The response data from the card.
     *   - The status word (SW), which indicates the processing status of the command.
     */
    func transmit(_ apdu: Bytes) async throws -> (responseData: Bytes, sw: UInt16)
}

extension CardReader {
    /**
     * Constructs and sends an APDU (Application Protocol Data Unit) command to the smart card.
     *
     * This method builds a command APDU according to ISO/IEC 7816-4 using the provided parameters
     * and transmits it. It automatically handles specific response status words:
     *
     * - **`0x6CXX`**: Indicates incorrect expected length (`Le`). The command is resent using the correct length from `SW2`.
     * - **`0x61XX`**: Indicates more response data is available. The method issues one or more `GET RESPONSE` commands (INS = `0xC0`) to retrieve the remaining data.
     *
     * If the final response status word is not `0x9000`, the method throws a `IdCardInternalError.swError(_:)` with the returned status word.
     *
     * - Parameters:
     *   - cls: The class byte (CLA) of the command. Defaults to `0x00`.
     *   - ins: The instruction byte (INS) of the command.
     *   - p1: The first parameter byte (P1). Defaults to `0x00`.
     *   - p2: The second parameter byte (P2). Defaults to `0x00`.
     *   - data: Optional command data to include in the APDU body (`Lc + Data`).
     *   - le: Optional expected length of response data (`Le`). If provided, an `Le` byte is appended.
     *
     * - Throws: `IdCardInternalError.swError(_:)` if the card's final status word is not `0x9000`, or any error thrown during transmission.
     *
     * - Returns: The full response data returned by the card (excluding the status word).
     */
    func sendAPDU(cls: UInt8 = 0x00, ins: UInt8, p1: UInt8 = 0x00, p2: UInt8 = 0x00,
                  data: (any RangeReplaceableCollection<UInt8>)? = nil, le: UInt8? = nil) async throws -> Data {
        var apdu: Bytes = [cls, ins, p1, p2]
        if let data {
            apdu.append(UInt8(data.count))
            apdu += data
        }
        if let le {
            apdu += [le]
        }
        var (result, sw) = try await transmit(apdu)

        // Handle SW 6CXX (Wrong length, correct length provided in SW2)
        if (sw & 0xFF00) == 0x6C00 {
            apdu[apdu.count - 1] = UInt8(truncatingIfNeeded: sw)
            (result, sw) = try await transmit(apdu)
        }

        // Handle SW 61XX (More data available, use GET RESPONSE command)
        while (sw & 0xFF00) == 0x6100 {
            let (additionalData, newSW) = try await transmit([0x00, 0xC0, 0x00, 0x00, UInt8(truncatingIfNeeded: sw)])
            result.append(contentsOf: additionalData)
            sw = newSW
        }

        guard sw == 0x9000 else {
            throw IdCardInternalError.swError(sw)
        }
        return Data(result)
    }
}
