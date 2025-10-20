//
//  CardReader.swift
//  IdCardLib
//
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

typealias Bytes = [UInt8]
@MainActor
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
     * - **`0x6CXX`**: Indicates incorrect expected length (`Le`).
     * The command is resent using the correct length from `SW2`.
     * - **`0x61XX`**: Indicates more response data is available.
     * The method issues one or more `GET RESPONSE` commands (INS = `0xC0`)
     * to retrieve the remaining data.
     *
     * If the final response status word is not `0x9000`, the method throws a
     * `IdCardInternalError.swError(_:)` with the returned status word.
     *
     * - Parameters:
     *   - cls: The class byte (CLA) of the command. Defaults to `0x00`.
     *   - ins: The instruction byte (INS) of the command.
     *   - p1: The first parameter byte (P1). Defaults to `0x00`.
     *   - p2: The second parameter byte (P2). Defaults to `0x00`.
     *   - data: Optional command data to include in the APDU body (`Lc + Data`).
     *   - le: Optional expected length of response data (`Le`). If provided, an `Le` byte is appended.
     *
     * - Throws: `IdCardInternalError.swError(_:)`
     * if the card's final status word is not `0x9000`, or any error thrown during transmission.
     *
     * - Returns: The full response data returned by the card (excluding the status word).
     */
    func sendAPDU(cls: UInt8 = 0x00, ins: UInt8, p1Byte: UInt8 = 0x00, p2Byte: UInt8 = 0x00,
                  data: (any RangeReplaceableCollection<UInt8>)? = nil, leByte: UInt8? = nil) async throws -> Data {
        var apdu: Bytes = [cls, ins, p1Byte, p2Byte]
        if let data {
            apdu.append(UInt8(data.count))
            apdu += data
        }
        if let leByte {
            apdu += [leByte]
        }
        var (result, swValue) = try await transmit(apdu)

        // Handle SW 6CXX (Wrong length, correct length provided in SW2)
        if (swValue & 0xFF00) == 0x6C00 {
            apdu[apdu.count - 1] = UInt8(truncatingIfNeeded: swValue)
            (result, swValue) = try await transmit(apdu)
        }

        // Handle SW 61XX (More data available, use GET RESPONSE command)
        while (swValue & 0xFF00) == 0x6100 {
            let (
                additionalData,
                newSW
            ) = try await transmit(
                [
                    0x00,
                    0xC0,
                    0x00,
                    0x00,
                    UInt8(
                        truncatingIfNeeded: swValue
                    )
                ]
            )
            result.append(contentsOf: additionalData)
            swValue = newSW
        }

        guard swValue == 0x9000 else {
            throw IdCardInternalError.swError(swValue)
        }
        return Data(result)
    }
}
