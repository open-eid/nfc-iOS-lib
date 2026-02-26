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

import OSLog
import Foundation
import iR301

public actor UsbReaderConnection {
    private static let logger = Logger(subsystem: "ee.ria.nfc-iOS-lib", category: "UsbReaderConnection")
    private var handle: SCARDCONTEXT = 0
    private var handler: UsbReaderInterfaceHandler?
    private var status: UsbReaderStatus = .sInitial
    private var cardHandler: CardCommands?
    private var continuation: AsyncStream<UsbReaderStatus>.Continuation?

    public init() {}

    public func startDiscoveringReaders() async {
        await ensureHandler()

        guard handle == 0 else {
            UsbReaderConnection.logger.error("ID-CARD: Reader discovery is already running")
            return
        }

        UsbReaderConnection.logger.info("ID-CARD: Starting reader discovery")
        await updateStatus(status)

        let result = SCardEstablishContext(DWORD(SCARD_SCOPE_SYSTEM), nil, nil, &handle)

        guard result == SCARD_S_SUCCESS else {
            await updateStatus(.sReaderProcessFailed)
            handle = 0
            return
        }

        UsbReaderConnection.logger.info("ID-CARD: Started reader discovery: \(self.handle)")
    }

    public func stopDiscoveringReaders(with status: UsbReaderStatus = .sInitial) async {
        await ensureHandler()

        UsbReaderConnection.logger.info("ID-CARD: Stopping reader discovery")
        self.status = status
        FtDidEnterBackground(1)
        SCardCancel(handle)
        SCardReleaseContext(handle)
        UsbReaderConnection.logger.info("ID-CARD: Stopped reader discovery with status: \(self.handle)")
        handle = 0
    }

    public func updateStatus(_ status: UsbReaderStatus) async {
        self.status = status
        continuation?.yield(status)
    }

    public func getHandle() async -> SCARDCONTEXT {
        return handle
    }

    public func getCardHandler() throws -> CardCommands {
        guard let cardCommands = self.cardHandler else {
            throw IdCardInternalError.connectionFailed
        }

        return cardCommands
    }

    public func setCardHandler(_ handler: CardCommands?) {
        self.cardHandler = handler
    }

    public func statusStream() -> AsyncStream<UsbReaderStatus> {
        AsyncStream { continuation in
            self.continuation = continuation
            continuation.yield(status)
        }
    }

    // MARK: Handler

    private func ensureHandler() async {
        guard handler == nil else { return }
        handler = await MainActor.run {
            UsbReaderInterfaceHandler(usbReaderConnection: self)
        }
    }
}

private final class UsbReaderInterfaceHandler: NSObject, ReaderInterfaceDelegate, Sendable {
    private static let logger = Logger(subsystem: "ee.ria.nfc-iOS-lib", category: "UsbReaderInterfaceHandler")
    @MainActor
    private let readerInterface = ReaderInterface()

    private let usbReaderConnection: UsbReaderConnection

    init(
        usbReaderConnection: UsbReaderConnection
    ) {
        self.usbReaderConnection = usbReaderConnection
        super.init()
        Task { @MainActor in
            readerInterface.setDelegate(self)
        }
    }

    func readerInterfaceDidChange(_ attached: Bool, bluetoothID _: String?) {
        UsbReaderInterfaceHandler.logger.info("ID-CARD: Reader attached: \(attached)")
        Task {
            await usbReaderConnection.updateStatus(attached ? .sReaderConnected : .sReaderNotConnected)
        }
    }

    func cardInterfaceDidDetach(_ attached: Bool) {
        UsbReaderInterfaceHandler.logger.info("ID-CARD: Card (interface) attached: \(attached)")
        Task {
            do {
                let contextHandle = await usbReaderConnection.getHandle()

                guard attached, let reader = try CardReaderiR301(contextHandle: contextHandle) else {
                    return await usbReaderConnection.updateStatus(.sReaderConnected)
                }

                let handler: CardCommands?

                do {
                    if let idemia = Idemia(reader: reader, atr: reader.atr) {
                        handler = idemia
                    } else {
                        handler = try Thales(reader: reader, atr: reader.atr)
                    }
                } catch {
                    UsbReaderInterfaceHandler.logger.error("ID-CARD: Unable to connect card. \(error)")
                    await usbReaderConnection.setCardHandler(nil)
                    await usbReaderConnection.updateStatus(.sReaderProcessFailed)
                    return
                }

                if let handler {
                    await usbReaderConnection.setCardHandler(handler)

                    UsbReaderInterfaceHandler.logger.info("ID-CARD: Card connected")

                    await usbReaderConnection.updateStatus(.sCardConnected)
                }
            } catch {
                UsbReaderInterfaceHandler.logger.error("ID-CARD: Unable to power on card")
                await usbReaderConnection.updateStatus(.sReaderProcessFailed)
            }
        }
    }

    func didGetBattery(_: Int) {}

    func findPeripheralReader(_ readerName: String) {
        UsbReaderInterfaceHandler.logger.info("ID-CARD: Reader name: \(readerName)")
    }
}
