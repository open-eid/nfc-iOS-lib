//
//  ReaderConnection.swift
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
import iR301
import OSLog

public protocol UsbReaderConnectionDelegate: AnyObject {
    func readerStatusDidChange(_ status: UsbReaderStatus)
}

public enum UsbReaderStatus {
    case sInitial
    case sReaderNotConnected
    case sReaderRestarted
    case sReaderConnected
    case sCardConnected(CardCommands)
    case sReaderProcessFailed
}

@MainActor
public class UsbReaderConnection {
    private static let logger = Logger(subsystem: "ee.ria.digidoc.RIADigiDoc", category: "ReaderConnection")
    public static let shared = UsbReaderConnection()

    public weak var delegate: UsbReaderConnectionDelegate?
    fileprivate var handle: SCARDCONTEXT = 0
    private var handler = UsbReaderInterfaceHandler()
    private var status: UsbReaderStatus = .sInitial

    private init() {
    }

    public func startDiscoveringReaders() {
        guard handle == 0 else {
            UsbReaderConnection.logger.error("ID-CARD: Reader discovery is already running")
            return
        }
        UsbReaderConnection.logger.debug("ID-CARD: Starting reader discovery")
        updateStatus(status)
        SCardEstablishContext(DWORD(SCARD_SCOPE_SYSTEM), nil, nil, &handle)
        UsbReaderConnection.logger.debug("ID-CARD: Started reader discovery: \(self.handle)")
    }

    public func stopDiscoveringReaders(with status: UsbReaderStatus = .sInitial) {
        UsbReaderConnection.logger.debug("ID-CARD: Stopping reader discovery")
        self.status = status
        FtDidEnterBackground(1)
        SCardCancel(handle)
        SCardReleaseContext(handle)
        UsbReaderConnection.logger.debug("ID-CARD: Stopped reader discovery with status: \(self.handle)")
        handle = 0
    }

    fileprivate func updateStatus(_ status: UsbReaderStatus) {
        self.status = status
        DispatchQueue.main.async {
            self.delegate?.readerStatusDidChange(status)
        }
    }
}

@MainActor
private class UsbReaderInterfaceHandler: NSObject, @MainActor ReaderInterfaceDelegate {
    private static let logger = Logger(subsystem: "ee.ria.digidoc.RIADigiDoc", category: "ReaderInterfaceDelegate")
    private let readerInterface = ReaderInterface()

    override init() {
        super.init()
        readerInterface.setDelegate(self)
    }

    func readerInterfaceDidChange(_ attached: Bool, bluetoothID _: String?) {
        UsbReaderInterfaceHandler.logger.debug("ID-CARD attached: \(attached)")
        UsbReaderConnection.shared.updateStatus(attached ? .sReaderConnected : .sReaderNotConnected)
    }

    func cardInterfaceDidDetach(_ attached: Bool) {
        UsbReaderInterfaceHandler.logger.debug("ID-CARD: Card (interface) attached: \(attached)")
        do {
            guard attached, let reader = try CardReaderiR301(contextHandle: UsbReaderConnection.shared.handle) else {
                return UsbReaderConnection.shared.updateStatus(.sReaderConnected)
            }
            if let handler: CardCommands = Idemia(reader: reader, atr: reader.atr)
                ?? (try? Thales(reader: reader, atr: reader.atr)) {
                UsbReaderConnection.shared.updateStatus(.sCardConnected(handler))
            }
        } catch {
            UsbReaderInterfaceHandler.logger.debug("ID-CARD: Unable to power on card")
            UsbReaderConnection.shared.updateStatus(.sReaderProcessFailed)
        }
    }

    func didGetBattery(_: Int) {
        // Implement if needed
    }

    func findPeripheralReader(_ readerName: String) {
        UsbReaderInterfaceHandler.logger.debug("ID-CARD: Reader name: \(readerName)")
    }
}
