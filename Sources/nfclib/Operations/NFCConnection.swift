// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
@preconcurrency import CoreNFC

// Allow CoreNFC types to cross async boundaries in this controlled context
extension NFCTagReaderSession: @unchecked @retroactive Sendable {}
extension NFCTag: @unchecked @retroactive Sendable {}

@MainActor
public class NFCConnection: NSObject, @MainActor NFCTagReaderSessionDelegate {
    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<NFCISO7816Tag, Error>?
    private var invalidationError: Error?

    override private init() {}

    /// Runs an operation on a new connection. On success the session is closed with `successMessage`,
    /// on failure `onError` maps the error to the error that is thrown and the message the session is
    /// invalidated with. Cancelling the calling task invalidates the session, and any failure after
    /// cancellation is passed to `onError` as `cancelledByUser`. A failure after the session was
    /// invalidated (e.g. the user cancelled the sheet or it timed out) is passed as that reason.
    public static func run<T>(
        successMessage: String = "Data read",
        onError: (Error) -> (error: Error, message: String) = { (error: $0, message: "Failed to read data") },
        _ operation: (NFCConnection) async throws -> T
    ) async throws -> T {
        let connection = NFCConnection()
        defer { connection.session = nil }
        do {
            let result = try await withTaskCancellationHandler {
                try await operation(connection)
            } onCancel: {
                Task { @MainActor [weak connection] in connection?.session?.invalidate() }
            }
            connection.session?.alertMessage = successMessage
            connection.session?.invalidate()
            return result
        } catch {
            let error: Error = if Task.isCancelled || error is CancellationError {
                IdCardInternalError.cancelledByUser
            } else {
                connection.invalidationError ?? error
            }
            let failure = onError(error)
            connection.session?.invalidate(errorMessage: failure.message)
            throw failure.error
        }
    }

    /// Starts the session showing `message`, and once a card is detected shows `detectedMessage`
    /// while it is connected to and set up with `CAN`.
    public func connect(CAN: String, message: String, detectedMessage: String) async throws -> CardCommands {
        try Task.checkCancellation()
        guard NFCTagReaderSession.readingAvailable else {
            throw IdCardInternalError.nfcNotSupported
        }
        guard self.session == nil else { throw IdCardInternalError.operationInProgress }
        guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: DispatchQueue.main) else {
            throw IdCardInternalError.nfcNotSupported
        }
        session.alertMessage = message
        self.session = session
        invalidationError = nil
        return try await withTaskCancellationHandler {
            let tag = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<NFCISO7816Tag, Error>) in
                self.continuation = continuation
                session.begin()
            }
            session.alertMessage = detectedMessage
            do {
                try await session.connect(to: .iso7816(tag))
            } catch {
                throw invalidationError ?? IdCardInternalError.connectionFailed
            }
            return try await cardCommands(tag: tag, CAN: CAN)
        } onCancel: {
            Task { @MainActor [weak self] in self?.session?.invalidate() }
        }
    }

    private func cardCommands(tag: NFCISO7816Tag, CAN: String) async throws -> CardCommands {
        guard let aid = Bytes(hex: tag.initialSelectedAID), !aid.isEmpty else {
            throw IdCardInternalError.connectionFailed
        }

        let reader = try await CardReaderNFC(tag, CAN: CAN) { [weak self] in self?.invalidationError }

        // Try Idemia with explicit AID
        if let cmd = Idemia(reader: reader, aid: aid) {
            return cmd
        }
        // Try Thales with explicit AID
        if let cmd = Thales(reader: reader, aid: aid) {
            return cmd
        }
        // Try Idemia selecting AID
        if let cmd = await Idemia(reader: reader, selectAID: true) {
            return cmd
        }
        // Try Thales selecting AID
        if let cmd = await Thales(reader: reader, selectAID: true) {
            return cmd
        }

        throw IdCardInternalError.cardNotSupported
    }

    public func message(_ message: String) {
        session?.alertMessage = message
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard tags.count == 1, let firstTag = tags.first else {
            session.alertMessage = "More than one card detected, please present only your ID card"
            Task { @MainActor [weak self] in
                // Give the user time to remove the extra card before polling again
                try? await Task.sleep(for: .milliseconds(500))
                self?.session?.restartPolling()
            }
            return
        }
        guard case let .iso7816(tag) = firstTag else {
            session.alertMessage = "Card not supported, please present your ID card"
            session.restartPolling()
            return
        }
        continuation?.resume(returning: tag)
        continuation = nil
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        guard session === self.session else { return }
        self.session = nil
        let error = IdCardInternalError.mapSessionInvalidation(error)
        invalidationError = error
        guard let continuation else { return }
        self.continuation = nil
        continuation.resume(throwing: error)
    }
}
