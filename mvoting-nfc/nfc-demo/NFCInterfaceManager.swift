////
////  NFCInterfaceManager.swift
////  nfc-demo
////
////  Created by Timo Kallaste on 15.11.2023.
////
//
//import SwiftUI
//import CoreNFC
//import nfc_lib
//
//@available(iOS 13.0, *)
//public class NFCReader: NSObject, ObservableObject, NFCTagReaderSessionDelegate {
//    public var startAlert = "Hold your iPhone near the tag."
//    public var endAlert = ""
//    public var msg = "Scan to read or Edit here to write..."
//    public var raw = "Raw Data available after scan."
//
//    public var session: NFCTagReaderSession?
//
//    public func read() {
//        guard NFCNDEFReaderSession.readingAvailable else {
//            print("Error")
//            return
//        }
//        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
//        session?.alertMessage = self.startAlert
//        session?.begin()
//    }
//
//    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
//        print("didDetect \(tags)")
//    }
//
//    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
//        print("tagReaderSessionDidBecomeActive \(session)")
//    }
//
//    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
//        print("didInvalidateWithError \(error)")
//    }
//}
//
//public class NFCWriter: NSObject, ObservableObject, NFCNDEFReaderSessionDelegate {
//
//    public var startAlert = "Hold your iPhone near the tag."
//    public var endAlert = ""
//    public var msg = ""
//    public var type = "T"
//
//    public var session: NFCNDEFReaderSession?
//
//    public func write() {
//        guard NFCNDEFReaderSession.readingAvailable else {
//            print("Error")
//            return
//        }
//        session = NFCNDEFReaderSession(delegate: self, queue: nil, invalidateAfterFirstRead: true)
//        session?.alertMessage = self.startAlert
//        session?.begin()
//    }
//
//    public func readerSession(_ session: NFCNDEFReaderSession, didDetectNDEFs messages: [NFCNDEFMessage]) {
//    }
//
//    public func readerSession(_ session: NFCNDEFReaderSession, didDetect tags: [NFCNDEFTag]) {
//        if tags.count > 1 {
//            let retryInterval = DispatchTimeInterval.milliseconds(500)
//            session.alertMessage = "Detected more than 1 tag. Please try again."
//            DispatchQueue.global().asyncAfter(deadline: .now() + retryInterval, execute: {
//                session.restartPolling()
//            })
//            return
//        }
//
//        let tag = tags.first!
//        session.connect(to: tag, completionHandler: { (error: Error?) in
//            if nil != error {
//                session.alertMessage = "Unable to connect to tag."
//                session.invalidate()
//                return
//            }
//
//            tag.queryNDEFStatus(completionHandler: { (ndefStatus: NFCNDEFStatus, capacity: Int, error: Error?) in
//                guard error == nil else {
//                    session.alertMessage = "Unable to query the status of tag."
//                    session.invalidate()
//                    return
//                }
//
//                switch ndefStatus {
//                case .notSupported:
//                    session.alertMessage = "Tag is not NDEF compliant."
//                    session.invalidate()
//                case .readOnly:
//                    session.alertMessage = "Read only tag detected."
//                    session.invalidate()
//                case .readWrite:
//                    let payload: NFCNDEFPayload?
//                    if self.type == "T" {
//                        payload = NFCNDEFPayload.init(
//                            format: .nfcWellKnown,
//                            type: Data("\(self.type)".utf8),
//                            identifier: Data(),
//                            payload: Data("\(self.msg)".utf8)
//                        )
//                    } else {
//                        payload = NFCNDEFPayload.wellKnownTypeURIPayload(string: "\(self.msg)")
//                    }
//                    let message = NFCNDEFMessage(records: [payload].compactMap({ $0 }))
//                    tag.writeNDEF(message, completionHandler: { (error: Error?) in
//                        if nil != error {
//                            session.alertMessage = "Write to tag fail: \(error!)"
//                        } else {
//                            session.alertMessage = self.endAlert != "" ? self.endAlert : "Write \(self.msg) to tag successful."
//                        }
//                        session.invalidate()
//                    })
//                @unknown default:
//                    session.alertMessage = "Unknown tag status."
//                    session.invalidate()
//                }
//            })
//        })
//    }
//
//    public func readerSessionDidBecomeActive(_ session: NFCNDEFReaderSession) {
//    }
//
//    public func readerSession(_ session: NFCNDEFReaderSession, didInvalidateWithError error: Error) {
//        print("Session did invalidate with error: \(error)")
//        self.session = nil
//    }
//}
//
