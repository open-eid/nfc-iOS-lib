// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import SwiftUI
import nfclib

@main
struct mvoting_nfcApp: App {
    init() {
        // Set to true (and add -D ENABLE_LOGGING to the nfclib target's Other Swift Flags) to see sensitive logs.
        NFCLibLogging.isEnabled = false
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
