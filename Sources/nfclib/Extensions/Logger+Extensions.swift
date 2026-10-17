// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import os

public enum NFCLibLogging {
    private static let enabled = OSAllocatedUnfairLock(initialState: false)

    public static var isEnabled: Bool {
        get { enabled.withLock { $0 } }
        set { enabled.withLock { $0 = newValue } }
    }
}

extension Logger {
    func debugSensitive(_ message: @autoclosure () -> String) {
        #if ENABLE_LOGGING
        guard NFCLibLogging.isEnabled else { return }
        let value = message()
        debug("\(value, privacy: .public)")
        #endif
    }
}
