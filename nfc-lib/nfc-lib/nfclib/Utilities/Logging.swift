//
//  Logging.swift
//  nfclib
//
//  Created by Timo Kallaste on 20.12.2023.
//

import Foundation

func print(_ items: Any..., separator: String = " ", terminator: String = "\n") {
#if DEBUG
    Swift.print(items, separator: separator, terminator: terminator)
#endif
}
