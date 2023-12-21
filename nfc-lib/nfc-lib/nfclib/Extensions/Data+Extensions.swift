//
//  Data+Extensions.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 20.12.2023.
//

extension Data {
    func padDataTo48Bytes() -> Data {
        var paddedData = self
        let requiredSize = 48

        if paddedData.count < requiredSize {
            let paddingSize = requiredSize - paddedData.count
            let padding = Data(repeating: 0, count: paddingSize)
            paddedData.append(padding)
        }

        return paddedData
    }

}
