// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

enum PersonalCodeParser {

    static func estonianDateOfBirth(_ personalCode: String) -> Date? {
        let digits = Array(personalCode)
        guard digits.count >= 7, digits.prefix(7).allSatisfy(\.isASCIIDigit) else { return nil }

        let century: Int
        switch digits[0].wholeNumberValue {
        case 1, 2: century = 1800
        case 3, 4: century = 1900
        case 5, 6: century = 2000
        case 7, 8: century = 2100
        default: return nil
        }

        guard let yearInCentury = Int(String(digits[1...2])),
              let month = Int(String(digits[3...4])),
              let day = Int(String(digits[5...6])) else { return nil }

        return gregorianDate(year: century + yearInCentury, month: month, day: day)
    }

    /**
     * Parse date of birth from Latvian personal code.
     *
     * Old format (pre-2017): DDMMYY-CZZZQ where C is century digit (0=18xx, 1=19xx, 2=20xx)
     * New format (from 2017): starts with "32", DOB not encoded — returns nil.
     */
    static func latvianDateOfBirth(_ personalCode: String) -> Date? {
        let digits = Array(personalCode.replacing("-", with: ""))
        guard digits.count >= 7, digits.prefix(7).allSatisfy(\.isASCIIDigit) else { return nil }
        guard !digits.starts(with: ["3", "2"]) else { return nil }

        let century: Int
        switch digits[6].wholeNumberValue {
        case 0: century = 1800
        case 1: century = 1900
        case 2: century = 2000
        default: return nil
        }

        guard let day = Int(String(digits[0...1])),
              let month = Int(String(digits[2...3])),
              let yearInCentury = Int(String(digits[4...5])) else { return nil }

        return gregorianDate(year: century + yearInCentury, month: month, day: day)
    }

    private static func gregorianDate(year: Int, month: Int, day: Int) -> Date? {
        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? calendar.timeZone
        guard let date = calendar.date(from: components) else { return nil }

        let rounded = calendar.dateComponents([.year, .month, .day], from: date)
        guard rounded.year == year, rounded.month == month, rounded.day == day else { return nil }
        return date
    }
}

private extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}
