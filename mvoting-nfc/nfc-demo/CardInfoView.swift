// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import SwiftUI
import nfclib

struct CardInfoView: View {
    var cardInfo: CardInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Card: \(cardInfo.cardType.rawValue)")
            Text("Given Name: \(cardInfo.givenName)")
            Text("Surname: \(cardInfo.surname)")
            Text("Personal Code: \(cardInfo.personalCode)")
            if !cardInfo.citizenship.isEmpty {
                Text("Citizenship: \(cardInfo.citizenship)")
            }
            if !cardInfo.issuingCountry.isEmpty {
                Text("Issuing Country: \(cardInfo.issuingCountry)")
            }
            if !cardInfo.dateOfExpiry.isEmpty {
                Text("Date of Expiry: \(cardInfo.dateOfExpiry)")
            }
            if let certificateExpiryDate = cardInfo.certificateExpiryDate {
                Text("Certificate Expiry: \(certificateExpiryDate.formatted(date: .numeric, time: .omitted))")
            }
        }
        .padding()
    }
}

// Preview Provider
struct CardInfoView_Previews: PreviewProvider {
    static var previews: some View {
        CardInfoView(cardInfo: CardInfo(givenName: "Jaak-Kristjan", surname: "Jõeorg", personalCode: "123456789", citizenship: "EST", dateOfExpiry: "11.12.1234"))
    }
}
