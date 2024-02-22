/*
 * Copyright 2017 - 2023 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import SwiftUI
import nfclib

struct CardInfoView: View {
    var cardInfo: CardInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Given Name: \(cardInfo.givenName)")
            Text("Surname: \(cardInfo.surname)")
            Text("Personal Code: \(cardInfo.personalCode)")
            Text("Citizenship: \(cardInfo.citizenship)")
            Text("Date of Expiry: \(cardInfo.dateOfExpiry)")
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
