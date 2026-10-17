// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

internal import SwiftECC

extension Domain {
    /// The same curve with a different generator, e.g. the mapped generator Ĝ in PACE.
    func withGenerator(_ generator: Point) throws -> Domain {
        try Domain.instance(
            name: name + " Mapped",
            p: p,
            a: a,
            b: b,
            gx: generator.x,
            gy: generator.y,
            order: order,
            cofactor: cofactor
        )
    }
}
