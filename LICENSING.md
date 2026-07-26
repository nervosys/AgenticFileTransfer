# Licensing

Agentic File Transfer (AFT) is **dual-licensed**. You may use it under **either**:

1. the **GNU Affero General Public License, version 3 or later (AGPL-3.0-or-later)**, at no cost; **or**
2. a **commercial license** from Nervosys, LLC, for use cases the AGPL does not suit.

You choose which license applies to your use. If you do nothing, the AGPL applies.

---

## Option 1 — AGPL-3.0-or-later (open source, free)

The full text is in [`LICENSE`](LICENSE). In plain terms, the AGPL lets you use,
study, modify, and redistribute AFT for free, provided you honor its copyleft
obligations. The obligation most people overlook is the **network clause**:

> **AGPL §13 — Remote Network Interaction.** If you modify AFT and let users
> interact with it *over a network* (for example, embedding it in a hosted or
> SaaS product), you must offer those users the **complete corresponding source
> code** of your modified version under the AGPL.

This "source reaches the user even over the network" rule is what distinguishes
the AGPL from the GPL, and it applies whether or not you distribute a binary.

The AGPL is the right choice if:

- your project is itself open source under a compatible license, **or**
- you use AFT internally and never expose a modified version to third parties over a network, **or**
- you are comfortable releasing the source of anything you build on top of AFT.

## Option 2 — Commercial license (proprietary / SaaS)

If you want to:

- ship AFT (or a derivative) inside a **closed-source** product,
- offer a **hosted/SaaS** service built on a modified AFT **without** publishing your source, or
- otherwise use AFT on terms incompatible with the AGPL's copyleft,

then you need a commercial license. It removes the AGPL's copyleft and
source-disclosure obligations in exchange for commercial terms, and can include
options such as warranty, indemnification, and support.

See [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md) for a summary, and contact
**licensing@nervosys.com** to obtain one.

---

## Which do I need? (quick guide)

| Your situation | License |
| --- | --- |
| Personal use, evaluation, research | AGPL (free) |
| Internal tool, never network-exposed to third parties in modified form | AGPL (free) |
| Contributing to / building an open-source project | AGPL (free) |
| Bundling AFT in a proprietary product you distribute | **Commercial** |
| Running a modified AFT as a hosted/SaaS product without sharing source | **Commercial** |
| Any use where you cannot meet AGPL §13 | **Commercial** |

This table is guidance, not legal advice. If you are unsure whether your use
triggers AGPL obligations, consult your own counsel or email
**licensing@nervosys.com**.

---

## Contributions

Unless stated otherwise, contributions you submit for inclusion in AFT are
provided under the **AGPL-3.0-or-later**, matching the project's inbound license
(inbound = outbound). Because AFT is also offered commercially, Nervosys may ask
contributors to agree to a Contributor License Agreement (CLA) or Developer
Certificate of Origin (DCO) sign-off so that the dual-licensing offer can
continue to cover contributed code. See `CONTRIBUTING.md` if present, or ask
before opening a large pull request.

## SPDX identifiers

Every source file carries an SPDX header:

```
// SPDX-License-Identifier: AGPL-3.0-or-later
```

This identifies the **open-source** license of the file. It does not limit
Nervosys's ability to license the same code commercially under Option 2.

---

Copyright © 2024–2026 Nervosys, LLC. All rights reserved to the extent not
granted by the licenses above.
