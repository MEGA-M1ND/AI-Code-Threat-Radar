# Example entries

Everything in this directory is fake. The identifiers use the reserved year
`9999`, and every domain is under `.invalid`, which is reserved by RFC 2606 and
can never resolve. These files exist so the tests have something to accept and
something to reject, and so the docs have something to point at.

Nothing here is ever built into `dist/`. `scripts/build.py` reads
`data/entries/` only.

| File | What it is for |
| --- | --- |
| `valid-entry.json` | A minimal entry that satisfies the schema and the house rules. |
| `invalid-no-primary-source.json` | Only secondary sources. Must be rejected. |
| `invalid-bad-id.json` | `id` is not `RS-YYYY-NNNN`. Must be rejected. |
| `invalid-unknown-field.json` | Carries a field the schema does not define. Must be rejected. |
| `invalid-no-indicators.json` | Empty `indicators` array. Must be rejected. |
| `invalid-long-summary.json` | Summary longer than two sentences. Must be rejected. |
| `invalid-bad-indicator.json` | Indicator with an unknown `registry`. Must be rejected. |
