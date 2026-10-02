# Test fixtures

All WSDLs here are **synthetic**. Real Amadeus WSDLs are proprietary
("unauthorized use and disclosure strictly forbidden") and must never be
committed.

| Directory | What | Used by |
|---|---|---|
| `wsdl/` | The two WSDL shapes `WsdlManager` handles (self-contained and `wsdl:import`) | `WsdlManagerTest` asserts its exact operation list: adding a WSDL here breaks it |
| `responses/` | Hand-written replies shaped like Amadeus output | `BookingChainTest` and unit tests |
| `tst/` | Real Amadeus TST traffic, sanitized | `tests/Feature/Tst`, cache, monitoring and failure tests |

The WSDL with all 9 operations, the real response namespaces and the
`AMA_SecurityHostedUser` header type lives outside this directory, in
`resources/testing/wsdl/`: it ships with the package because `Amadeus::fake()`
loads it. `BookingChainTest`, `RecursiveSearchTest` and every test using
`fakeAmadeus()` load it too (`AmadeusFake::wsdlDirectory()`).

Its `AMA_SecurityHostedUser` declaration matters for envelope tests: without
it SoapClient serializes the header as a generic `item/key/value` map instead
of `<UserID PseudoCityCode="..."/>`.

## `tst/`

- `requests/` — the SOAP Body of requests Amadeus TST accepted. Feature tests
  assert the package builds exactly these bodies (`assertSoapBodyMatchesFixture`).
- `responses/` — full SOAP replies, queued on `ReplaySoapClient`
  (`fakeAmadeus()` in `tests/TestCase.php`), which only intercepts HTTP, so
  parsing runs on real data through the real SOAP layer.

They come from several runs, not one booking. `hotel-sell.xml` (success) and
`hotel-sell-ctl-error.xml` (error `CTL`, nothing booked) come from different
attempts — `CTL` is a per-rate refusal (see CLAUDE.md, "Verified against
Amadeus TST"). The requests from the end transaction on (`pnr-end`,
`pnr-retrieve`, `hotel-complete-reservation-details`, `pnr-cancel`,
`pnr-cancel-end`) and the `pnr-cancel*` replies come from a later complete
booking that was cancelled (PNR `TST003`, hotel segment 2); the other replies
are from the earlier run (PNR `TST002`).

New captures go at the **end** of `FIXTURES`: fake locators are numbered in
map order, and tests pin `TST002` and `10000001`. Appending only renumbers the
fake session IDs and tokens in the other replies, which no test pins.

### Regenerating

1. Capture with the smoke script, which writes request/response XML to
   `storage/tst-chain/` (git-ignored):

   ```bash
   php scripts/tst-chain.php --city=MTY --dump-all
   ```

2. Turn captures into fixtures. Credentials and card data are read from
   `.env.tst` (git-ignored; template in `.env.tst.example`):

   ```bash
   php tests/Fixtures/sanitize-tst-captures.php storage/tst-chain .env.tst
   ```

The capture → fixture mapping is the `FIXTURES` constant in the script; new
captures have new file names, so update it first. The script replaces
credentials, office ID, WSAP and endpoint, session tokens, PNR and confirmation
numbers, the agency IATA number, names, emails, card data, and phone or loyalty
numbers in PNR free texts with fixed fakes; keeps only the Body of requests;
and **refuses to write** if any known secret survives. Review the diff before
committing new fixtures anyway.
