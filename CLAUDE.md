# CLAUDE.md — amadeus-soap

## Project Overview

Laravel package wrapping the Amadeus Globalizer SOAP Web Services API for hotel booking operations. Handles WS-Security authentication, stateful SOAP sessions, WSDL parsing, and typed response DTOs.

- **Namespace:** `Aldogtz\AmadeusSoap`
- **PHP:** ^8.2 (readonly classes, enums, constructor promotion)
- **Framework:** Laravel via `spatie/laravel-package-tools`
- **Testing:** Pest (^2.0|^3.0) with Orchestra Testbench

## Commands

```bash
# Run tests
./vendor/bin/pest

# Run a specific test file
./vendor/bin/pest tests/Unit/Operations/HotelSearchTest.php

# Run a specific test by name
./vendor/bin/pest --filter="test_it_builds_multi_city_search"

# Install dependencies
composer install
```

## Architecture

### Execution Flow

```
Params::fromArray() → Operation::build() → BodyBuilder → HeaderBuilder → SoapTransport → AmadeusResponse → *Response::fromResponse()
```

1. **Params validation** — readonly DTOs with `ValidatesParams` trait
2. **Operation build** — implements `Operation` interface (`getOperationName()`, `build()`)
3. **WSDL resolution** — `WsdlManager` lazy-loads and caches operation metadata in `OperationRegistry`
4. **Headers** — `HeaderBuilder` composes WS-Security, AMA Security, Session, and Addressing headers
5. **Transport** — `SoapTransport` executes call with `RetryHandler` (exponential backoff, only `ConnectionException`)
6. **Response** — `AmadeusResponse` wraps XML, typed response DTOs use `ParsesAmadeusXml` trait

### Key Directories

```
src/
├── AmadeusSoap.php              # Main service (orchestrates operations)
├── AmadeusSoapServiceProvider.php
├── Cache/                       # OperationCache (stateless responses only), SearchCacheLevel enum
├── Client/                      # SoapTransport, SoapClientFactory (per-WSDL client pool), RetryHandler
├── Data/
│   ├── *Params.php              # Readonly param DTOs with validation
│   ├── AmadeusResponse.php      # Raw XML wrapper with XPath
│   └── Responses/               # Typed response DTOs
│       ├── Concerns/ParsesAmadeusXml.php  # XPath helpers
│       └── Values/              # Value objects (AmadeusError, etc.)
├── Events/                      # OperationStarting, OperationCompleted, OperationFailed
├── Exceptions/                  # Typed exceptions (Connection, Auth, Session, SoapFault, etc.)
├── Headers/                     # HeaderBuilder, BodyBuilder, SessionHeader, AddressingHeaders
├── Logging/SoapLogger.php
├── Performance/PerformanceMonitor.php  # Event subscriber; metrics in a cache store
├── Operations/                  # Operation builders (implement Operation interface)
│   ├── Contracts/Operation.php  # Interface: getOperationName(), build()
│   └── Concerns/BuildsGuestCounts.php
├── Facades/Amadeus.php          # Facade (composer alias: AmadeusSoap)
├── Security/                    # WsSecurityHeader, AmaSecurityHeader
├── Session/
│   ├── Contracts/SessionStore.php
│   ├── SessionManager.php
│   ├── SessionData.php          # Readonly: sessionId, sequenceNumber, securityToken
│   └── Stores/                  # Redis, Cache, File, Array, Null
├── RateFiltering/               # RateFilterStrategy (BestOnlyIndicator), RateFilterCriteria,
│                                # RateFilter (local, per hotel), TwoPhaseSearchService
└── Wsdl/                        # WsdlManager, OperationRegistry, OperationMetadata
```

Performance features (all opt-in, see `docs/performance.md`):
- `OperationCache` serves only stateless calls (multi search by city/coordinates,
  descriptive info); a hit skips transport, session and events. Store errors are
  reported and swallowed. Key = request body + office ID + WSDL path + the
  endpoint from the WSDL (where the request actually goes).
- `PerformanceMonitor` subscribes to `OperationCompleted`/`OperationFailed`;
  store errors are swallowed so they can never fail a completed sell.
- `rate_filter_criteria` filters the room stays of a search **by hotel code**
  locally; without `hotel_code` it is rejected.

### Verified against Amadeus TST

All nine operations have run against the real TST endpoint. A full booking
completed on `CPMTYE71` (hotel segment 2), returning the hotel confirmation in
`HotelSellResponse::$confirmationNumber` — the same number PNR_Reply reports
for the segment — with `hotelCompleteReservationDetails` returning the property's real
cancellation policy and total.

Operational constraints learned from those runs, none of them visible from the
API surface:

- **Every step from the single-hotel search to the sell must stay on one
  property.** Each `hotelSearch('single', …)` replaces the session's
  availability context, so searching a second property and then pricing the
  first fails with `<Errors><Error Code="SCI"/></Errors>`. The sell tolerates a
  replaced context; pricing does not.
- **`errorGroup` code `CTL` on a sell is per rate.** `CPMTYE71` sells booking
  code `STN57JU` and refuses `KNG57JU` in the same session, with requests that
  differ only in that value. Retry the remaining rates from the single-hotel
  search rather than rebuilding the request — the session and its availability
  context survive a refusal, and re-searching would replace the context.
  Nothing in the rate's shape predicts it: `*RH` with a `Converted:BAR:P`
  category sells, and two earlier attempts to guess from those markers (first
  "unsellable placeholder", then "property-specific") were both wrong.
- **`errorGroup` can carry only a code**, with no `errorWarningDescription`.
  `HotelSellResponse` used to report nothing for that shape, which made a
  refused sell look like a completed one.

- **Pricing needs a stateful single-hotel search first.** A city-wide
  `hotelSearch('multi')` is stateless and its booking codes are summary values.
  Pricing one directly returns `<Errors><Error Code="SCM"/></Errors>` with an
  empty message. Run `hotelSearch('single', ['hotel_code' => …])` for the chosen
  property, take its fresh `bookingCode`, and price that — then carry the same
  code into `hotelSell`.
- **Do not filter a property search by a rate plan code a city search
  reported.** Those are converted values (plan `RAFNOV` for booking code
  `B2DRAFNOV` — room type and plan concatenated). Filtering by one gets
  `RATE NOT LOADED`, `Error Code="842"`. Pass rate plan codes the office has
  loaded, or `rate_code => []` to omit the filter.
- **`SearchCacheLevel` defaults to `Live`**, and a city search on it takes
  ~11s against TST. Pass `search_cache_level => 'VeryRecent'` when iterating.
- **Amadeus puts its error code in `faultstring`**, not `faultcode`, as
  `code|Category|text` — `faultcode` stays `soap:Client`. Use
  `SoapTransport::parseAmadeusFault()`.

### Amadeus response shapes that bite

Learned by running the package against real Amadeus replies. All fixed, all
covered by tests — do not undo these:

- **`HotelStay/@RoomStayRPH` is a space-separated list** (`"0 1 2"`) when a
  property has several rates. Comparing the raw attribute against
  `RoomStay/@RPH` matches nothing, which left every multi-rate property with a
  null total and empty plan/dates. Pair through `HotelResult::roomStays()`, or
  read the parsed `HotelResult::$roomStayRPHs`.
- **`Hotel_SellReply` nests differently from the Hotel_Sell request.** The reply
  uses `globalBookingInfo/bookingInfo/reservation/controlNumber` and
  `globalBookingInfo/hotelPropertyInfo/hotelReference`; the request-side names
  (`bookingRecordId`, `bookingConfirmationNumber`, `markerGlobalBookingInfo`)
  never appear in a reply. Reading only those returned a null booking reference
  for every sale. `confirmationNumber` is that reservation `controlNumber`; the
  booking code is only the echo of the request (`roomResults[].bookingCode`).
- **`CancelPenalty/@NonRefundable` is sometimes absent** (e.g. a 100% penalty
  described only in text). `RoomStayResult::$nonRefundable` is then `null`, and
  such rates pass neither `refundable_only` nor `non_refundable_only`.
- **Amadeus pads values.** The POT segment qualifier arrives as `"POT "`.
  `ParsesAmadeusXml::str()` trims every scalar read; keep it that way.
- **`HotelSearchResponse` parses nothing without `//Warnings/Warning[@Tag='OK']`.**
  A reply missing that marker yields `ok=false` and empty collections, not
  partial data. Response fixtures must include it.
- **Operation builders return associative arrays.** Pass them straight to
  `executeStandardOperation()` / `BodyBuilder::build()`. Wrapping in `[$body]`
  produces a sequential array, which `spatie/array-to-xml` rejects with
  `DOMException: Invalid Character Error` — this made `hotelSell`,
  `addMultiElements`, `pnrRetrieve`, `pnrCancel` and
  `hotelCompleteReservationDetails` throw on every call.

### Wiring caveats

Worth knowing before changing anything here:

- **Nothing in `src/` calls `config()` except `AmadeusSoapServiceProvider`**;
  `AmadeusSoap` reads the config array it is given (`search_cache_level.default`,
  `rate_filtering.default_strategy`, `retention`, `contact_email`).
- `SoapClientFactory` is a container singleton, so `app(SoapClientFactory::class)`
  is the live client pool (tests swap it for `ReplaySoapClientFactory`).
- Deprecated, removed in 3.0 (kept for the 2.x API): `SoapTransport`'s
  `$wsdlManager` parameter (optional, unused) and `WsdlManager::getWsdlDomDoc()`
  / `getWsdlDomXpath()` (always `[]`: `ensureLoaded()` frees the DOMs).
- Every single-hotel search (and `PNR_Retrieve`) starts a **new** Amadeus session.
  The stored one is signed out first (best effort: a failure is reported, never
  thrown; `session.sign_out_replaced`), so it no longer stays open on Amadeus
  until it times out.
- Requests always go to the endpoint in the WSDL (`soap:address`); there is no
  config override.

### Session Management

- **Stateful operations** persist session across requests (SessionId, SequenceNumber, SecurityToken)
- **Stateless operations** don't use sessions (e.g., `Hotel_DescriptiveInfo`)
- **Drivers:** redis (production), cache (flexible), file (dev), array (testing), null (stateless)
- **WS-Security headers** only sent when starting a new session (not for in-series calls)

### Error Handling

```
AmadeusSoapException (base)
├── AuthenticationException    # Invalid credentials (not retried)
├── ConnectionException        # Transient errors (retried)
├── SessionException           # Session expired/invalid
├── SoapFaultException         # Business logic errors
├── XmlParseException          # Malformed XML response
├── InvalidParameterException  # Param validation failure
└── OperationNotFoundException # Unknown operation
```

- All response DTOs use `AmadeusError` value object: `message`, `code`, `type`
- Response-level errors parsed via `ParsesAmadeusXml::parseOtaErrors()`

### Supported Operations

| Amadeus Operation | Class | Stateful |
|---|---|---|
| Hotel_MultiSingleAvailability | HotelSearch | Conditional |
| Hotel_EnhancedPricing | HotelPricing | Yes |
| Hotel_Sell | HotelSell | Yes |
| Hotel_DescriptiveInfo | HotelDescriptiveInfo | No |
| Hotel_CompleteReservationDetails | HotelCompleteReservationDetails | Yes |
| PNR_AddMultiElements | PnrAddMultiElements | Yes |
| PNR_Retrieve | PnrRetrieve | Yes |
| PNR_Cancel | PnrCancel | Yes |
| Security_SignOut | SecuritySignOut | Yes |

## Coding Conventions

- Files do not declare `strict_types` (match the existing code)
- Value objects and params are `final readonly class`
- Response DTOs use static `fromResponse(AmadeusResponse)` factory methods
- Params use static `fromArray(array)` with `ValidatesParams` trait
- Operations implement `Operation` interface; `build()` returns the children of the root
  element, with root attributes under `'_attributes'`
- Session stores implement `SessionStore` interface
- XPath queries use `res` namespace prefix for response elements
- Request params are snake_case array keys in every method; the camelCase keys
  sell / descriptive info / PNR retrieve, cancel and details used before stay
  accepted (`ValidatesParams::acceptSnakeCase()`, `HotelSellParams::normalize()`).
  Response DTO properties are camelCase
- Methods also take the previous step's reply objects instead of arrays
  (`HotelPricingParams::fromRoomStay()`, `HotelSellParams::forRoom()`); keep the
  array form working whenever adding one
- Unit tests are PHPUnit-style classes with `test_*` methods extending
  `PHPUnit\Framework\TestCase`; only `tests/Feature/` gets Pest's `uses()` binding
- Tests needing the container extend `Aldogtz\AmadeusSoap\Tests\TestCase`
  (Orchestra Testbench)
- Test doubles in `tests/Doubles/`; WSDL fixtures in `tests/Fixtures/wsdl/` and `wsdl-full/`
- Never commit raw captures (`storage/`) or `.env.tst`: they hold credentials and PII

## Configuration

Config file: `config/amadeus-soap.php`

Env vars that actually have an effect (read by the ServiceProvider):
- `AMADEUS_WSDL_PATH` — directory containing .wsdl files (required)
- `AMADEUS_USERNAME`, `AMADEUS_PASSWORD`, `AMADEUS_OFFICE_ID` — credentials
- `AMADEUS_SESSION_DRIVER` — redis|cache|file|array|null, plus
  `AMADEUS_SESSION_CONNECTION`, `AMADEUS_SESSION_CACHE_STORE`,
  `AMADEUS_SESSION_PREFIX`, `AMADEUS_SESSION_TTL`
- `AMADEUS_RETRY_ENABLED` and the other `AMADEUS_RETRY_*` values
- `AMADEUS_LOGGING`, `AMADEUS_LOG_CHANNEL`
- `AMADEUS_SOAP_TRACE`, `AMADEUS_CONNECTION_TIMEOUT`, `AMADEUS_TIMEOUT`
- `AMADEUS_CONTACT_EMAIL` — PNR AP element (default is a hardcoded
  `desarollo@enlaceforte.com`, note the misspelling)

- `AMADEUS_CACHE_*`, `AMADEUS_MONITORING_*`, `AMADEUS_DEFAULT_SEARCH_CACHE_LEVEL`,
  `AMADEUS_LISTING_CACHE_LEVEL`, `AMADEUS_DETAILS_CACHE_LEVEL`,
  `AMADEUS_DEFAULT_RATE_STRATEGY` — performance options, see `docs/performance.md`

Env vars with **no effect**: `AMADEUS_SEARCH_CACHE_LEVEL` and
`AMADEUS_RATE_STRATEGY` (old names, never read), `AMADEUS_CONNECTION_POOL_*`,
`AMADEUS_XML_CACHE_*`, `AMADEUS_MAX_RATES_PER_HOTEL`,
`AMADEUS_MIN_PRICE_DIFFERENCE`, `AMADEUS_ENDPOINT` and `AMADEUS_DEBUG`
(removed).

## Test Environment

Tests configure via `TestCase::getEnvironmentSetUp()`:
- WSDL path: `tests/Fixtures/wsdl` (synthetic WSDLs covering both the
  self-contained and the `wsdl:import` shapes)
- Credentials: `test_user` / `test_pass` / `TEST01`
- Session driver `array`, cache store `array`, contact email `test@example.com`
- Logging disabled

Fixture layout:
- `tests/Fixtures/wsdl/` — the two WSDL shapes `WsdlManagerTest` asserts on.
  Its tests check the exact operation list, so adding a WSDL here breaks them.
- `tests/Fixtures/wsdl-full/` — one WSDL declaring all 9 operations with the
  real response namespaces, used by `BookingChainTest`. The namespaces matter:
  they are what `OperationMetadata` hands to `AmadeusResponse` for XPath, so a
  wrong one makes the chain silently parse nothing.
- `tests/Fixtures/responses/` — replies shaped like real Amadeus output, with
  identifiers, session tokens and card digits replaced by placeholders.
- `tests/Fixtures/tst/` — real TST traffic, sanitized by
  `tests/Fixtures/sanitize-tst-captures.php` from `storage/tst-chain` (written by
  `scripts/tst-chain.php`) and `.env.tst`: request bodies Amadeus accepted and
  full replies. See `tests/Fixtures/README.md`.

`tests/Feature/BookingChainTest.php` drives the whole flow through `AmadeusSoap`
over `FakeTransport`: operation order, stateful/session-body flags per
operation, session lifecycle, value hand-off between steps, multi-room and
multi-passenger bookings, and business errors. It is the regression net for the
orchestration — run it before touching `AmadeusSoap.php`.

`tests/Feature/Tst/` replays `tests/Fixtures/tst` through the real SOAP layer
(`fakeAmadeus()` + `ReplaySoapClient`, which only intercepts HTTP):
`assertSoapBodyMatchesFixture()` compares every request body with the one TST
accepted, and parsing runs on real replies. Cache, monitoring and failure
handling have their own feature tests on the same fixtures.

`tests/Feature/RedisSessionStoreIntegrationTest.php` skips itself when no Redis
server is reachable. Run it with a server up:

```bash
REDIS_PORT=6379 ./vendor/bin/pest tests/Feature
```

## Smoke Testing Against Amadeus TST

`scripts/tst-chain.php` runs the real booking chain against the Amadeus test
environment and is the reference for correct parameter usage. It aborts if the
WSDL's endpoint is not a test endpoint.

```bash
php scripts/tst-chain.php --city=MTY --dry-run   # validate config, no calls
php scripts/tst-chain.php --city=MTY             # read-only chain
php scripts/tst-chain.php --city=MTY --book      # creates and cancels a PNR
```

Real Amadeus WSDLs are never in the repo: point `AMADEUS_WSDL_PATH` (in
`.env.tst`) at your local TST WSDL directory.

## Documentation Accuracy

Performance, caching and rate filtering are documented in one place,
`docs/performance.md`; README links to it. Keep docs to what the code does —
earlier versions documented unwired config, fabricated benchmark numbers and
param names that did not exist, which cost real debugging time. Do not publish
latency figures for Amadeus calls; they vary by market, date range, node and
load.
