# Changelog

All notable changes to `amadeus-soap` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-10-05

### Added
- Every call accepts what the previous step returned, so the booking flow no
  longer re-types hotel, dates, codes, agent or passenger:
  `hotelPricing($roomStay)`, `hotelSell($roomStay, $pnrReply, $card)`,
  `addMultiElements('create', new Traveler(...))`, `pnrRetrieve('ABC123'|$reply)`,
  `hotelCompleteReservationDetails($reply)`, `pnrCancel($segment)` and
  `hotelDescriptiveInfo('CODE'|$hotel|$roomStay)`. Arrays keep working.
- `PaymentCard` (number and CVC redacted from traces and dumps) and `Traveler`
  value objects; `HotelPricingParams::fromRoomStay()` and
  `HotelSellParams::forRoom()` build the params from the replies
- `RoomStayResult::$hotelCode`, `$adults` and `$children`, read from the reply
- snake_case keys in every method (`travel_agent_ref`, `pnr_number`,
  `segment_number`, `hotel_code`…); the camelCase spelling stays accepted
- Reply fields applications read with their own XPaths until now:
  - `RoomStayResult`: `acceptedCardCodes`, `commissionStatusType`,
    `commissionPercent`, `cancelPenalties`, `taxes`, `availabilityStatus`
  - `HotelResult`: `chainName`, `hotelCityCode`, `address`
  - `HotelSearchResponse::$warnings` (every OTA Warning, e.g. the per-provider
    statuses of a multi-hotel search)
  - `HotelPricingResponse`: `acceptedCardCodes` of the priced rate (`null`
    when no rate plan matches its booking code), `ratePlanCategory`,
    `currencyConversions`
  - `HotelDescriptiveContent`: `hotelName`, `chainCode`, `checkInTime`,
    `checkOutTime`
  - `PnrSegment`: `start`, `end`, `ratePlanCode`;
    `AddMultiElementsResponse::travelerByReference()` for a segment's
    principal guest
  - `Tax::$type` (Inclusive / Exclusive)
- `AmadeusSoap::usingSession($key, $callback, signOut: false)` runs a flow on
  its own session (a queued job, an inspection) and restores the previous key
  afterwards; `SessionManager::usingKey()` underneath
- `addMultiElements()` takes the check-out date for the retention segment
  (`checkOutDate:`); a single passenger's `check_out_date` is read too
- `Amadeus::fake()` for applications' tests: queued reply XML, no network,
  real request building and parsing, with `assertSent()`,
  `assertSentCount()`, `assertNoPendingReplies()` and `pushFault()`. The
  test WSDL it loads ships in `resources/testing/wsdl`.
- `fromXml()` on every response DTO and `AmadeusResponse::fromXml()`, which
  read the namespace from the reply

### Changed
- The dist archive (what Composer installs) no longer ships `tests/`,
  `scripts/`, the CI workflows, `CLAUDE.md`, `composer.lock` or `phpunit.xml`
- The response cache keys entries by the endpoint the WSDL points at, so
  environments sharing a cache store, an office ID and even the WSDL directory
  path never share entries
- Card numbers (all but the last four digits) and security codes are masked
  in `getLastRequest()`/`getLastResponse()`, the SOAP log and the
  request/response carried by `SoapFaultException`, `ConnectionException`
  and `AuthenticationException`. Amadeus still receives the card as given.
- `Hotel_Sell` sends an explicit `ccHolderName` as given and no longer pads
  the composed one; `firstName`/`surname` are sent only when the caller
  passes either

### Deprecated
- `Facades\AmadeusSoapFacade`, the facade name of the unversioned `dev-main`
  generation, kept as an alias of `Facades\Amadeus`; removed in 3.0
- `SoapTransport`'s `$wsdlManager` constructor parameter (optional now; it was
  never used) and `WsdlManager::getWsdlDomDoc()` / `getWsdlDomXpath()` (they
  always returned `[]`). All three are removed in 3.0.

### Fixed
- The default contact email (`contact_email`, the PNR AP element) was
  misspelled `desarollo@enlaceforte.com`; it is `desarrollo@enlaceforte.com`.
  Set `AMADEUS_CONTACT_EMAIL` to keep sending to another mailbox.
- `HotelDescriptiveContent::$addresses` and `$infoAddress` were empty for
  every real reply: Amadeus sends the property's addresses under
  `ContactInfos/ContactInfo/Addresses`, not `HotelInfo/Addresses`. With no
  `HotelInfo/Address` in the reply, `infoAddress` is now the physical
  (UseType 7) address, or the first one.
- A multi-room sell keyed by `ccHolderName` alone sent `" NAME"` plus empty
  `firstName`/`surname` elements; it now sends the holder name alone, as the
  `dev-main` package did
- `ReservationTax::$beginDate` / `$endDate` read `2026-8-30`: Amadeus does not
  zero-pad month and day. They are Y-m-d dates now.
- 2.0.0 could not be installed on Laravel 13: `illuminate/contracts` was
  capped at ^12.0. Laravel 13 is now supported and tested (Testbench 11,
  Pest 4, PHPUnit 12), and CI covers it on PHP 8.3 and 8.4

### Removed
- The `endpoint` (`AMADEUS_ENDPOINT`) and `debug` (`AMADEUS_DEBUG`) config
  options. Nothing read them: requests always went to the WSDL's endpoint,
  which made `AMADEUS_ENDPOINT` look like it pointed the client somewhere it
  did not.

## [2.0.0] - 2026-10-02

A rewrite of the package: validated params, typed response DTOs, pluggable
session stores and an event per operation. It is **not compatible** with the
previous, unversioned generation (`dev-main`), whose methods returned
`DOMXPath`: applications on `dev-main` (such as BookingV2) keep working
unchanged and must migrate their calls before requiring `^2.0`.

### Added
- Hotel search operations (single and multi-city)
- Hotel pricing and booking operations
- Hotel descriptive information retrieval
- PNR management (create, retrieve, cancel)
- Stateful SOAP session management
- Multiple session storage backends (Redis, Cache, File, Array, Null)
- WS-Security authentication
- Automatic retry logic with exponential backoff
- Comprehensive error handling with typed exceptions
- Event-driven architecture (OperationStarting, OperationCompleted, OperationFailed)
- WSDL lazy loading and caching
- Full test coverage with Pest PHP
- Type-safe DTOs with PHP 8.2+ features
- Response cache (`OperationCache`) for stateless calls — multi-hotel searches by
  city/coordinates and descriptive info — wired into `AmadeusSoap`; stateful
  calls are never cached
- Performance monitoring (`PerformanceMonitor`) fed by the operation events
- `SearchCacheLevel` enum with the values the Amadeus schema accepts, plus
  configurable defaults for `search_cache_level` and `rate_strategy`
  (`AMADEUS_DEFAULT_SEARCH_CACHE_LEVEL`, `AMADEUS_DEFAULT_RATE_STRATEGY`)
- Local rate filtering of single-hotel searches (`rate_filter_criteria`,
  `RateFilter`, `HotelSearchResponse::filterRoomStays()`)
- `TwoPhaseSearchService` (`quickSearch()` / `detailedRates()`)
- `scripts/tst-chain.php`: end-to-end smoke run of the booking chain against
  Amadeus TST (read-only by default, `--book` creates and cancels a PNR,
  `--dry-run` validates config and WSDLs without calling Amadeus)
- `HotelResult::roomStays()` / `$roomStayRPHs` to pair a property with its rates,
  and `HotelSearchResponse::mergePage()`
- `SoapTransport::parseAmadeusFault()` for Amadeus' `code|Category|text` faults
- Test suites: orchestration (`BookingChainTest`), transport, headers, sessions,
  WSDL; plus `tests/Feature/Tst`, which replays sanitized Amadeus TST traffic
  through the real SOAP layer, and `tests/Fixtures/sanitize-tst-captures.php`
  to produce those fixtures
- Consolidated guide: `docs/performance.md`
- CI (GitHub Actions): PHP 8.2–8.4 × Laravel 10, 11 and 12, with Redis so the
  session store integration tests run

### Changed
- `RateFilterStrategy` has two cases, `best_only` and `all_rates`, the only
  ones that change the request (`BestOnlyIndicator`)
- `RateFilterCriteria` keeps only criteria backed by response data:
  refundable / non-refundable, breakfast, rate plan codes, max rates, minimum
  price difference and sort order
- Invalid `search_cache_level`, `rate_strategy` or `rate_filter_criteria` now
  fail with `InvalidParameterException` before calling Amadeus;
  `rate_filter_criteria` also requires `hotel_code`
- `RoomStayResult::$nonRefundable` is `?bool`: `null` when the reply does not
  state it, and OTA `"1"`/`"0"` are parsed
- `OperationFailed` is dispatched (and logged) for every failure, including
  `AuthenticationException` and `XmlParseException`
- `HotelSellResponse::$confirmationNumber` is the hotel's reservation
  `controlNumber` — the same number PNR_Reply reports for the segment — not the
  echoed booking code (still in `roomResults[].bookingCode`)
- `recursiveHotelSearch()` walks every page and merges them (page cap, guards
  against repeated tokens and empty pages)
- `ParsesAmadeusXml::str()` trims every value (Amadeus pads some, e.g. `"POT "`)
- `SoapClientFactory` is resolved from the container (swappable in tests)
- `composer.json` declares the supported Laravel versions
  (`illuminate/contracts` ^10.0|^11.0|^12.0); Laravel 9 was admitted before
  but never tested

### Upgrade notes
- `AMADEUS_SEARCH_CACHE_LEVEL` and `AMADEUS_RATE_STRATEGY` were never read and
  are now ignored. Their replacements, `AMADEUS_DEFAULT_SEARCH_CACHE_LEVEL` and
  `AMADEUS_DEFAULT_RATE_STRATEGY`, do apply to every `hotelSearch()`; the
  defaults (`Live`, `best_only`) keep the previous behavior. The old example
  values `SlightlyLessRecent`, `filtered`, `two_phase` and `incremental` are
  rejected.

### Removed
- `ConnectionPool`: duplicated the per-WSDL client pool `SoapClientFactory` has
- `XmlParserCache`: never hit (every reply carries unique session data)
- `StreamingXmlRateFilter`: read element paths that do not exist in Amadeus replies
- `AmadeusCacheStrategy` and `examples/DoubleCache_Example.php`: hardcoded
  duplicates of the config, fabricated response times, and the invalid
  `SlightlyLessRecent` level
- `TwoPhaseSearchService::batchDetailedRates()` / `progressiveSearch()`: each
  single-hotel search replaces the session and its availability context, so
  only the last hotel could ever be priced
- `PERFORMANCE.md`, `RATE_FILTERING.md`, `AMADEUS_CACHE.md`,
  `SOLUTION_SUMMARY.md`, `docs/RATE_FILTERING_DIAGRAMS.md` (merged into
  `docs/performance.md`)

### Fixed
- `hotelSell()`, `hotelCompleteReservationDetails()`, `addMultiElements()`,
  `pnrRetrieve()` and `pnrCancel()` always threw `DOMException` (the body was
  wrapped in a list that ArrayToXml rejects)
- `hotelSearch()`, `hotelPricing()` and `hotelDescriptiveInfo()` sent request
  options (`EchoToken`, `SearchCacheLevel`, `MaxResponses`, …) as child
  elements instead of root attributes; Amadeus answered `11|Session|`
- Properties with more than one rate came back without total, rate plan or
  dates (`RoomStayRPH` is a space-separated list)
- `HotelSellResponse` reported failed sells (error `CTL` without description)
  as successful, and read the confirmation number, booking code and hotel from
  request paths instead of the reply
- Authentication faults (`Not authenticated`, `|Security|`) were not classified
  as `AuthenticationException`
- `WsdlManager` skipped merging `wsdl:import`s for every manager after the first
  in a process, breaking requests in Octane and queue workers
- Session stores now treat an incomplete stored payload as no session
- `AddMultiElementsResponse::$ratePlanCode` read `negotiated` instead of
  `negotiated/rateCode` (PNR_Reply 21.1)
- Single-hotel searches and `PNR_Retrieve` replaced the stored session without
  signing it out, leaving it open on Amadeus (counting against the office's
  session limit) until it timed out; it is now signed out first
  (`AMADEUS_SESSION_SIGN_OUT_REPLACED`, on by default)
- `HotelPricingResponse` cancel penalties read `NonRefundable="1"` as refundable
- `PerformanceMonitor` percentile read past the end of small samples
- A cache or monitoring store outage could fail a call Amadeus had already
  completed (e.g. a sell that booked the room); store errors are now reported
  and swallowed
- After a cache hit, `getLastRequest()`/`getLastResponse()` no longer return
  the previous (possibly another user's) exchange
- Composer facade alias pointed to a class that does not exist

### Security
- `.env.*` (except `.env.example`) and `storage/` are git-ignored: raw TST
  captures contain credentials and personal data

[Unreleased]: https://github.com/Enlace/AmadeusSoap/compare/v2.1.0...v2
[2.1.0]: https://github.com/Enlace/AmadeusSoap/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Enlace/AmadeusSoap/releases/tag/v2.0.0