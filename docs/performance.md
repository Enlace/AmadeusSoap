# Performance and rate filtering

Everything here is opt-in and off by default unless noted: with no extra
configuration the package behaves exactly as a plain `hotelSearch()` /
`hotelPricing()` / `hotelSell()` client.

- [Response cache](#response-cache)
- [Amadeus SearchCacheLevel](#amadeus-searchcachelevel)
- [Rate strategy and local rate filtering](#rate-strategy-and-local-rate-filtering)
- [Two-phase search](#two-phase-search)
- [Performance monitoring](#performance-monitoring)
- [Other settings](#other-settings)

## Response cache

Caches the raw response XML of **stateless** calls in a Laravel cache store:

| Call | Stateless? | Cached |
|---|---|---|
| `hotelSearch('multi', …)` by city or coordinates | Yes | Yes |
| `hotelDescriptiveInfo()` | Yes | Yes |
| `hotelSearch('single', …)` / multi search by hotel code | No | Never |
| Pricing, sell, PNR, sign out | No | Never |

Stateful calls are never cached, even if listed in the config: their response
carries the Amadeus session that pricing, sell and PNR continue, and replaying
it from cache would break the booking flow.

```env
AMADEUS_CACHE_ENABLED=true
AMADEUS_CACHE_STORE=redis        # optional, defaults to the app's cache store
AMADEUS_CACHE_SEARCH_TTL=300     # Hotel_MultiSingleAvailability, seconds
AMADEUS_CACHE_INFO_TTL=3600      # Hotel_DescriptiveInfo, seconds
```

- The key is the request body plus the office ID, the WSDL path and the
  endpoint the WSDL points at, so different searches, offices or environments
  (TST vs production) never share entries — even when they share a cache store
  and the same `AMADEUS_WSDL_PATH`.
- Responses with errors (e.g. no availability) are not cached.
- A cache hit does not call Amadeus, does not touch the session and does not
  dispatch `OperationStarting` / `OperationCompleted`; `getLastRequest()` and
  `getLastResponse()` return `null` after it.
- Store failures are reported (`report()`) and treated as misses: a cache
  outage never fails an Amadeus call.
- To invalidate everything (works on any store, no cache tags needed):

```php
app(\Aldogtz\AmadeusSoap\Cache\OperationCache::class)->flush();
```

## Amadeus SearchCacheLevel

Amadeus keeps its own server-side availability cache, selected per search with
`search_cache_level`. The Amadeus schema accepts exactly three values
(`Aldogtz\AmadeusSoap\Cache\SearchCacheLevel`):

| Value | Meaning |
|---|---|
| `Live` | Real-time availability from the provider. Default. |
| `VeryRecent` | Availability Amadeus cached a few minutes ago. |
| `LessRecent` | Older cached availability: fastest, least accurate. |

Any other value (for example `SlightlyLessRecent`) is rejected with an
`InvalidParameterException` before calling Amadeus. How long each level keeps
data is decided by Amadeus per market and contract, not by the client.

```php
use Aldogtz\AmadeusSoap\Cache\SearchCacheLevel;
use Aldogtz\AmadeusSoap\Facades\Amadeus;

Amadeus::hotelSearch('multi', [
    'hotel_city_code' => 'MTY',
    'start' => '2026-08-30',
    'end' => '2026-08-31',
    'search_cache_level' => SearchCacheLevel::VERY_RECENT, // or 'VeryRecent'
]);
```

Defaults when a call does not set it:

```env
AMADEUS_DEFAULT_SEARCH_CACHE_LEVEL=Live   # hotelSearch()
AMADEUS_LISTING_CACHE_LEVEL=VeryRecent    # TwoPhaseSearchService::quickSearch()
AMADEUS_DETAILS_CACHE_LEVEL=VeryRecent    # TwoPhaseSearchService::detailedRates()
```

Use `Live` right before pricing and sell.

## Rate strategy and local rate filtering

### Rate strategy (request side)

For multi-hotel searches, `rate_strategy` sets `BestOnlyIndicator`:

| Strategy | Effect |
|---|---|
| `best_only` (default) | One rate per hotel: smallest, fastest response. |
| `all_rates` | Every available rate per hotel. |

```php
Amadeus::hotelSearch('multi', [..., 'rate_strategy' => 'all_rates']);
```

The default comes from `AMADEUS_DEFAULT_RATE_STRATEGY`. Single-hotel searches
don't use `BestOnlyIndicator`: they return every rate of the hotel for the
requested rate codes.

Which rate plans are requested is controlled separately by `rate_code`
(`RatePlanCandidates`, default `RAC`; pass `[]` to omit the element). Don't
filter a single-hotel search by a converted rate plan code taken from a
listing (e.g. `57J`): Amadeus answers "RATE NOT LOADED" (error 842).

With `all_rates`, a property's `RoomStayRPH` is a space-separated list
(`"0 1 2"`). Use `$hotel->roomStays($response->roomStays)` to get its rates
instead of matching RPHs by hand.

### Local rate filtering (response side)

Amadeus has no request-side filter for refundability or breakfast, so
`rate_filter_criteria` filters the parsed room stays of a search **by hotel
code** (without `hotel_code` it is rejected: rates of different hotels and
currencies can't be ranked together):

```php
$response = Amadeus::hotelSearch('single', [
    'hotel_code' => 'YZMTY045',
    'start' => '2026-08-30',
    'end' => '2026-08-31',
    'rate_filter_criteria' => [
        'refundable_only' => true,       // or 'non_refundable_only' => true
        'breakfast_included' => true,
        'rate_plan_codes' => ['57J'],
        'min_price_difference' => 50,    // drop near-duplicate prices
        'sort_by' => 'price_asc',        // or 'price_desc'
        'max_rates' => 5,
    ],
]);

$response->roomStays;  // filtered and sorted
$response->raw;        // untouched Amadeus response
```

The same can be applied to a response with
`$response->filterRoomStays(RateFilterCriteria::fromArray([...]))`, or to one
property of a multi-hotel `all_rates` search:

```php
$rates = (new RateFilter($criteria))->apply($hotel->roomStays($response->roomStays));
```

- Order of application: filter → sort by price → drop near-duplicates → apply
  `sort_by` → cap at `max_rates`.
- Prices are after-tax totals. Room stays without one are kept and sorted last.
- Refundability comes from `CancelPenalty@NonRefundable`. Some rates omit it
  and only describe the penalty in text (`RoomStayResult::$nonRefundable` is
  then `null`): those pass neither `refundable_only` nor `non_refundable_only`.
- Boolean criteria accept `true`/`false`, `1`/`0` and their string forms, so
  query-string input works (`"false"` is false).

## Two-phase search

`TwoPhaseSearchService` wraps the usual listing → detail flow:

```php
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterCriteria;
use Aldogtz\AmadeusSoap\RateFiltering\TwoPhaseSearchService;

$search = app(TwoPhaseSearchService::class);

// Phase 1: multi-hotel listing, best rate per hotel, listing cache level
$listing = $search->quickSearch([
    'hotel_city_code' => 'MTY',
    'start' => '2026-08-30',
    'end' => '2026-08-31',
]);

// Phase 2: the rates of the chosen hotel (for the requested rate_code), filtered locally
$rates = $search->detailedRates(
    hotelCode: 'YZMTY045',
    params: ['start' => '2026-08-30', 'end' => '2026-08-31'],
    criteria: new RateFilterCriteria(refundableOnly: true, maxRates: 5),
    fresh: true, // force Live availability right before pricing
);
```

Phase 2 is a stateful single-hotel search: it starts the Amadeus session that
`hotelPricing()` and `hotelSell()` continue, and **every call starts a new
session** that replaces the stored one. The replaced session is signed out
first (`AMADEUS_SESSION_SIGN_OUT_REPLACED`, on by default), and its
availability context goes with it: pricing a hotel from an earlier search fails
(Amadeus error `SCI`). Call it for the hotel being booked, right before
pricing, and not in a loop over several hotels.

## Performance monitoring

Records the duration and outcome of every SOAP call — including
authentication, connection and parsing failures — from the
`OperationCompleted` / `OperationFailed` events:

```env
AMADEUS_MONITORING_ENABLED=true
AMADEUS_MONITORING_STORE=redis       # optional, defaults to the app's cache store
AMADEUS_MONITORING_STORE_HOURS=24
```

```php
$metrics = app(\Aldogtz\AmadeusSoap\Performance\PerformanceMonitor::class)
    ->getMetrics('Hotel_MultiSingleAvailability', hours: 6);

// count, avg_duration_ms, min_duration_ms, max_duration_ms,
// p95_duration_ms, p99_duration_ms, success_rate
```

Samples are bucketed per operation and hour (latest 1000 per hour) and
updated with read-modify-write, so concurrent requests can occasionally drop
a sample: treat the numbers as approximate. For exact metrics, listen to the
events and send them to your own metrics system.

The listeners run synchronously inside the SOAP call; a store failure is
reported and swallowed, so it can never turn a completed call (such as a sell
that booked the room) into an exception.

## Other settings

- **Sessions**: use the `redis` session driver in production; `array` in tests.
- **SOAP clients** are already reused per WSDL within a process
  (`SoapClientFactory`), and WSDL metadata is parsed lazily once per process.
- **Timeouts**: `AMADEUS_CONNECTION_TIMEOUT` / `AMADEUS_TIMEOUT`.
- **Retries**: `AMADEUS_RETRY_ENABLED=true` retries only connection errors
  (timeouts, SSL, DNS) with exponential backoff, never business errors.
- **Logging**: keep `AMADEUS_LOGGING=false` in production; formatting the XML
  for the log costs extra time on every call.
