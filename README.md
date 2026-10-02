# Amadeus SOAP Client for Laravel

[![PHP Version](https://img.shields.io/badge/php-%5E8.2-blue)](https://php.net)
[![Laravel](https://img.shields.io/badge/laravel-%5E10.0%7C%5E11.0%7C%5E12.0%7C%5E13.0-red)](https://laravel.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A robust Laravel package for integrating with Amadeus Globalizer SOAP Web Services. This package provides a clean, type-safe interface for hotel booking operations, PNR management, and other GDS functionalities.

## Features

- **Type-Safe DTOs** - Fully typed request/response objects with PHP 8.2+ features (readonly classes, constructor promotion)
- **Stateful Session Management** - Automatic handling of SOAP sessions with multiple storage backends (Redis, Cache, File, Array)
- **WS-Security Authentication** - Built-in support for WS-Security headers and Amadeus-specific security tokens
- **Automatic Retry Logic** - Exponential backoff for transient connection errors
- **Event-Driven Architecture** - Dispatches Laravel events for monitoring and logging
- **Comprehensive Error Handling** - Typed exception hierarchy for different error scenarios
- **WSDL Management** - Lazy loading and caching of WSDL metadata
- **Compact Calls** - Each step takes the previous reply (room stay, PNR, segment): no re-typing hotel, codes, agent or passenger
- **Tested Against Real Traffic** - Feature tests replay sanitized Amadeus TST requests and responses
- **Testing Fake** - `Amadeus::fake()` answers your application's calls with queued reply XML, no network
- **Card Data Masking** - Card numbers and security codes never reach logs, debug output or exceptions
- **Response Cache** - Optional caching of stateless searches and descriptive info
- **Rate Filtering** - Best-only or all-rates searches, plus local filtering of a hotel's rates (refundable, breakfast, rate plans, price)
- **Performance Monitoring** - Optional response-time and success-rate metrics per operation

## Supported Operations

| Operation | Description | Stateful |
|-----------|-------------|----------|
| `hotelSearch` | Search for hotel availability | Conditional |
| `hotelPricing` | Get enhanced pricing for a hotel | Yes |
| `hotelSell` | Create a hotel booking segment | Yes |
| `hotelDescriptiveInfo` | Get hotel details and amenities | No |
| `hotelCompleteReservationDetails` | Get complete reservation details | Yes |
| `addMultiElements` | Add elements to PNR (create/update) | Yes |
| `pnrRetrieve` | Retrieve PNR by record locator | Yes |
| `pnrCancel` | Cancel a PNR | Yes |
| `signOut` | End the Amadeus session | Yes |

## Requirements

- PHP ^8.2
- Laravel ^10.0, ^11.0, ^12.0 or ^13.0 (Laravel 13 needs PHP 8.3)
- PHP SOAP extension (`ext-soap`)
- PHP DOM extension (`ext-dom`)
- Redis (recommended for production) or another cache driver

## Installation

Install the package via Composer:

```bash
composer require aldogtz/amadeus-soap:^2.0
```

2.x is a rewrite with typed params and response DTOs. The previous,
unversioned generation (`dev-main`) returns `DOMXPath`; apps on `dev-main`
keep working unchanged and need to migrate their calls before moving to
`^2.0`. See the [CHANGELOG](CHANGELOG.md).

### Publish Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag="amadeus-soap-config"
```

This will create `config/amadeus-soap.php` in your Laravel application.

## Configuration

### Environment Variables

Add the following to your `.env` file:

```env
# Amadeus Credentials
AMADEUS_USERNAME=your_username
AMADEUS_PASSWORD=your_password
AMADEUS_OFFICE_ID=your_office_id

# WSDL Path
AMADEUS_WSDL_PATH=/path/to/amadeus/wsdl/files

# Session Configuration (optional)
AMADEUS_SESSION_DRIVER=redis
AMADEUS_SESSION_CONNECTION=default      # redis driver
AMADEUS_SESSION_CACHE_STORE=file        # cache driver
AMADEUS_SESSION_PREFIX=amadeus_session_
AMADEUS_SESSION_TTL=900

# SOAP Client Options (optional)
AMADEUS_CONNECTION_TIMEOUT=30
AMADEUS_TIMEOUT=60
AMADEUS_SOAP_TRACE=true                 # required for getLastRequest/getLastResponse

# Retry Configuration (optional)
AMADEUS_RETRY_ENABLED=true
AMADEUS_RETRY_MAX_ATTEMPTS=3
AMADEUS_RETRY_BASE_DELAY_MS=500
AMADEUS_RETRY_MULTIPLIER=2.0
AMADEUS_RETRY_MAX_DELAY_MS=5000

# Search defaults (optional) — see docs/performance.md
AMADEUS_DEFAULT_RATE_STRATEGY=best_only
AMADEUS_DEFAULT_SEARCH_CACHE_LEVEL=Live

# Logging (optional)
AMADEUS_LOGGING=false
AMADEUS_LOG_CHANNEL=stack

# Contact Email — written as the PNR AP element (optional)
AMADEUS_CONTACT_EMAIL=your-email@example.com
```

`AMADEUS_WSDL_PATH` points at the **directory** holding the `.wsdl` files
Amadeus issued for your office, not at a single file. The service endpoint is
read from the WSDL, so a test-environment directory targets the test endpoint
automatically.

### Session Drivers

The package supports multiple session storage backends:

- **`redis`** - Direct Redis storage (recommended for production)
- **`cache`** - Laravel Cache facade (supports file, database, redis, memcached)
- **`file`** - JSON files on disk (good for development)
- **`array`** - In-memory only (ideal for testing)
- **`null`** - No persistence (fully stateless)

## Usage

> **Parameter naming.** Request params are snake_case array keys (`hotel_city_code`,
> `guest_count`), while response DTO properties are camelCase (`hotelCode`,
> `ratePlanCode`). Dates are `start` / `end` in `Y-m-d`, not `check_in` / `check_out`.

### Searching for Hotels

```php
use Aldogtz\AmadeusSoap\Facades\Amadeus;

$search = Amadeus::hotelSearch('multi', [
    'start' => '2024-12-25',       // check-in,  Y-m-d
    'end' => '2024-12-28',         // check-out, Y-m-d
    'hotel_city_code' => 'NYC',    // or 'hotel_code', 'hotel_name', or latitude+longitude
    'guest_count' => 2,            // adults per room
    'quantity' => 1,               // number of rooms
    'children' => [8, 11],         // child ages
    'currency' => 'MXN',
]);

// Amadeus returns hotels and rates as two parallel collections:
// $search->hotels holds HotelResult, $search->roomStays holds RoomStayResult.
// A property can point at several rates, so pair them with roomStays().
foreach ($search->hotels as $hotel) {
    echo "Hotel: {$hotel->hotelName} ({$hotel->hotelCode})\n";
    echo "Chain: {$hotel->chainCode}\n";

    // $hotel->total describes the first (best) rate
    if ($hotel->total !== null) {
        echo "From: {$hotel->total->currencyCode} {$hotel->total->amountAfterTax}\n";
    }

    foreach ($hotel->roomStays($search->roomStays) as $rate) {
        echo "  {$rate->ratePlanCode} · booking {$rate->bookingCode} · room {$rate->roomTypeCode}";
        echo " · {$rate->currency} {$rate->total?->amountAfterTax}\n";
    }
}
```

> **Do not pair on `roomStayRPH` yourself.** Amadeus sends it as a
> space-separated list (`"0 1 2"`) when a property has more than one rate, so
> matching that raw string against `RoomStayResult::$rph` finds nothing. Use
> `$hotel->roomStays($search->roomStays)`, or `$hotel->roomStayRPHs` for the
> parsed list.

Each `RoomStayResult` carries what deciding on a rate takes: `guaranteeCode`
(31 guarantee, 8 deposit), `acceptedCardCodes` (`['AX', 'VI', 'CA']`, empty
when the reply lists none), `commissionStatusType` (`Commissionable`,
`Non-paying`) and `commissionPercent`, `cancelPenalties` (with
`absoluteDeadline`), `nonRefundable`, `meals`, `availabilityStatus` and the
`taxes` of its total — each `Tax` with its `code`, `percent` or `amount`,
`chargeUnit` (19 = per night) and `type` (`Inclusive`, `Exclusive`).
`HotelResult` adds `chainName`, `hotelCityCode` and `address`.

`$search->warnings` lists every OTA `Warning` of the reply. A multi-hotel
search reports one per provider (`tag` `AVL`, `CLS`, `PE`…, `status`
`PRV.4`), the `OK` marker included.

At least one search criterion is required: `hotel_code`, `hotel_city_code`,
`hotel_name`, or both `latitude` and `longitude`. Omitting all four throws
`InvalidParameterException`. `start` and `end` default to today and today + 7 days.

### Pricing a Rate

> **Price against a single-hotel search, not a city search.** A city-wide
> `hotelSearch('multi', …)` is stateless and its booking codes are summary
> values. Pricing one directly makes Amadeus answer with
> `<Errors><Error Code="SCM"/></Errors>` and no message. The working sequence is:
>
> 1. `hotelSearch('multi', ['hotel_city_code' => …])` — browse, stateless
> 2. `hotelSearch('single', ['hotel_code' => …])` — opens the session and
>    returns fresh, priceable booking codes for that property
> 3. `hotelPricing(...)` with the booking code from step 2
>
> Carry that same fresh booking code into `hotelSell`.

```php
// Step 2: re-search the chosen property to open a session and refresh the rate
$single = Amadeus::hotelSearch('single', [
    'hotel_code' => $hotel->hotelCode, 'start' => '2024-12-25', 'end' => '2024-12-28',
    'guest_count' => 2,
    'rate_code' => [],   // no filter: return whatever is loaded
]);

$room = $single->roomStays[0];
```

**On `rate_code`.** It defaults to `'RAC'`, and `[]` omits the
`RatePlanCandidates` filter entirely. Do not filter this search by the
`ratePlanCode` a city search reported — that is a converted value, and Amadeus
answers `RATE NOT LOADED` (`Error Code="842"`). Filter by rate plan codes your
office actually has loaded, or by nothing.

Pass that room stay to `hotelPricing`: the hotel, dates, rate identifiers and
occupancy come from it (the second argument overrides any of them).

```php
$pricing = Amadeus::hotelPricing($room);

echo "Room: {$pricing->roomType} · guarantee {$pricing->guaranteeCode}\n";

foreach ($pricing->cancelPenalties as $penalty) {
    echo $penalty->nonRefundable
        ? "Non-refundable\n"
        : "Free until {$penalty->absoluteDeadline}, then {$penalty->currencyCode} {$penalty->amount}\n";
}
```

`$pricing->acceptedCardCodes` lists the cards the priced rate's guarantee
accepts: `[]` when the rate lists none, `null` when no rate plan in the reply
matches the priced booking code (the guarantee cannot be checked). The reply
also has `ratePlanCategory` (`Converted:BAR:P`, which names the rate's source)
and `currencyConversions`.

The array form still works — `start`, `end`, `hotel_code`, `rate_plan_code`,
`booking_code`, `room_type_code`, `quantity` and `guest_count` are then
required. A rate without a room type code cannot be priced either way.

### Creating a Booking

The booking chain is **PNR first, hotel segment second**: `hotelSell` needs the
`travelAgentRef` and traveller reference that `addMultiElements('create')`
returns.

```php
use Aldogtz\AmadeusSoap\Data\PaymentCard;
use Aldogtz\AmadeusSoap\Data\Traveler;

// 1. Open the PNR with the passenger
$pnr = Amadeus::addMultiElements('create', new Traveler('DOE', 'JOHN'));

// 2. Attach the hotel segment. Agent and passenger come from the PNR reply,
//    hotel and booking code from the room stay, payment type from its guarantee.
$card = new PaymentCard('VI', config('services.amadeus.card_number'), config('services.amadeus.card_cvc'), '1226', 'JOHN DOE');
$sell = Amadeus::hotelSell($room, $pnr, $card);

if ($sell->hasErrors) {
    // e.g. CTL: Amadeus refuses this rate. It is per rate, so another room
    // stay of the same search (same session) may sell.
}

echo "Confirmation: {$sell->confirmationNumber}\n";

// 3. Commit the PNR and get the record locator
$end = Amadeus::addMultiElements('end');

echo "PNR: {$end->pnrNumber}\n";

// 4. Release the session
Amadeus::signOut();
```

`PaymentCard` keeps the number and CVC out of stack traces and masks them in
`var_dump()`/`dd()`.

For several passengers pass a list — `addMultiElements('create', [new Traveler('DOE', 'JOHN'), new Traveler('DOE', 'JANE')])`.
The fourth argument dates the PNR's retention segment from the check-out
(`addMultiElements('create', $travelers, checkOutDate: '2024-12-28')`);
without it the segment is dated a week from today.

For several rooms, give `hotelSell` the array form: one room array per room
alongside `travel_agent_ref`. A room may name the card holder with
`cc_holder_name` alone, or with `first_name` and `surname`.

Each HHL segment of the end-transaction reply has its `segmentNumber`,
`confirmationNumber`, `start` and `end` (Y-m-d), `ratePlanCode` and the
`passengerReference` of its principal guest:
`$end->travelerByReference($segment->passengerReference)` returns that
traveler, and `$segment->companions` the others.

Array keys are snake_case in every method (`travel_agent_ref`, `booking_code`,
`pnr_number`, `segment_number`, …); the camelCase spelling some methods used
before (`travelAgentRef`, `pnrNumber`) is still accepted.

Never hardcode card details. Read them from config or environment.

### Hotel Descriptive Information

Stateless — no session is opened for this call.

```php
// A hotel code, a HotelResult or RoomStayResult, or ['hotel_code' => [...]] for several
$info = Amadeus::hotelDescriptiveInfo('NYC12345');

// $info->hotels holds HotelDescriptiveContent objects.
// hotel() returns one by code, or the first when called with no argument.
$hotel = $info->hotel('NYC12345');

echo "{$hotel->hotelName} ({$hotel->hotelCode}, chain {$hotel->chainCode})\n";
echo "Address: {$hotel->infoAddress->addressLine}, {$hotel->infoAddress->cityName}\n";
echo "Country: {$hotel->infoAddress->countryCode}\n";
echo "Check-in {$hotel->checkInTime}, check-out {$hotel->checkOutTime}\n";
echo "Thumbnail: {$hotel->thumbnailUrl}\n";

foreach ($hotel->texts as $text) {
    echo "[{$text->infoCode}] {$text->description}\n";
}

foreach ($hotel->imageGroups as $group) {
    foreach ($group->items as $image) {
        echo "Image ({$image->category}): {$image->url}\n";
    }
}

foreach ($hotel->attractions as $attraction) {
    echo "Nearby: {$attraction->name} ({$attraction->categoryCode})\n";
}
```

`$hotel->addresses` holds the property's contact addresses
(`ContactInfos/ContactInfo/Addresses`), each with its `useType` (`7` is the
physical address). Amadeus replies carry no `HotelInfo/Address`, so
`infoAddress` is the physical address, or the first one.

The send-flags (`sendGuestRooms`, `sendPolicies`, `sendAttractions`, …) all
default to `'true'`; pass `'false'` to trim the response.

### PNR Management

```php
// Retrieve a PNR by record locator (or pass the end-transaction reply)
$pnr = Amadeus::pnrRetrieve('ABC123');

foreach ($pnr->segments as $segment) {
    echo "Segment {$segment->segmentNumber}\n";
}

// Complete reservation details: PNR and first hotel segment from the reply
$details = Amadeus::hotelCompleteReservationDetails($pnr);

// Cancel a hotel segment, then commit the cancellation
Amadeus::pnrCancel($pnr->segments[0]);
Amadeus::addMultiElements('cancel');
```

`pnrCancel` takes the segment (or its number, or an array of numbers): the
element number inside the PNR, not the record locator. The array forms still
work: `pnrRetrieve(['pnr_number' => 'ABC123'])`,
`hotelCompleteReservationDetails(['pnr_number' => 'ABC123', 'segment_number' => '2'])`,
`pnrCancel(['segment_number' => '2'])`.

### Running a Flow on Its Own Session

The session is stored per authenticated user (`session.key_resolver`, default
`Auth::id() ?? 'system'`). A queued job, a console command or an inspection
tool should not share it: give the flow its own key with `usingSession()`.

```php
use Aldogtz\AmadeusSoap\AmadeusSoap;

$end = Amadeus::usingSession("approval:{$approval->id}", function (AmadeusSoap $amadeus) use ($traveler, $card) {
    $room = $amadeus->hotelSearch('single', [/* … */])->roomStays[0];
    $amadeus->hotelPricing($room);
    $pnr = $amadeus->addMultiElements('create', $traveler);
    $amadeus->hotelSell($room, $pnr, $card);

    return $amadeus->addMultiElements('end');
}, signOut: true);
```

The previous key is restored when the callback returns or throws. With
`signOut: true` the flow's session is signed out at the end either way; a
failed sign-out is reported, never thrown. `session()->withKey()` also sets a
key, but for the rest of the process — in a queue worker, the next jobs too.

### Advanced: Recursive Hotel Search (Pagination)

`recursiveHotelSearch` follows Amadeus' `moreIndicator` token, re-issuing the
search and merging each page into the result.

```php
$search = Amadeus::recursiveHotelSearch([
    'start' => '2024-12-25',
    'end' => '2024-12-28',
    'hotel_city_code' => 'NYC',
    'guest_count' => 2,
    'quantity' => 1,
]);

echo "Found ".count($search->hotels)." hotels\n";
echo $search->moreIndicator !== null ? "More pages remain\n" : "Complete\n";

// Pairing still works across pages
foreach ($search->hotels as $hotel) {
    foreach ($hotel->roomStays($search->roomStays) as $rate) {
        // ...
    }
}
```

It stops at 10 pages by default; raise or lower the cap with the second
argument:

```php
Amadeus::recursiveHotelSearch($params, maxPages: 25);
```

It also stops early if Amadeus repeats a token or returns a page with no
results, keeping whatever was already collected. Each call is a full SOAP
round-trip, so a large city with a wide date range can be slow — pair it with
`'rate_strategy' => 'best_only'`.

Amadeus numbers RPHs per response, so pages can reuse `"0"`. When they collide
the merge rewrites the incoming page's RPHs (on both the hotels and the room
stays) so `roomStays()` keeps pairing correctly. `$search->raw` holds the first
page's XML.

### End-to-End Smoke Test

[`scripts/tst-chain.php`](scripts/tst-chain.php) runs the whole chain against the
Amadeus TST environment and is the reference for correct parameter usage. It
refuses to run against a non-test endpoint.

```bash
# read-only: search -> pricing -> descriptive info -> sign out
php scripts/tst-chain.php --city=MTY

# validate config and WSDL without contacting Amadeus
php scripts/tst-chain.php --city=MTY --dry-run

# full chain, creates and then cancels a PNR in TST
php scripts/tst-chain.php --city=MTY --book

# same, with the params BookingV2 sends in production (occupants with the
# retention check-out, loyalty remark, room list keyed by ccHolderName alone)
php scripts/tst-chain.php --hotel=MCMEXSFM --guests=2 --book --bookingv2
```

### Dependency Injection

You can also use dependency injection instead of the facade:

```php
use Aldogtz\AmadeusSoap\AmadeusSoap;

class HotelBookingService
{
    public function __construct(
        protected AmadeusSoap $amadeus
    ) {}

    public function searchHotels(array $params)
    {
        return $this->amadeus->hotelSearch('multi', $params);
    }
}
```

## Error Handling

The package provides a comprehensive exception hierarchy:

```php
use Aldogtz\AmadeusSoap\Exceptions\AmadeusSoapException;
use Aldogtz\AmadeusSoap\Exceptions\AuthenticationException;
use Aldogtz\AmadeusSoap\Exceptions\ConnectionException;
use Aldogtz\AmadeusSoap\Exceptions\SessionException;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;

try {
    $response = Amadeus::hotelSearch('multi', $params);
} catch (AuthenticationException $e) {
    // Invalid credentials
    Log::error('Authentication failed: ' . $e->getMessage());
} catch (SessionException $e) {
    // Session expired or invalid
    Log::warning('Session error: ' . $e->getMessage());
} catch (ConnectionException $e) {
    // Network/timeout errors (automatically retried if enabled)
    Log::error('Connection error: ' . $e->getMessage());
} catch (SoapFaultException $e) {
    // Business logic errors from Amadeus
    Log::error('SOAP fault: ' . $e->getMessage());
} catch (AmadeusSoapException $e) {
    // Base exception - catch all
    Log::error('Amadeus error: ' . $e->getMessage());
}
```

### Response-Level Errors

Amadeus reports business-level problems inside a successful SOAP response, so
these do not raise exceptions. Every response DTO exposes `hasErrors` and
`errors` as **properties**, holding `AmadeusError` value objects:

```php
$response = Amadeus::hotelSearch('multi', $params);

if ($response->hasErrors) {
    foreach ($response->errors as $error) {
        echo "Error [{$error->code}]: {$error->message}\n";
        echo "Type: {$error->type}\n";
    }
}
```

The raw XML wrapper is reachable through `$response->raw` when you need to go
below the typed DTO:

```php
$xml = $response->raw->getRawXml();
$nodes = $response->raw->query('//res:RoomStay');
```

For debugging a request/response pair, the transport keeps the last exchange:

```php
Amadeus::getLastRequest();   // pretty-printed request XML
Amadeus::getLastResponse();  // pretty-printed response XML
```

## Events

The package dispatches the following events:

```php
use Aldogtz\AmadeusSoap\Events\OperationStarting;
use Aldogtz\AmadeusSoap\Events\OperationCompleted;
use Aldogtz\AmadeusSoap\Events\OperationFailed;

// Listen to events in your EventServiceProvider
protected $listen = [
    OperationStarting::class => [
        LogAmadeusOperation::class,
    ],
    OperationCompleted::class => [
        RecordAmadeusMetrics::class,
    ],
    OperationFailed::class => [
        AlertOnAmadeusFailure::class,
    ],
];
```

## Testing

Run the test suite:

```bash
./vendor/bin/pest
```

Run a specific test file, or filter by name:

```bash
./vendor/bin/pest tests/Unit/Operations/HotelSearchTest.php
./vendor/bin/pest --filter="it builds geo search"
```

The Redis integration tests in `tests/Feature/` skip themselves when no Redis
server is reachable. To run them, start one and point the suite at it:

```bash
REDIS_PORT=6379 ./vendor/bin/pest tests/Feature
```

`tests/Feature/Tst/` replays sanitized Amadeus TST traffic through the real
SOAP layer: request bodies are compared with the requests TST accepted, and
parsing runs on real replies. See [tests/Fixtures/README.md](tests/Fixtures/README.md)
for how captures from `scripts/tst-chain.php` become fixtures.

### Testing Your Integration

`Amadeus::fake()` answers calls with reply XML you queue, in order, with no
network access. Only the HTTP exchange is replaced: params, request building,
headers, sessions and parsing run for real, against a test WSDL shipped with
the package. Sessions are kept in memory and the response cache is off, so
your test config needs no WSDLs, credentials or Redis.

```php
use Aldogtz\AmadeusSoap\Facades\Amadeus;

$fake = Amadeus::fake()->pushFile(
    base_path('tests/Fixtures/amadeus/search-single.xml'),
    base_path('tests/Fixtures/amadeus/pricing.xml'),
);

$this->postJson('/api/hotels/rate', [/* … */])->assertOk();

$fake->assertSent('Hotel_EnhancedPricing', fn (string $xml) => str_contains($xml, 'B2DRAFNOV'))
    ->assertSentCount(2)
    ->assertNoPendingReplies();
```

`push(...$xml)` queues XML strings, `pushFault('code|Category|text')` a SOAP
fault; `requests()` and `sent($operation)` return what was sent. A call with
nothing queued throws. Install the fake before the code under test resolves
the service: an `AmadeusSoap` instance injected earlier keeps the real client.

To mock the service instead, build the reply objects from your fixtures —
`fromXml()` reads the namespace from the reply itself:

```php
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;

Amadeus::shouldReceive('hotelSearch')
    ->once()
    ->andReturn(HotelSearchResponse::fromXml(file_get_contents($fixture)));
```

Code written against the facade name of the unversioned `dev-main` package
keeps working: `AmadeusSoapFacade` is a deprecated alias of `Amadeus`
(removed in 3.0).

## Performance

All optional and off by default. Full guide: [docs/performance.md](docs/performance.md).

```env
# Cache stateless calls: multi-hotel searches by city/coordinates, descriptive info
AMADEUS_CACHE_ENABLED=true
AMADEUS_CACHE_SEARCH_TTL=300
AMADEUS_CACHE_INFO_TTL=3600

# Amadeus server-side cache when a search doesn't set one: Live, VeryRecent or LessRecent
AMADEUS_DEFAULT_SEARCH_CACHE_LEVEL=Live

# Multi-hotel searches: best_only (one rate per hotel) or all_rates
AMADEUS_DEFAULT_RATE_STRATEGY=best_only

# Response-time and success-rate metrics per operation
AMADEUS_MONITORING_ENABLED=true
```

Narrow down the rates of a search by hotel code locally:

```php
$response = Amadeus::hotelSearch('single', [
    'hotel_code' => 'YZMTY045',
    'start' => '2026-08-30',
    'end' => '2026-08-31',
    'rate_filter_criteria' => [
        'refundable_only' => true,
        'breakfast_included' => true,
        'max_rates' => 5,
    ],
]);
```

`TwoPhaseSearchService` combines both phases (a listing with the best rate per
hotel, then the rates of the chosen hotel); see the guide for the session
caveats.

## Architecture

### Execution Flow

```
Request → Params Validation → Operation Builder → Body Builder
   ↓
Header Builder (WS-Security + Session + Addressing)
   ↓
SOAP Transport (with Retry Logic)
   ↓
AmadeusResponse (XML Wrapper)
   ↓
Response Parser → Typed DTO
```

### Key Components

- **`AmadeusSoap`** - Main service orchestrator
- **`SoapTransport`** - Handles SOAP communication and retries
- **`SessionManager`** - Manages stateful SOAP sessions
- **`WsdlManager`** - Lazy-loads and caches WSDL metadata
- **`Operations`** - Operation builders implementing the `Operation` interface
- **`Responses`** - Typed DTOs with XPath parsing helpers

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability, please email security@enlaceforte.com. All security vulnerabilities will be promptly addressed.

### Best Practices

- Never commit your `.env` file
- Use environment variables for credentials
- Card numbers and security codes are masked in everything the package hands
  out after a call — `getLastRequest()`/`getLastResponse()`, the SOAP log and
  the request/response carried by exceptions — so they can be logged or sent
  to an error tracker. Amadeus still receives the card as given.
- Enable logging only in development
- Use Redis with authentication in production
- Implement rate limiting on your API endpoints
- Validate all user input before passing to the package

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Ensure all tests pass (`./vendor/bin/pest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Coding Standards

- Follow PSR-12 coding standards
- Add type hints to all methods
- Write tests for new features
- Update documentation as needed

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Credits

- [Aldo Gutierrez](https://github.com/aldogtz)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

## Support

- **Documentation**: [CLAUDE.md](CLAUDE.md) - Detailed technical documentation
- **Issues**: [GitHub Issues](https://github.com/Enlace/AmadeusSoap/issues)
- **Email**: aldogtz1998@gmail.com

## Acknowledgments

- Built with [Spatie's Laravel Package Tools](https://github.com/spatie/laravel-package-tools)
- Tested with [Pest PHP](https://pestphp.com)
- Developed for [Enlace Forte](https://enlaceforte.com)