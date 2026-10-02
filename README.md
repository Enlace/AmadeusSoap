# Amadeus SOAP Client for Laravel

[![PHP Version](https://img.shields.io/badge/php-%5E8.2-blue)](https://php.net)
[![Laravel](https://img.shields.io/badge/laravel-%5E10.0%7C%5E11.0%7C%5E12.0-red)](https://laravel.com)
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
- **Tested Against Real Traffic** - Feature tests replay sanitized Amadeus TST requests and responses
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
- Laravel ^10.0, ^11.0 or ^12.0
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
    'start' => '2024-12-25',
    'end' => '2024-12-28',
    'hotel_code' => $hotel->hotelCode,
    'quantity' => 1,
    'guest_count' => 2,
    'rate_code' => [],   // no filter: return whatever is loaded
]);

$fresh = $single->roomStays[0];
```

**On `rate_code`.** It defaults to `'RAC'`, and `[]` omits the
`RatePlanCandidates` filter entirely. Do not filter this search by the
`ratePlanCode` a city search reported — that is a converted value, and Amadeus
answers `RATE NOT LOADED` (`Error Code="842"`). Filter by rate plan codes your
office actually has loaded, or by nothing.

`hotelPricing` needs the rate identifiers from that single-hotel search.

```php
$pricing = Amadeus::hotelPricing([
    'start' => '2024-12-25',
    'end' => '2024-12-28',
    'hotel_code' => $hotel->hotelCode,
    'rate_plan_code' => $fresh->ratePlanCode,
    'booking_code' => $fresh->bookingCode,
    'room_type_code' => $fresh->roomTypeCode,
    'quantity' => 1,
    'guest_count' => 2,
    'is_per_room' => 'true',   // optional, defaults to 'true'
]);

echo "Room: {$pricing->roomType} · guarantee {$pricing->guaranteeCode}\n";

foreach ($pricing->cancelPenalties as $penalty) {
    echo $penalty->nonRefundable
        ? "Non-refundable\n"
        : "Free until {$penalty->absoluteDeadline}, then {$penalty->currencyCode} {$penalty->amount}\n";
}
```

All of `start`, `end`, `hotel_code`, `rate_plan_code`, `booking_code`,
`room_type_code`, `quantity` and `guest_count` are required.

### Creating a Booking

The booking chain is **PNR first, hotel segment second**: `hotelSell` needs the
`travelAgentRef` and traveller reference that `addMultiElements('create')`
returns.

```php
// 1. Open the PNR with the passenger
$create = Amadeus::addMultiElements('create', [
    'surname' => 'DOE',
    'name' => 'JOHN',
    'type' => 'ADT',
]);

$traveler = $create->travelers[0];

// 2. Attach the hotel segment (needs a card for the guarantee)
$sell = Amadeus::hotelSell([
    'travelAgentRef' => $create->travelAgentRef,
    'chainCode' => $hotel->chainCode,
    'cityCode' => 'NYC',
    'hotelCode' => $hotel->hotelCode,
    'bookingCode' => $rate->bookingCode,
    'paymentType' => 'CC',
    'vendorCode' => 'VI',
    'cardNumber' => config('services.amadeus.card_number'),
    'securityId' => config('services.amadeus.card_cvc'),
    'expiryDate' => '1226',              // MMYY
    'surname' => 'DOE',
    'firstName' => 'JOHN',
    'passengerReference' => [
        'type' => 'BHO',                 // booking holder occupant
        'value' => $traveler->referenceNumber,
    ],
]);

echo "Booking reference: {$sell->bookingReference}\n";
echo "Confirmation: {$sell->confirmationNumber}\n";

// 3. Commit the PNR and get the record locator
$end = Amadeus::addMultiElements('end', [
    'surname' => 'DOE',
    'name' => 'JOHN',
    'type' => 'ADT',
]);

echo "PNR: {$end->pnrNumber}\n";

// 4. Release the session
Amadeus::signOut();
```

For multiple passengers or rooms, pass a list of arrays instead of a flat one —
`addMultiElements('create', [['surname' => ..., 'name' => ..., 'type' => 'ADT'], ...])`
and give `hotelSell` one keyed room array per room alongside `travelAgentRef`.

Never hardcode card details. Read them from config or environment.

### Hotel Descriptive Information

Stateless — no session is opened for this call.

```php
$info = Amadeus::hotelDescriptiveInfo([
    'hotelCode' => 'NYC12345',   // string, or an array of codes
]);

// $info->hotels holds HotelDescriptiveContent objects.
// hotel() returns one by code, or the first when called with no argument.
$hotel = $info->hotel('NYC12345');

echo "Code: {$hotel->hotelCode}\n";
echo "Address: {$hotel->infoAddress->addressLine}, {$hotel->infoAddress->cityName}\n";
echo "Country: {$hotel->infoAddress->countryName}\n";
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

The send-flags (`sendGuestRooms`, `sendPolicies`, `sendAttractions`, …) all
default to `'true'`; pass `'false'` to trim the response.

### PNR Management

```php
// Retrieve a PNR by record locator
$pnr = Amadeus::pnrRetrieve([
    'pnrNumber' => 'ABC123',
]);

echo "PNR: {$pnr->pnrNumber}\n";

foreach ($pnr->segments as $segment) {
    echo "Segment {$segment->segmentNumber}\n";
}

// Complete reservation details for one hotel segment
$details = Amadeus::hotelCompleteReservationDetails([
    'pnrNumber' => 'ABC123',
    'segmentNumber' => '1',
]);

// Cancel a segment by its number within the PNR
$cancel = Amadeus::pnrCancel([
    'segmentNumber' => '1',        // string, or an array of numbers
]);

// Commit the cancellation
Amadeus::addMultiElements('cancel', []);
```

`pnrRetrieve` takes `pnrNumber` (the record locator). `pnrCancel` takes
`segmentNumber` — the element number inside the PNR, not the record locator.

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

For testing, use the `array` session driver:

```env
# In your phpunit.xml or .env.testing
AMADEUS_SESSION_DRIVER=array
```

You can also mock the service in your tests:

```php
use Aldogtz\AmadeusSoap\Facades\Amadeus;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;

Amadeus::shouldReceive('hotelSearch')
    ->once()
    ->with('multi', ['hotel_city_code' => 'NYC'])
    ->andReturn(new HotelSearchResponse(/* ... */));
```

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