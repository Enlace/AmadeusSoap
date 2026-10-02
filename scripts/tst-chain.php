<?php

/**
 * End-to-end smoke run of the full booking chain against the Amadeus TST
 * (test) environment.
 *
 *   php scripts/tst-chain.php --city=MTY
 *   php scripts/tst-chain.php --city=MTY --book --yes
 *
 * Read-only by default: search -> pricing -> descriptive info -> sign out.
 * The mutating half of the chain (PNR create, hotel sell, end transaction)
 * only runs with --book, and the PNR it creates is cancelled again on the way
 * out unless --keep is passed.
 *
 * Refuses to run against a non-test endpoint. The check is on the endpoint
 * baked into the WSDL, so pointing AMADEUS_WSDL_PATH at a production
 * directory aborts before the first call.
 *
 * Credentials and card details are read from the environment and never
 * written to disk by this script. Dumped XML has the WS-Security block and
 * card number redacted, but treat the dump directory as sensitive anyway.
 *
 * Required environment:
 *   AMADEUS_WSDL_PATH   directory holding the TST .wsdl files
 *   AMADEUS_USERNAME
 *   AMADEUS_PASSWORD
 *   AMADEUS_OFFICE_ID
 *
 * Additionally required by --book (the sell step needs a card guarantee):
 *   AMADEUS_TST_CARD_VENDOR   e.g. CA, VI, AX
 *   AMADEUS_TST_CARD_NUMBER
 *   AMADEUS_TST_CARD_CVC
 *   AMADEUS_TST_CARD_EXPIRY   MMYY
 *
 * Optional:
 *   AMADEUS_TST_CARD_HOLDER     card holder name, default Enlaceforte
 *   AMADEUS_TST_PAX_SURNAME    default TEST
 *   AMADEUS_TST_PAX_FIRSTNAME  default TESTER
 */

declare(strict_types=1);

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\AmadeusSoapServiceProvider;
use Aldogtz\AmadeusSoap\Data\Responses\HotelResult;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;
use Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use Orchestra\Testbench\Foundation\Application as TestbenchApplication;

// Booting Laravel and parsing the Amadeus WSDLs needs far more than a
// conservative CLI memory_limit allows — a 2M limit dies inside the autoloader.
// Raise it before anything loads, unless the environment already allows more.
$currentLimit = trim((string) ini_get('memory_limit'));

if ($currentLimit !== '-1') {
    $bytes = (int) $currentLimit;

    $bytes *= match (strtolower(substr($currentLimit, -1))) {
        'g' => 1024 ** 3,
        'm' => 1024 ** 2,
        'k' => 1024,
        default => 1,
    };

    if ($bytes < 512 * 1024 ** 2) {
        ini_set('memory_limit', '512M');
    }
}

require __DIR__.'/../vendor/autoload.php';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

$options = getopt('h', [
    'city:',
    'hotel:',
    'in:',
    'out:',
    'nights:',
    'guests:',
    'rooms:',
    'currency:',
    'payment-type:',
    'passenger-ref-type:',
    'max-sell-attempts:',
    'dump-dir:',
    'book',
    'bookingv2',
    'keep',
    'yes',
    'dry-run',
    'password-stdin',
    'dump-all',
    'help',
]) ?: [];

if (isset($options['h']) || isset($options['help'])) {
    fwrite(STDOUT, <<<'TXT'
Runs the Amadeus booking chain against the TST environment.

  --city=MTY            IATA city code to search (default MTY)
  --hotel=CODE          search one property instead of a city
  --in=YYYY-MM-DD       check-in  (default today +30 days)
  --out=YYYY-MM-DD      check-out (default check-in + --nights)
  --nights=N            nights when --out is omitted (default 1)
  --guests=N            adults per room (default 1)
  --rooms=N             rooms (default 1)
  --currency=MXN        rate currency (default MXN)
  --payment-type=N      Hotel_Sell guarantee payment type (default 1, which is
                        what Amadeus' own replies show for a card guarantee)
  --passenger-ref-type=BHO
                        passengerReference type for Hotel_Sell (default BHO)
  --max-sell-attempts=N how many rates to try when Amadeus refuses the sell
                        with errorGroup CTL (default 4)
  --book                also run PNR create / hotel sell / end transaction
  --bookingv2           with --book, send the shapes BookingV2 sends in
                        production: create with every occupant, check_out_date
                        (retention segment) and a loyalty RM remark; sell as a
                        list of room arrays keyed by ccHolderName alone, with
                        BHO/BOP passenger references; end with no params.
                        --guests=2 adds a companion (BOP).
  --keep                leave the created PNR in place instead of cancelling
  --yes                 skip the confirmation prompt for --book
  --dry-run             validate config, WSDL and endpoint, then stop without
                        contacting Amadeus
  --password-stdin      read AMADEUS_PASSWORD from stdin instead of the
                        environment, so it stays out of shell history and ps
  --dump-all            write request/response XML for every step, not only
                        for failures
  --dump-dir=PATH       where to write request/response XML (default ./storage/tst-chain)

Read-only without --book. See the header of this file for required env vars.

TXT);
    exit(0);
}

$book = isset($options['book']);
$bookingV2 = isset($options['bookingv2']);
$keep = isset($options['keep']);
$city = strtoupper((string) ($options['city'] ?? 'MTY'));
$hotelCodeArg = isset($options['hotel']) ? strtoupper((string) $options['hotel']) : null;
$nights = max(1, (int) ($options['nights'] ?? 1));
$checkIn = (string) ($options['in'] ?? (new DateTimeImmutable('+30 days'))->format('Y-m-d'));
$checkOut = (string) ($options['out'] ?? (new DateTimeImmutable($checkIn))->modify("+{$nights} days")->format('Y-m-d'));
$guests = (string) ($options['guests'] ?? '1');
$rooms = (string) ($options['rooms'] ?? '1');
$currency = strtoupper((string) ($options['currency'] ?? 'MXN'));
$paymentType = (string) ($options['payment-type'] ?? '1');
$passengerRefType = strtoupper((string) ($options['passenger-ref-type'] ?? 'BHO'));
$maxSellAttempts = max(1, (int) ($options['max-sell-attempts'] ?? 4));
$dumpDir = rtrim((string) ($options['dump-dir'] ?? __DIR__.'/../storage/tst-chain'), '/');

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

$useColor = stream_isatty(STDOUT);
$paint = function (string $text, string $color) use ($useColor): string {
    if (! $useColor) {
        return $text;
    }

    $codes = ['red' => '0;31', 'green' => '0;32', 'yellow' => '0;33', 'blue' => '0;34', 'grey' => '0;90', 'bold' => '1'];

    return "\033[{$codes[$color]}m{$text}\033[0m";
};

$line = fn (string $text = '') => fwrite(STDOUT, $text."\n");
$heading = fn (string $text) => $line("\n".$paint($text, 'bold'));
$note = fn (string $text) => $line('  '.$paint($text, 'grey'));
$fail = fn (string $text) => fwrite(STDERR, $paint('  '.$text, 'red')."\n");

$abort = function (string $message) use ($paint): never {
    fwrite(STDERR, $paint('ABORTA: ', 'red').$message."\n");
    exit(1);
};

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

$env = function (string $key): ?string {
    $value = getenv($key);

    return ($value === false || $value === '') ? null : $value;
};

// --password-stdin keeps the secret out of the environment, shell history and
// the process list. Read before the required-vars check so it counts as set.
$passwordFromStdin = null;

if (isset($options['password-stdin'])) {
    $passwordFromStdin = rtrim((string) fgets(STDIN), "\r\n");

    if ($passwordFromStdin === '') {
        $abort('--password-stdin was given but stdin was empty.');
    }
}

$required = ['AMADEUS_WSDL_PATH', 'AMADEUS_USERNAME', 'AMADEUS_OFFICE_ID'];

if ($passwordFromStdin === null) {
    $required[] = 'AMADEUS_PASSWORD';
}

if ($book) {
    $required = array_merge($required, [
        'AMADEUS_TST_CARD_VENDOR',
        'AMADEUS_TST_CARD_NUMBER',
        'AMADEUS_TST_CARD_CVC',
        'AMADEUS_TST_CARD_EXPIRY',
    ]);
}

$missing = array_values(array_filter($required, fn (string $key) => $env($key) === null));

if ($missing !== []) {
    $abort("faltan variables de entorno:\n  - ".implode("\n  - ", $missing)
        .($book ? "\n\nLas AMADEUS_TST_CARD_* solo hacen falta con --book." : ''));
}

$wsdlPath = $env('AMADEUS_WSDL_PATH');

if (! is_dir($wsdlPath)) {
    $abort("AMADEUS_WSDL_PATH no es un directorio: {$wsdlPath}");
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

$app = TestbenchApplication::create(
    basePath: __DIR__.'/../vendor/orchestra/testbench-core/laravel',
    options: ['enables_package_discoveries' => false],
);

$app->register(AmadeusSoapServiceProvider::class);

$app['config']->set('amadeus-soap.wsdl_path', $wsdlPath);
$app['config']->set('amadeus-soap.username', $env('AMADEUS_USERNAME'));
$app['config']->set('amadeus-soap.password', $passwordFromStdin ?? $env('AMADEUS_PASSWORD'));
$app['config']->set('amadeus-soap.office_id', $env('AMADEUS_OFFICE_ID'));
$app['config']->set('amadeus-soap.session.driver', 'array');
$app['config']->set('amadeus-soap.session.key_resolver', fn () => 'tst-chain');
$app['config']->set('amadeus-soap.logging.enabled', false);
$app['config']->set('amadeus-soap.retry.enabled', true);
$app['config']->set('amadeus-soap.retry.max_attempts', 2);

// ---------------------------------------------------------------------------
// Guard: test endpoint only
// ---------------------------------------------------------------------------

$registry = $app->make(WsdlManager::class)->getRegistry();

if (! $registry->has('Hotel_MultiSingleAvailability')) {
    $abort("el WSDL en {$wsdlPath} no expone Hotel_MultiSingleAvailability.\n"
        .'Operaciones encontradas: '.(implode(', ', array_keys($registry->all())) ?: '(ninguna)'));
}

$endpoint = $registry->get('Hotel_MultiSingleAvailability')->serviceEndpoint;

if (! str_contains($endpoint, '.test.')) {
    $abort("el endpoint del WSDL no es de pruebas:\n  {$endpoint}\n\n"
        .'Este script solo corre contra TST. Apunta AMADEUS_WSDL_PATH al directorio de pruebas.');
}

$amadeus = $app->make(AmadeusSoap::class);

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

$line($paint('Cadena de reserva Amadeus — entorno TST', 'bold'));
$line();
$line('  endpoint    '.$endpoint);
$line('  office id   '.$env('AMADEUS_OFFICE_ID'));
$line('  usuario     '.$env('AMADEUS_USERNAME'));
$line('  wsdl        '.$wsdlPath);
$line('  búsqueda    '.($hotelCodeArg ? "hotel {$hotelCodeArg}" : "ciudad {$city}")
    ." · {$checkIn} → {$checkOut} · {$rooms} hab · {$guests} adulto(s) · {$currency}");
$line('  modo        '.($book
    ? $paint('--book: CREA un PNR real en TST', 'yellow').($keep ? $paint(' y lo deja', 'yellow') : ' (se cancela al final)')
    : $paint('solo lectura', 'green')));
$line();

if (isset($options['dry-run'])) {
    $line('  operaciones en el WSDL: '.count($registry->all()));

    foreach (['Hotel_MultiSingleAvailability', 'Hotel_EnhancedPricing', 'Hotel_DescriptiveInfo',
        'PNR_AddMultiElements', 'Hotel_Sell', 'PNR_Retrieve', 'PNR_Cancel', 'Security_SignOut'] as $operation) {
        $known = $registry->has($operation);
        $line(sprintf('    %s  %s%s',
            $known ? $paint('✓', 'green') : $paint('✗', 'red'),
            $operation,
            $known ? $paint('  v'.$registry->get($operation)->version, 'grey') : $paint('  ausente del WSDL', 'red'),
        ));
    }

    $line();
    $line($paint('  --dry-run: configuración válida, no se llamó a Amadeus.', 'green'));
    $line();
    exit(0);
}

if ($book && ! isset($options['yes'])) {
    fwrite(STDOUT, 'Se creará un PNR en el entorno de pruebas. ¿Continuar? [s/N] ');
    $answer = strtolower(trim((string) fgets(STDIN)));

    if (! in_array($answer, ['s', 'si', 'sí', 'y', 'yes'], true)) {
        $line('Cancelado.');
        exit(0);
    }
}

if (! is_dir($dumpDir) && ! @mkdir($dumpDir, 0755, true) && ! is_dir($dumpDir)) {
    $abort("no pude crear el directorio de dumps: {$dumpDir}");
}

// ---------------------------------------------------------------------------
// Step runner
// ---------------------------------------------------------------------------

$stepNumber = 0;
$results = [];
$cardNumber = $env('AMADEUS_TST_CARD_NUMBER');

$redact = function (?string $xml) use ($cardNumber): ?string {
    if ($xml === null) {
        return null;
    }

    // Mask the secret leaves of the WS-Security header but keep its structure:
    // dropping the whole block hides exactly what you need to see when Amadeus
    // rejects authentication.
    $xml = preg_replace(
        '#(<(\w+:)?(Password|Nonce)\b[^>]*>)[^<]*(</(\w+:)?\3>)#',
        '$1[REDACTADO]$4',
        $xml,
    ) ?? $xml;

    if ($cardNumber !== null && $cardNumber !== '') {
        $xml = str_replace($cardNumber, '[TARJETA REDACTADA]', $xml);
    }

    return preg_replace(
        '#(<(\w+:)?(cardNumber|securityId)>)[^<]*(</(\w+:)?\3>)#',
        '$1[REDACTADO]$4',
        $xml,
    ) ?? $xml;
};

$dump = function (string $slug) use ($amadeus, $dumpDir, $redact, $note): void {
    $stamp = date('His');

    foreach (['request' => $amadeus->getLastRequest(), 'response' => $amadeus->getLastResponse()] as $kind => $xml) {
        $xml = $redact($xml);

        if ($xml === null) {
            continue;
        }

        $file = "{$dumpDir}/{$stamp}-{$slug}-{$kind}.xml";
        file_put_contents($file, $xml);
        $note("{$kind}: {$file}");
    }
};

/**
 * Run one step. Returns the response, or null when the step failed.
 */
$dumpAll = isset($options['dump-all']);

/**
 * Run one step. Returns the response, or null when the step failed.
 *
 * $verify may return an error string to fail a step that Amadeus answered
 * without errors but which did not actually accomplish anything.
 */
$step = function (string $slug, string $label, callable $callback, ?callable $verify = null) use (
    &$stepNumber, &$results, $line, $note, $fail, $paint, $dump, $dumpAll
) {
    $stepNumber++;
    $line();
    $line($paint(sprintf('[%d] %s', $stepNumber, $label), 'blue'));

    $startedAt = microtime(true);

    try {
        $response = $callback();
        $ms = (int) round((microtime(true) - $startedAt) * 1000);

        // Every response DTO in this package exposes errors the same way
        $hasErrors = property_exists($response, 'hasErrors') && $response->hasErrors;
        $errors = property_exists($response, 'errors') ? $response->errors : [];

        if ($hasErrors) {
            $fail(sprintf('Amadeus respondió con errores (%d ms)', $ms));

            foreach ($errors as $error) {
                $fail(sprintf('  [%s] %s', $error->code ?? '?', $error->message ?? '(sin mensaje)'));
            }

            $dump($slug);
            $results[$label] = 'error de negocio';

            return null;
        }

        // Amadeus can answer without errors and still not do the thing —
        // Hotel_Sell returning no room results is the case that matters.
        $problem = $verify !== null ? $verify($response) : null;

        if ($problem !== null) {
            $fail(sprintf('respuesta sin errores pero incompleta (%d ms)', $ms));
            $fail('  '.$problem);
            $dump($slug);
            $results[$label] = 'respuesta incompleta';

            return null;
        }

        $line($paint(sprintf('  ok (%d ms)', $ms), 'green'));
        $results[$label] = 'ok';

        if ($dumpAll) {
            $dump($slug);
        }

        return $response;
    } catch (Throwable $e) {
        $ms = (int) round((microtime(true) - $startedAt) * 1000);
        $fail(sprintf('%s (%d ms)', class_basename($e), $ms));
        $fail('  '.$e->getMessage());
        $dump($slug);
        $results[$label] = class_basename($e);

        return null;
    }
};

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

$pnrNumber = null;
$hotelSegment = null;
$interrupted = null;
$exitCode = 0;

try {
    // -- 1. Search ----------------------------------------------------------
    $searchParams = [
        'start' => $checkIn,
        'end' => $checkOut,
        'quantity' => $rooms,
        'guest_count' => $guests,
        'currency' => $currency,
    ];

    $hotelCodeArg !== null
        ? $searchParams['hotel_code'] = $hotelCodeArg
        : $searchParams['hotel_city_code'] = $city;

    $search = $step('search', 'hotelSearch', fn () => $amadeus->hotelSearch('multi', $searchParams));

    if ($search === null) {
        throw new RuntimeException('la búsqueda falló; no hay nada que encadenar');
    }

    $note(sprintf('%d hotel(es), %d tarifa(s)', count($search->hotels), count($search->roomStays)));

    if ($search->hotels === []) {
        throw new RuntimeException('sin disponibilidad para esos parámetros; prueba otras fechas o ciudad');
    }

    // Pick the first property that actually carries a rate. RoomStayRPH is a
    // space-separated list for multi-rate properties, so pairing goes through
    // HotelResult::roomStays() rather than matching the raw attribute.
    $hotel = null;
    $roomStay = null;

    foreach ($search->hotels as $candidate) {
        $rates = $candidate->roomStays($search->roomStays);

        if ($rates !== []) {
            $hotel = $candidate;
            $roomStay = $rates[0];
            break;
        }
    }

    if (! $hotel instanceof HotelResult || ! $roomStay instanceof RoomStayResult) {
        throw new RuntimeException('ningún hotel del resultado trae una tarifa asociada');
    }

    $note(sprintf('elegido: %s (%s) · chain %s · %d tarifa(s)',
        $hotel->hotelName, $hotel->hotelCode, $hotel->chainCode,
        count($hotel->roomStays($search->roomStays)),
    ));
    $note(sprintf('tarifa: plan %s · booking %s · room %s · %s%s',
        $roomStay->ratePlanCode,
        $roomStay->bookingCode,
        $roomStay->roomTypeCode,
        $roomStay->currency,
        $roomStay->total?->amountAfterTax ?? $roomStay->total?->amountBeforeTax ?? '?',
    ));

    // hotelPricing requires room_type_code, and Amadeus returns some rates
    // without one — 4 of CPMTYE71's 32, including the very one a city search
    // reports. Those cannot be priced at all, so they are not candidates.
    //
    // Nothing else about the rate's shape is filtered on. Wildcard room codes
    // ("*RH") and a "Converted:BAR:P" category do sell; two earlier versions of
    // this script tried to predict refusals from those markers and were wrong
    // both times.
    $priceable = fn (RoomStayResult $rate): bool => $rate->roomTypeCode !== ''
        && $rate->bookingCode !== '';

    /**
     * Pick a rate out of a single-hotel search: the one the city search
     * pointed at, else the first that can be priced.
     */
    $pickRate = function (HotelSearchResponse $reply) use ($roomStay, $priceable): ?RoomStayResult {
        foreach ($reply->roomStays as $candidate) {
            if ($priceable($candidate)
                && $candidate->ratePlanCode === $roomStay->ratePlanCode
                && $candidate->roomTypeCode === $roomStay->roomTypeCode) {
                return $candidate;
            }
        }

        foreach ($reply->roomStays as $candidate) {
            if ($priceable($candidate)) {
                return $candidate;
            }
        }

        return null;
    };

    // -- 2. Single-hotel search --------------------------------------------
    // A city-wide search is stateless and its booking codes are summary
    // values; Amadeus answers pricing with Errors/Error Code="SCM" if you
    // price straight off one. Pricing needs a stateful single-hotel search
    // first, and the fresh BookingCode that search returns.
    //
    // No rate_code filter: the plan code a city search reports is a converted
    // value, and filtering the single search by it gets "RATE NOT LOADED"
    // (Error Code 842). An empty array omits RatePlanCandidates entirely, so
    // Amadeus returns whatever is actually loaded for the property.
    $searchOne = fn (string $hotelCode) => $amadeus->hotelSearch('single', [
        'start' => $checkIn,
        'end' => $checkOut,
        'hotel_code' => $hotelCode,
        'quantity' => $rooms,
        'guest_count' => $guests,
        'currency' => $currency,
        'rate_code' => [],
    ]);

    $single = $step('search-single', "hotelSearch('single') — abre sesión y refresca la tarifa",
        fn () => $searchOne($hotel->hotelCode));

    if ($single === null) {
        throw new RuntimeException('la búsqueda por hotel falló; pricing no puede continuar');
    }

    $note(sprintf('%d tarifa(s) cargada(s) para %s', count($single->roomStays), $hotel->hotelCode));

    $fresh = $pickRate($single);

    // Nothing to sell and nothing to price.
    //
    // Searching a different property here would be a mistake: each
    // single-hotel search replaces the session's availability context, so
    // pricing the first property after searching a second one fails with
    // Errors/Error Code="SCI". Everything from here to the sell has to stay on
    // one property.
    if (! $fresh instanceof RoomStayResult) {
        throw new RuntimeException(sprintf(
            'ninguna de las %d tarifa(s) de %s trae roomTypeCode y bookingCode, '
            .'que hotelPricing exige; prueba otra propiedad o fechas',
            count($single->roomStays),
            $hotel->hotelCode,
        ));
    }

    $note(sprintf('booking code fresco: %s (plan %s · room %s · categoría %s)',
        $fresh->bookingCode, $fresh->ratePlanCode, $fresh->roomTypeCode, $fresh->ratePlanCategory));

    // -- 3. Pricing ---------------------------------------------------------
    $pricing = $step('pricing', 'hotelPricing', fn () => $amadeus->hotelPricing([
        'start' => $checkIn,
        'end' => $checkOut,
        'hotel_code' => $hotel->hotelCode,
        'rate_plan_code' => $fresh->ratePlanCode,
        'booking_code' => $fresh->bookingCode,
        'room_type_code' => $fresh->roomTypeCode,
        'quantity' => $rooms,
        'guest_count' => $guests,
    ]));

    $describe = fn () => $step('descriptive', 'hotelDescriptiveInfo', fn () => $amadeus->hotelDescriptiveInfo([
        'hotelCode' => $hotel->hotelCode,
    ]));

    if (! $book) {
        // -- 4. Descriptive info (stateless) --------------------------------
        $describe();

        $line();
        $note('sin --book: se omiten PNR create, hotelSell, end transaction, pnrRetrieve');
    } else {
        // hotelDescriptiveInfo is deliberately NOT called here. It is a
        // stateless request, which makes Amadeus open and immediately release
        // a session, and dropping that between the availability search and the
        // sell risks losing the availability context the sell depends on —
        // the failure mode the docs describe as a context-missing error.
        // BookingV2 calls it after the booking is committed; so do we.
        $note('hotelDescriptiveInfo se posterga: es stateless y rompería el contexto de venta');

        // -- 4. PNR create --------------------------------------------------
        $paxSurname = $env('AMADEUS_TST_PAX_SURNAME') ?? 'TEST';
        $paxFirstName = $env('AMADEUS_TST_PAX_FIRSTNAME') ?? 'TESTER';

        if ($bookingV2) {
            // AmadeusController::store: one name element per occupant, each
            // carrying the stay's check-out (it dates the RU retention
            // segment), plus the loyalty remark when a program applies.
            $passengers = [['surname' => $paxSurname, 'name' => $paxFirstName, 'type' => 'ADT', 'check_out_date' => $checkOut]];
            for ($i = 2; $i <= (int) $guests; $i++) {
                $passengers[] = ['surname' => $paxSurname, 'name' => 'COMPANION'.chr(64 + $i), 'type' => 'ADT', 'check_out_date' => $checkOut];
            }
            $remarks = ['loyalty_programs' => [mb_substr(
                "LEALTAD NUM TST1234 PROGRAMA TEST REWARDS TITULAR {$paxSurname}/{$paxFirstName} FAVOR DE AGREGAR PUNTOS",
                0, 199,
            )]];

            $create = $step('pnr-create', "addMultiElements('create') — forma BookingV2", fn () => $amadeus->addMultiElements('create', $passengers, $remarks));
        } else {
            $create = $step('pnr-create', "addMultiElements('create')", fn () => $amadeus->addMultiElements('create', [
                'surname' => $paxSurname,
                'name' => $paxFirstName,
                'type' => 'ADT',
            ]));
        }

        if ($create === null) {
            throw new RuntimeException('no se pudo crear el PNR; se detiene la cadena');
        }

        $note('travelAgentRef: '.$create->travelAgentRef);
        $note(sprintf('%d viajero(s)', count($create->travelers)));

        if ($bookingV2) {
            // What Amadeus recorded: the RU retention segment's date and the RM remark
            $retention = $create->raw->evaluate("string(//res:originDestinationDetails/res:itineraryInfo[res:elementManagementItinerary/res:segmentName = 'RU']/res:travelProduct/res:product/res:depDate)");
            $remark = $create->raw->evaluate("string(//res:dataElementsIndiv[res:elementManagementData/res:segmentName = 'RM']//res:freetext)");
            $note('retención (RU): '.($retention !== '' ? $retention : '(no aparece)'));
            $note('remark de lealtad (RM): '.($remark !== '' ? 'registrado' : '(no aparece)'));
        }

        $traveler = $create->travelers[0] ?? null;

        if ($traveler === null) {
            throw new RuntimeException('el PNR se creó sin referencias de viajero; hotelSell no puede continuar');
        }

        // Payment type follows the rate's guarantee code, the way BookingV2
        // derives it — a GuaranteeCode of 8 wants 2, anything else wants 1.
        // --payment-type overrides it.
        if (! isset($options['payment-type']) && $pricing !== null) {
            $guaranteeCode = $pricing->guaranteeCode;
            $paymentType = $guaranteeCode === '8' ? '2' : '1';
            $note(sprintf('guaranteeCode %s → paymentType %s', $guaranteeCode ?: '(ninguno)', $paymentType));
        }

        // The card holder's name, which is not the passenger's. BookingV2
        // sends the holder in firstName with an empty surname.
        $cardHolder = $env('AMADEUS_TST_CARD_HOLDER') ?? 'Enlaceforte';

        // -- 5. Hotel sell --------------------------------------------------
        // CTL is per rate, not per property: CPMTYE71 sells booking code
        // STN57JU and refuses KNG57JU in the same session with a request that
        // is otherwise byte-identical. The session and its availability context
        // survive a refusal, so the remaining rates can be tried without
        // re-searching — which would replace the context and break pricing.
        $candidates = [$fresh];

        foreach ($single->roomStays as $candidate) {
            if ($priceable($candidate) && $candidate->bookingCode !== $fresh->bookingCode) {
                $candidates[] = $candidate;
            }
        }

        $candidates = array_slice($candidates, 0, $maxSellAttempts);
        $sell = null;

        // AmadeusController::store: always the list form, one array per room,
        // the holder in ccHolderName alone, the principal BHO and companions BOP
        $bookingV2Sell = fn ($rate) => [
            'travelAgentRef' => $create->travelAgentRef,
            [
                'chainCode' => $hotel->chainCode,
                'cityCode' => substr($hotel->hotelCode, 2, 3),
                'hotelCode' => $hotel->hotelCode,
                'paymentType' => $paymentType,
                'bookingCode' => $rate->bookingCode,
                'passengerReference' => array_map(
                    fn ($traveler) => [
                        'value' => $traveler->referenceNumber,
                        'type' => strcasecmp($traveler->firstName, $paxFirstName) === 0 ? 'BHO' : 'BOP',
                    ],
                    $create->travelers,
                ),
                'ccHolderName' => $cardHolder,
                'vendorCode' => $env('AMADEUS_TST_CARD_VENDOR'),
                'cardNumber' => $env('AMADEUS_TST_CARD_NUMBER'),
                'securityId' => $env('AMADEUS_TST_CARD_CVC'),
                'expiryDate' => $env('AMADEUS_TST_CARD_EXPIRY'),
            ],
        ];

        foreach ($candidates as $attempt => $rate) {
            $label = $attempt === 0
                ? 'hotelSell'
                : sprintf('hotelSell (intento %d: %s)', $attempt + 1, $rate->bookingCode);

            $sellParams = $bookingV2
                ? $bookingV2Sell($rate)
                : null;

            $sell = $step($attempt === 0 ? 'sell' : 'sell-'.$rate->bookingCode, $label, fn () => $amadeus->hotelSell($sellParams ?? [
                'travelAgentRef' => $create->travelAgentRef,
                'chainCode' => $hotel->chainCode,
                // An Amadeus property code is chain(2) + city(3) + property(3):
                // YZMTY045 is chain YZ, city MTY, property 045. Taking the
                // first three characters yields "YZM", which does not resolve.
                'cityCode' => substr($hotel->hotelCode, 2, 3),
                'hotelCode' => $hotel->hotelCode,
                // The fresh code from the single-hotel search, not the city one
                'bookingCode' => $rate->bookingCode,
                'paymentType' => $paymentType,
                'vendorCode' => $env('AMADEUS_TST_CARD_VENDOR'),
                'cardNumber' => $env('AMADEUS_TST_CARD_NUMBER'),
                'securityId' => $env('AMADEUS_TST_CARD_CVC'),
                'expiryDate' => $env('AMADEUS_TST_CARD_EXPIRY'),
                'ccHolderName' => $cardHolder,
                'firstName' => $cardHolder,
                'surname' => '',
                'passengerReference' => [
                    // A list, matching BookingV2. HotelSell also accepts a flat
                    // ['type' => …, 'value' => …] for one passenger.
                    [
                        // BHO = booking holder occupant. HotelSell branches on
                        // this to derive the guest-list qualifier
                        // (BHO -> RMO, else ROP).
                        'type' => $passengerRefType,
                        'value' => $traveler->referenceNumber,
                    ],
                ],
            ]),
                // A sell that attaches nothing answers without errors, so check
                // that a room actually came back before calling it a success.
                fn ($response) => $response->roomResults === []
                    ? 'Hotel_Sell no devolvió ningún roomStayData: no se adjuntó habitación al PNR'
                    : null,
            );

            if ($sell !== null) {
                $fresh = $rate;

                if ($attempt > 0) {
                    $note(sprintf('vendió con %s tras %d rechazo(s)', $rate->bookingCode, $attempt));
                }

                break;
            }

            if ($attempt + 1 < count($candidates)) {
                $note(sprintf('%s rechazada; se prueba la siguiente tarifa', $rate->bookingCode));
            }
        }

        if ($sell === null) {
            // End transaction is what commits the PNR. Without a room attached
            // it would leave a passenger-only PNR behind, so stop here and let
            // signOut discard the uncommitted one.
            $fail(sprintf(
                'ninguna de las %d tarifa(s) probadas de %s se pudo vender; '
                .'sube --max-sell-attempts o prueba otra propiedad',
                count($candidates),
                $hotel->hotelCode,
            ));

            throw new RuntimeException(
                'la venta no adjuntó habitación; no se ejecuta el end transaction '
                .'para no dejar un PNR sin reserva. signOut descarta el PNR sin comitear.'
            );
        }

        $note('booking reference: '.($sell->bookingReference ?? '(ninguna)'));
        $note('confirmation: '.($sell->confirmationNumber ?? '(ninguna)'));
        $note(sprintf('%d cuarto(s) en la respuesta', count($sell->roomResults)));

        // -- 6. End transaction ---------------------------------------------
        $end = $step('pnr-end', "addMultiElements('end')", fn () => $bookingV2
            ? $amadeus->addMultiElements('end')
            : $amadeus->addMultiElements('end', [
                'surname' => $paxSurname,
                'name' => $paxFirstName,
                'type' => 'ADT',
            ]));

        if ($end !== null && $end->pnrNumber !== null) {
            $pnrNumber = $end->pnrNumber;
            $line('  '.$paint('PNR creado: '.$pnrNumber, 'yellow'));
        } else {
            $note('sin record locator en la respuesta; no habrá limpieza automática');
        }

        // The hotel segment's ST reference is what pnrCancel takes — not the
        // element number, and not a fixed '1'. The RU retention segment also
        // lives in the PNR, so the number has to come from the HHL segment.
        if ($end !== null && isset($end->segments[0])) {
            $hotelSegment = $end->segments[0]->segmentNumber;
            $note('segmento de hotel: '.$hotelSegment);

            if ($bookingV2) {
                $principal = $end->travelerByReference($end->segments[0]->passengerReference);
                $note(sprintf(
                    'titular del segmento: %s · acompañantes: %d · fechas %s → %s',
                    $principal !== null ? 'encontrado' : '(no aparece)',
                    count($end->segments[0]->companions),
                    $end->segments[0]->start ?: '?',
                    $end->segments[0]->end ?: '?',
                ));
            }
        }

        // -- 7. Retrieve ----------------------------------------------------
        if ($pnrNumber !== null) {
            $retrieve = $step('pnr-retrieve', 'pnrRetrieve', fn () => $amadeus->pnrRetrieve([
                'pnrNumber' => $pnrNumber,
            ]),
                // A PNR with no HHL segment holds a passenger and a retention
                // line but no booking — the whole point of the chain.
                fn ($response) => $response->segments === []
                    ? 'el PNR no tiene ningún segmento HHL: la reserva de hotel no quedó adjunta'
                    : null,
            );

            if ($retrieve !== null) {
                $note(sprintf('%d segmento(s) HHL en el PNR', count($retrieve->segments)));

                // Prefer what the PNR itself reports over the sell reply
                if (isset($retrieve->segments[0])) {
                    $hotelSegment = $retrieve->segments[0]->segmentNumber;
                }
            }
        }

        // -- 8. Reservation details -----------------------------------------
        if ($pnrNumber !== null && $hotelSegment !== null) {
            $details = $step('details', 'hotelCompleteReservationDetails', fn () => $amadeus->hotelCompleteReservationDetails([
                'pnrNumber' => $pnrNumber,
                'segmentNumber' => $hotelSegment,
            ]));

            if ($details !== null) {
                $note(sprintf('total con impuestos: %s %s', $details->currency, $details->totalAmountWithTax));

                foreach ($details->cancellationDescriptions as $description) {
                    $note('política: '.$description);
                }
            }
        }

        // Now that the booking is committed, the stateless call is harmless
        $describe();
    }
} catch (Throwable $e) {
    $line();
    $fail("cadena interrumpida: ".$e->getMessage());
    $interrupted = $e->getMessage();
    $exitCode = 1;
} finally {
    // -- Cleanup: cancel the hotel segment, then always sign out ------------
    if ($pnrNumber !== null && ! $keep) {
        // An earlier step may have failed before the segment number was known
        if ($hotelSegment === null) {
            $recovered = $step('pnr-retrieve-cleanup', 'pnrRetrieve (para localizar el segmento)', fn () => $amadeus->pnrRetrieve([
                'pnrNumber' => $pnrNumber,
            ]));

            $hotelSegment = $recovered->segments[0]->segmentNumber ?? null;
        }

        if ($hotelSegment === null) {
            $fail("no pude determinar el segmento de hotel; el PNR {$pnrNumber} queda en TST");
            $exitCode = 1;
        } else {
            $step('pnr-cancel', "pnrCancel (segmento {$hotelSegment})", fn () => $amadeus->pnrCancel([
                'segmentNumber' => $hotelSegment,
            ]));

            $confirm = $step('pnr-cancel-end', "addMultiElements('cancel') — confirma la cancelación", fn () => $amadeus->addMultiElements('cancel', []));

            if ($confirm !== null) {
                $deleted = $confirm->isSegmentDeleted($hotelSegment);
                $note($deleted
                    ? "segmento {$hotelSegment} cancelado"
                    : "segmento {$hotelSegment} SIGUE en el PNR {$pnrNumber}");

                if (! $deleted) {
                    $exitCode = 1;
                }
            }
        }
    } elseif ($pnrNumber !== null) {
        $line();
        $note("--keep: el PNR {$pnrNumber} queda en TST".($hotelSegment !== null ? " (segmento {$hotelSegment})" : ''));
    }

    $step('signout', 'signOut', fn () => $amadeus->signOut());
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

$heading('Resumen');

$failed = 0;

foreach ($results as $label => $outcome) {
    $ok = $outcome === 'ok';
    $failed += $ok ? 0 : 1;
    $line(sprintf('  %s  %-38s %s',
        $ok ? $paint('✓', 'green') : $paint('✗', 'red'),
        $label,
        $ok ? '' : $paint($outcome, 'red'),
    ));
}

$line();

if ($pnrNumber !== null && $keep) {
    $line('  PNR dejado en TST: '.$paint($pnrNumber, 'yellow'));
}

// $interrupted is set when the chain threw before finishing, which can happen
// with every individual step still reporting ok — an empty search result being
// the obvious case. Reporting "complete" then would be a lie.
if ($failed === 0 && ! $interrupted) {
    $line($paint('  Cadena completa sin errores.', 'green'));
} elseif ($failed === 0) {
    $line($paint('  Cadena incompleta: '.$interrupted, 'red'));
    $exitCode = 1;
} else {
    $line($paint("  {$failed} paso(s) con problemas. XML en {$dumpDir}", 'red'));

    if ($interrupted !== null) {
        $line($paint('  Cadena interrumpida: '.$interrupted, 'red'));
    }

    $exitCode = 1;
}

$line();

exit($exitCode);
