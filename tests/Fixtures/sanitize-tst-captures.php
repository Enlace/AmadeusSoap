<?php

/**
 * Turns raw Amadeus TST captures into committable test fixtures.
 *
 *   php tests/Fixtures/sanitize-tst-captures.php [capture-dir] [env-file]
 *
 * Defaults: storage/tst-chain (git-ignored) and .env.tst. Output goes to
 * tests/Fixtures/tst/{requests,responses}.
 *
 * Everything that identifies the account, the agency or a person is replaced
 * by a fixed fake: credentials, office ID, WSAP and endpoint, session tokens,
 * PNR and confirmation numbers, agency IATA number, names, emails and card
 * data. Requests keep only the SOAP Body (the Header carries WS-Security).
 *
 * Secret values are read from the env file, never hardcoded here. Nothing is
 * written if any known secret survives sanitization.
 */

$root = dirname(__DIR__, 2);
$captureDir = rtrim($argv[1] ?? $root.'/storage/tst-chain', '/');
$envFile = $argv[2] ?? $root.'/.env.tst';
$outputDir = __DIR__.'/tst';

/** Fixture (relative to tests/Fixtures/tst) => capture file. */
const FIXTURES = [
    'requests/hotel-search-multi.xml' => '200401-search-request.xml',
    'requests/hotel-search-single.xml' => '172257-search-single-request.xml',
    'requests/hotel-pricing.xml' => '172258-pricing-request.xml',
    'requests/hotel-descriptive-info.xml' => '172259-descriptive-request.xml',
    'requests/pnr-create.xml' => '172300-pnr-create-request.xml',
    'requests/hotel-sell.xml' => '172633-sell-request.xml',
    'requests/signout.xml' => '172302-signout-request.xml',
    'responses/hotel-search-multi.xml' => '200401-search-response.xml',
    'responses/hotel-search-single.xml' => '172257-search-single-response.xml',
    'responses/hotel-pricing.xml' => '172258-pricing-response.xml',
    'responses/hotel-descriptive-info.xml' => '172259-descriptive-response.xml',
    'responses/pnr-create.xml' => '172300-pnr-create-response.xml',
    'responses/hotel-sell.xml' => '200415-sell-response.xml',
    'responses/hotel-sell-ctl-error.xml' => '172301-sell-response.xml',
    'responses/pnr-end.xml' => '200415-pnr-end-response.xml',
    'responses/pnr-retrieve.xml' => '200416-pnr-retrieve-response.xml',
    'responses/hotel-complete-reservation-details.xml' => '200416-details-response.xml',
    'responses/signout.xml' => '172302-signout-response.xml',
];

const FAKE_OFFICE_ID = 'TEST01';
const FAKE_USERNAME = 'WSTESTUSR';
const FAKE_WSAP = '1ASIWTEST';
const FAKE_HOST = 'webservices.amadeus.test';
const FAKE_IATA = '00000000';
const FAKE_EMAIL = 'test@example.com';
const FAKE_SURNAME = 'TRAVELER';
const FAKE_FIRST_NAME = 'TEST';
const FAKE_CARD_HOLDER = 'TEST TRAVELER';
const FAKE_CARD_NUMBER = '378282246310005'; // public Amex test number
const FAKE_CARD_MASKED = 'XXXXXXXXXXX0005';
const FAKE_CVC = '0000';
const FAKE_EXPIRY = '1230';

function fail(string $message): never
{
    fwrite(STDERR, "✗ {$message}\n");
    exit(1);
}

/** @return array<string, string> */
function readEnv(string $file): array
{
    if (! is_file($file)) {
        fail("Env file not found: {$file}");
    }

    $env = [];
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with(trim($line), '#') || ! str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = array_map('trim', explode('=', $line, 2));
        $env[$key] = trim($value, "\"'");
    }

    return $env;
}

/** Regex matching the text content of a leaf element, any prefix. */
function element(string $names): string
{
    return '#(<(?:[\w-]+:)?(?:'.$names.')\b[^>]*>)([^<]*)(</(?:[\w-]+:)?(?:'.$names.')>)#';
}

function replaceElement(string $xml, string $names, callable|string $replacement): string
{
    return preg_replace_callback(element($names), function (array $m) use ($replacement) {
        if (trim($m[2]) === '') {
            return $m[0];
        }

        return $m[1].(is_callable($replacement) ? $replacement($m[2]) : $replacement).$m[3];
    }, $xml);
}

/** @return string[] */
function elementValues(string $xml, string $names): array
{
    preg_match_all(element($names), $xml, $matches);

    return array_values(array_filter(array_map('trim', $matches[2])));
}

/** Keep only the element inside soap:Body. */
function bodyOnly(string $xml, string $fixture): string
{
    $dom = new DOMDocument;
    $dom->preserveWhiteSpace = true;
    if (! $dom->loadXML($xml)) {
        fail("{$fixture}: capture is not valid XML");
    }

    $body = $dom->getElementsByTagNameNS('http://schemas.xmlsoap.org/soap/envelope/', 'Body')->item(0);
    foreach ($body?->childNodes ?? [] as $node) {
        if ($node instanceof DOMElement) {
            return '<?xml version="1.0" encoding="UTF-8"?>'."\n".$dom->saveXML($node)."\n";
        }
    }

    fail("{$fixture}: no SOAP Body element found");
}

$env = readEnv($envFile);
$captures = [];

foreach (FIXTURES as $fixture => $capture) {
    $path = "{$captureDir}/{$capture}";
    if (! is_file($path)) {
        fail("Capture not found: {$path}");
    }
    $captures[$fixture] = file_get_contents($path);
}

// Values that must map consistently across files (a PNR locator appears in
// pnr-end, pnr-retrieve and free texts alike).
// Values shorter than 5 chars are skipped: replacing them globally would
// corrupt unrelated text.
$all = implode("\n", $captures);
$maps = [];
$addMapping = function (string $value, string $fake) use (&$maps) {
    if (strlen($value) >= 5 && ! isset($maps[$value])) {
        $maps[$value] = $fake;
    }
};

foreach (elementValues($all, 'controlNumber') as $value) {
    $addMapping($value, ctype_digit($value)
        ? (string) (10000001 + count($maps))
        : sprintf('TST%03d', count($maps) + 1));
}
foreach (elementValues($all, 'SessionId') as $value) {
    $addMapping($value, sprintf('SESSION%04d', count($maps) + 1));
}
foreach (elementValues($all, 'SecurityToken') as $value) {
    $addMapping($value, sprintf('SECURITYTOKEN%04d', count($maps) + 1));
}
foreach (elementValues($all, 'originatorId|iataCode|creatorIataCode') as $value) {
    $addMapping($value, FAKE_IATA);
}

// Account secrets: replaced anywhere they appear, case-insensitively
$secrets = [];
foreach ([
    'AMADEUS_USERNAME' => FAKE_USERNAME,
    'AMADEUS_OFFICE_ID' => FAKE_OFFICE_ID,
    'AMADEUS_PASSWORD' => 'PASSWORD',
    'AMADEUS_TST_CARD_NUMBER' => FAKE_CARD_NUMBER,
    'AMADEUS_TST_CARD_HOLDER' => FAKE_CARD_HOLDER,
] as $key => $fake) {
    if (strlen($env[$key] ?? '') >= 5) {
        $secrets[] = [$env[$key], $fake];
    }
}

if (empty($env['AMADEUS_USERNAME']) || empty($env['AMADEUS_OFFICE_ID'])) {
    fail('AMADEUS_USERNAME and AMADEUS_OFFICE_ID must be set in the env file');
}

$output = [];

foreach ($captures as $fixture => $xml) {
    $isRequest = str_starts_with($fixture, 'requests/');

    // Tokenized cards (Fort Knox ids) and any other card-length number
    $xml = preg_replace_callback('#(?<![\d.])\d{13,19}(?![\d.])#', fn (array $m) => str_repeat('0', strlen($m[0])), $xml);

    // Card data: masked card free texts embed the expiry date
    $xml = preg_replace('#CC([A-Z]{2})X+\d{4}EXP\d{4}#', 'CC$1'.FAKE_CARD_MASKED.'EXP'.FAKE_EXPIRY, $xml);
    $xml = replaceElement($xml, 'cardNumber', $isRequest ? FAKE_CARD_NUMBER : FAKE_CARD_MASKED);
    $xml = replaceElement($xml, 'creditCardNumber', FAKE_CARD_MASKED);
    $xml = replaceElement($xml, 'securityId', FAKE_CVC);
    $xml = replaceElement($xml, 'expiryDate', FAKE_EXPIRY);
    $xml = replaceElement($xml, 'ccHolderName', FAKE_CARD_HOLDER);

    // People
    $xml = replaceElement($xml, 'surname|Surname', FAKE_SURNAME);
    $xml = replaceElement($xml, 'firstName|givenName|GivenName', FAKE_FIRST_NAME);

    // PNR free texts (AP contacts, RM remarks) may hold phone or loyalty
    // numbers: zero the digits of any such text with 7+ digits
    $zeroDigits = fn (string $text) => preg_match_all('/\d/', $text) >= 7 ? preg_replace('/\d/', '0', $text) : $text;
    $xml = replaceElement($xml, 'longFreetext', $zeroDigits);
    $xml = preg_replace_callback(
        '#<((?:[\w-]+:)?(?:remarks|structuredRemark|miscellaneousRemarks))\b.*?</\1>#s',
        fn (array $m) => replaceElement($m[0], 'freetext|freeText', $zeroDigits),
        $xml,
    );
    $xml = preg_replace_callback(
        '#[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}#',
        fn (array $m) => ctype_upper(preg_replace('/[^A-Za-z]/', '', $m[0])) ? strtoupper(FAKE_EMAIL) : FAKE_EMAIL,
        $xml,
    );

    // Account and endpoint
    $xml = preg_replace('#node\w*\.[\w.]*webservices\.amadeus\.com#', FAKE_HOST, $xml);
    $xml = preg_replace('#1ASIW[A-Z0-9]{3,}#', FAKE_WSAP, $xml);
    foreach ($secrets as [$secret, $fake]) {
        $xml = str_ireplace($secret, $fake, $xml);
    }

    // Locators, sessions, agency numbers (strtr tries longest keys first)
    $xml = strtr($xml, $maps);

    $output[$fixture] = $isRequest ? bodyOnly($xml, $fixture) : $xml;
}

// Verify: no secret or original identifier may survive
$forbidden = array_merge(
    array_column($secrets, 0),
    array_map('strval', array_keys($maps)),
    ['enlaceforte', 'amadeus.com/1ASIW'],
);
// Short values (CVC, expiry, test names) are checked per element and as whole
// words in free texts: as plain substrings they match unrelated data such as
// image hashes or "TEST01".
$fixedFields = [
    'cardNumber' => [FAKE_CARD_NUMBER, FAKE_CARD_MASKED],
    'creditCardNumber' => [FAKE_CARD_MASKED],
    'securityId' => [FAKE_CVC],
    'expiryDate' => [FAKE_EXPIRY],
    'ccHolderName' => [FAKE_CARD_HOLDER],
    'surname|Surname' => [FAKE_SURNAME],
    'firstName|givenName|GivenName' => [FAKE_FIRST_NAME],
];
// Values that are themselves one of the fakes (e.g. a test passenger named
// "TEST") are not secrets.
$fakeWords = array_map('strtolower', preg_split('/\W+/', implode(' ', [
    FAKE_SURNAME, FAKE_FIRST_NAME, FAKE_CARD_HOLDER, FAKE_EMAIL, FAKE_OFFICE_ID, FAKE_USERNAME, FAKE_CVC, FAKE_EXPIRY,
])));
$shortSecrets = array_filter(
    array_map(fn ($key) => $env[$key] ?? '', ['AMADEUS_TST_PAX_SURNAME', 'AMADEUS_TST_PAX_FIRSTNAME', 'AMADEUS_TST_CARD_CVC', 'AMADEUS_TST_CARD_EXPIRY']),
    fn (string $value) => strlen($value) >= 3 && ! in_array(strtolower($value), $fakeWords, true),
);
foreach ($output as $fixture => $xml) {
    $dom = new DOMDocument;
    if (! @$dom->loadXML($xml)) {
        fail("{$fixture}: sanitized output is not valid XML");
    }

    foreach ($forbidden as $value) {
        if (stripos($xml, $value) !== false) {
            fail("{$fixture}: a sensitive value survived sanitization (".strlen($value).' chars)');
        }
    }

    foreach ($fixedFields as $field => $allowed) {
        if (array_diff(elementValues($xml, $field), $allowed) !== []) {
            fail("{$fixture}: <{$field}> survived sanitization");
        }
    }

    $freeTexts = implode("\n", elementValues($xml, 'longFreetext|freetext|freeText|Text'));
    foreach ($shortSecrets as $value) {
        if (preg_match('/\b'.preg_quote($value, '/').'\b/i', $freeTexts)) {
            fail("{$fixture}: a passenger or card value survived in a free text (".strlen($value).' chars)');
        }
    }

    if (preg_match_all('#CC[A-Z]{2}X+\d{4}EXP\d{4}#', $xml, $masked)
        && array_diff($masked[0], preg_grep('#'.FAKE_CARD_MASKED.'EXP'.FAKE_EXPIRY.'$#', $masked[0])) !== []) {
        fail("{$fixture}: a masked card survived sanitization");
    }

    foreach (['Username', 'Nonce', 'Password'] as $header) {
        if (preg_match('#<(?:\w+:)?'.$header.'\b#', $xml)) {
            fail("{$fixture}: WS-Security <{$header}> survived sanitization");
        }
    }
}

foreach ($output as $fixture => $xml) {
    $path = "{$outputDir}/{$fixture}";
    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0775, true);
    }
    file_put_contents($path, $xml);
    echo "✓ {$fixture}\n";
}
