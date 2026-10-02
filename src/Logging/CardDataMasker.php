<?php

namespace Aldogtz\AmadeusSoap\Logging;

/**
 * Masks guarantee-card data in SOAP XML: card numbers keep their last four
 * digits, security codes are replaced entirely.
 *
 * Applied to everything the package hands out after a call — the last
 * request/response, the logger and exception payloads — because PCI DSS
 * forbids storing the security code after authorization, and logs and
 * error trackers are storage.
 */
final class CardDataMasker
{
    public static function mask(string $xml): string
    {
        // <cardNumber>, <creditCardNumber>, <securityId>, any namespace prefix
        $xml = preg_replace_callback(
            '#(<(?:[\w.-]+:)?(cardNumber|creditCardNumber|securityId)(?:\s[^>]*)?>)([^<]*)(</(?:[\w.-]+:)?\2>)#',
            fn (array $m) => $m[1].self::maskValue($m[2], $m[3]).$m[4],
            $xml,
        ) ?? $xml;

        // Form of payment in free text: CCVI4111111111111111EXP1230
        return preg_replace_callback(
            '#\bCC([A-Z]{2})(\d{9,15})(\d{4})#',
            fn (array $m) => 'CC'.$m[1].str_repeat('X', strlen($m[2])).$m[3],
            $xml,
        ) ?? $xml;
    }

    private static function maskValue(string $element, string $value): string
    {
        $value = trim($value);

        if ($element === 'securityId') {
            return str_repeat('X', strlen($value));
        }

        return strlen($value) > 4
            ? str_repeat('X', strlen($value) - 4).substr($value, -4)
            : str_repeat('X', strlen($value));
    }
}
