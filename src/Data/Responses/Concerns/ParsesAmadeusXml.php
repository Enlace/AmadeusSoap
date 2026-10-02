<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Concerns;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Address;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;
use Aldogtz\AmadeusSoap\Data\Responses\Values\CancelPenalty;
use Aldogtz\AmadeusSoap\Data\Responses\Values\CurrencyConversion;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Tax;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Warning;

trait ParsesAmadeusXml
{
    /**
     * Parse a reply from its XML (a SOAP envelope or the bare reply element),
     * e.g. a fixture file in an application's tests.
     */
    public static function fromXml(string $xml): static
    {
        return static::fromResponse(AmadeusResponse::fromXml($xml));
    }

    /**
     * Read a scalar, trimmed.
     *
     * Amadeus pads some values (the POT segment qualifier arrives as "POT "),
     * and string() over an element with children picks up inter-element
     * whitespace, so every scalar read is trimmed rather than trusting the
     * document to be tight.
     */
    protected static function str(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): string
    {
        return trim((string) $response->evaluate("string($xpath)", $context));
    }

    protected static function float(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): float
    {
        return (float) self::str($response, $xpath, $context);
    }

    protected static function int(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): int
    {
        return (int) self::str($response, $xpath, $context);
    }

    protected static function bool(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): bool
    {
        return ! empty($response->evaluate($xpath, $context));
    }

    /**
     * OTA boolean attribute ("true"/"false" or "1"/"0"); null when absent or unrecognized.
     */
    protected static function otaBoolean(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): ?bool
    {
        return match (strtolower(self::str($response, $xpath, $context))) {
            'true', '1' => true,
            'false', '0' => false,
            default => null,
        };
    }

    /**
     * Quote a value for safe interpolation into an XPath expression.
     */
    protected static function xpathLiteral(string $value): string
    {
        if (! str_contains($value, "'")) {
            return "'".$value."'";
        }

        if (! str_contains($value, '"')) {
            return '"'.$value.'"';
        }

        return 'concat('.implode(", \"'\", ", array_map(
            fn (string $part) => "'".$part."'",
            explode("'", $value),
        )).')';
    }

    protected static function nodes(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): \DOMNodeList
    {
        $result = $response->evaluate($xpath, $context);

        return $result instanceof \DOMNodeList ? $result : new \DOMNodeList;
    }

    /**
     * Parse OTA-standard errors (//res:Errors/res:Error).
     *
     * @return AmadeusError[]
     */
    protected static function parseOtaErrors(AmadeusResponse $response): array
    {
        $errors = [];
        $nodes = self::nodes($response, '//res:Errors/res:Error');

        foreach ($nodes as $node) {
            $errors[] = new AmadeusError(
                message: trim($node->textContent),
                code: self::str($response, './@Code', $node),
                type: 'error',
            );
        }

        return $errors;
    }

    /**
     * Parse OTA warnings (//res:Warnings/res:Warning), the OK marker included.
     *
     * @return Warning[]
     */
    protected static function parseOtaWarnings(AmadeusResponse $response): array
    {
        $warnings = [];

        foreach (self::nodes($response, '//res:Warnings/res:Warning') as $node) {
            $warnings[] = new Warning(
                type: self::str($response, './@Type', $node),
                code: self::str($response, './@Code', $node),
                status: self::str($response, './@Status', $node),
                tag: self::str($response, './@Tag', $node),
                text: trim($node->textContent),
            );
        }

        return $warnings;
    }

    /**
     * @return CancelPenalty[]
     */
    protected static function cancelPenaltiesAt(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): array
    {
        $penalties = [];

        foreach (self::nodes($response, $xpath, $context) as $node) {
            $descriptions = [];
            foreach (self::nodes($response, './res:PenaltyDescription', $node) as $descNode) {
                $descriptions[] = $descNode->nodeValue;
            }

            $penalties[] = new CancelPenalty(
                // OTA booleans arrive as "true"/"false" or "1"/"0"
                nonRefundable: self::otaBoolean($response, './@NonRefundable', $node) === true,
                amount: self::float($response, './res:AmountPercent/@Amount', $node),
                currencyCode: self::str($response, './res:AmountPercent/@CurrencyCode', $node),
                absoluteDeadline: self::str($response, './res:Deadline/@AbsoluteDeadline', $node) ?: null,
                descriptions: $descriptions,
            );
        }

        return $penalties;
    }

    /**
     * @return Tax[]
     */
    protected static function taxesAt(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): array
    {
        $taxes = [];

        foreach (self::nodes($response, $xpath, $context) as $node) {
            $taxes[] = new Tax(
                code: self::str($response, './@Code', $node) ?: null,
                percent: self::float($response, './@Percent', $node) ?: null,
                amount: self::float($response, './@Amount', $node) ?: null,
                currencyCode: self::str($response, './@CurrencyCode', $node) ?: null,
                chargeUnit: self::str($response, './@ChargeUnit', $node) ?: null,
                type: self::str($response, './@Type', $node) ?: null,
            );
        }

        return $taxes;
    }

    /**
     * @return CurrencyConversion[]
     */
    protected static function currencyConversionsAt(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): array
    {
        $conversions = [];

        foreach (self::nodes($response, $xpath, $context) as $node) {
            $conversions[] = new CurrencyConversion(
                sourceCurrencyCode: self::str($response, './@SourceCurrencyCode', $node),
                requestedCurrencyCode: self::str($response, './@RequestedCurrencyCode', $node),
                rateConversion: self::float($response, './@RateConversion', $node),
            );
        }

        return $conversions;
    }

    /**
     * Card codes (VI, MC, AX…) under the given GuaranteeAccepted path,
     * uppercased and without duplicates.
     *
     * @return string[]
     */
    protected static function cardCodesAt(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): array
    {
        $codes = [];

        foreach (self::nodes($response, $xpath, $context) as $node) {
            $code = strtoupper(trim((string) $node->nodeValue));
            if ($code !== '') {
                $codes[$code] = $code;
            }
        }

        return array_values($codes);
    }

    /**
     * EDIFACT-style date (year/month/day children, month and day not
     * zero-padded) as Y-m-d; null when a part is missing.
     */
    protected static function dateAt(AmadeusResponse $response, string $xpath, ?\DOMNode $context = null): ?string
    {
        $year = self::str($response, $xpath.'/res:year', $context);
        $month = self::str($response, $xpath.'/res:month', $context);
        $day = self::str($response, $xpath.'/res:day', $context);

        if ($year === '' || $month === '' || $day === '') {
            return null;
        }

        return sprintf('%04d-%02d-%02d', (int) $year, (int) $month, (int) $day);
    }

    /**
     * Read an OTA Address element. Several AddressLine elements are joined
     * with a newline.
     */
    protected static function addressFrom(AmadeusResponse $response, \DOMNode $node): Address
    {
        $lines = [];
        foreach (self::nodes($response, './res:AddressLine', $node) as $lineNode) {
            $lines[] = trim((string) $lineNode->nodeValue);
        }

        return new Address(
            addressLine: implode("\n", $lines),
            cityName: self::str($response, './res:CityName', $node),
            postalCode: self::str($response, './res:PostalCode', $node),
            countryCode: self::str($response, './res:CountryName/@Code', $node),
            countryName: self::str($response, './res:CountryName', $node),
            stateCode: self::str($response, './res:StateProv/@StateCode', $node),
            stateName: self::str($response, './res:StateProv', $node),
            useType: self::str($response, './@UseType', $node),
        );
    }
}
