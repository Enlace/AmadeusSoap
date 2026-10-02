<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Concerns;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;

trait ParsesAmadeusXml
{
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
}
