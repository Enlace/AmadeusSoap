<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;

final class PnrCancelResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     */
    public function __construct(
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly AmadeusResponse $raw,
    ) {}

    public static function fromResponse(AmadeusResponse $response): self
    {
        $errors = [];
        $errorInfoNodes = self::nodes($response, '//res:generalErrorInfo');

        foreach ($errorInfoNodes as $node) {
            $text = self::str($response, './res:messageErrorText/res:text', $node);
            $code = self::str($response, './res:messageErrorInformation/res:errorDetail/res:qualifier', $node);

            $errors[] = new AmadeusError(
                message: $text ?: 'Unknown error',
                code: $code,
                type: 'error',
            );
        }

        return new self(
            hasErrors: count($errors) > 0,
            errors: $errors,
            raw: $response,
        );
    }
}
