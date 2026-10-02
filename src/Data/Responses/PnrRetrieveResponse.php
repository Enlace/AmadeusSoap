<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;

final class PnrRetrieveResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     * @param  PnrRetrieveSegment[]  $segments
     */
    public function __construct(
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly ?string $pnrNumber,
        public readonly array $segments,
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

        $pnrNumber = self::str($response, '//res:pnrHeader/res:reservationInfo/res:reservation/res:controlNumber') ?: null;

        $segments = [];
        $segmentNodes = self::nodes($response, "//res:originDestinationDetails/res:itineraryInfo[./res:elementManagementItinerary/res:segmentName/text() = 'HHL']");

        foreach ($segmentNodes as $node) {
            $segments[] = new PnrRetrieveSegment(
                segmentNumber: self::str($response, "./res:elementManagementItinerary/res:reference[./res:qualifier/text() = 'ST']/res:number", $node),
            );
        }

        return new self(
            hasErrors: count($errors) > 0,
            errors: $errors,
            pnrNumber: $pnrNumber,
            segments: $segments,
            raw: $response,
        );
    }
}
