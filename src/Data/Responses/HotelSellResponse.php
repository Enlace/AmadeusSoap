<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;

final class HotelSellResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     * @param  SellRoomResult[]  $roomResults
     */
    public function __construct(
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly ?string $bookingReference,
        public readonly ?string $confirmationNumber,
        public readonly array $roomResults,
        public readonly AmadeusResponse $raw,
    ) {}

    public static function fromResponse(AmadeusResponse $response): self
    {
        $errors = [];
        $errorGroupNodes = self::nodes($response, '//res:errorGroup');

        foreach ($errorGroupNodes as $node) {
            // Amadeus reports the code under messageErrorInformation; the
            // errorWarningCode path is a different shape kept as a fallback.
            $code = self::str($response, './res:messageErrorInformation/res:errorDetails/res:errorCode', $node)
                ?: self::str($response, './res:errorWarningCode/res:errorDetails/res:errorCode', $node);

            $freeTextNodes = self::nodes($response, './res:errorWarningDescription/res:freeText', $node);

            // A refused sell can arrive as a bare code with no description at
            // all. Reporting nothing for it made a failed booking look like a
            // success, so an errorGroup always yields at least one error.
            if ($freeTextNodes->length === 0) {
                $errors[] = new AmadeusError(
                    message: $code !== '' ? "Amadeus rejected the sell (code {$code})" : 'Amadeus rejected the sell',
                    code: $code,
                    type: 'error',
                );

                continue;
            }

            foreach ($freeTextNodes as $textNode) {
                $errors[] = new AmadeusError(
                    message: trim($textNode->textContent),
                    code: $code,
                    type: 'error',
                );
            }
        }

        // Hotel_SellReply carries the reservation number at
        // globalBookingInfo/bookingInfo. The bookingRecordId and
        // bookingConfirmationNumber paths tried first are request-side shapes
        // that never appear in the reply; they stay as fallbacks.
        $bookingReference = self::str($response, '//res:roomStayData/res:globalBookingInfo/res:bookingInfo/res:reservation/res:controlNumber')
            ?: self::str($response, '//res:roomStayData/res:bookingRecordId/res:reservation/res:controlNumber')
            ?: null;

        // The hotel's confirmation number: the controlNumber of the property's
        // reservation, the same value PNR_Reply reports for the segment. The
        // booking code is only an echo of the request (see roomResults).
        $confirmationNumber = self::str($response, '//res:roomStayData/res:globalBookingInfo/res:bookingInfo/res:reservation/res:controlNumber')
            ?: self::str($response, '//res:roomStayData/res:globalBookingInfo/res:bookingConfirmationNumber/res:reservation/res:controlNumber')
            ?: null;

        // Parse room results
        $roomResults = self::parseRoomResults($response);

        return new self(
            hasErrors: count($errors) > 0,
            errors: $errors,
            bookingReference: $bookingReference,
            confirmationNumber: $confirmationNumber,
            roomResults: $roomResults,
            raw: $response,
        );
    }

    /**
     * @return SellRoomResult[]
     */
    private static function parseRoomResults(AmadeusResponse $response): array
    {
        $results = [];
        $roomNodes = self::nodes($response, '//res:roomStayData');

        foreach ($roomNodes as $node) {
            // Reply-side paths first, request-side shapes as fallbacks
            $bookingCode = self::str($response, './res:roomListInfo/res:requestableInformation/res:roomRateDetails/res:roomInformation/res:bookingCode', $node)
                ?: self::str($response, './res:roomList/res:roomRateDetails/res:hotelProductReference/res:referenceDetails[./res:type/text() = "BC"]/res:value', $node);

            $bookingRef = self::str($response, './res:globalBookingInfo/res:bookingInfo/res:reservation/res:controlNumber', $node)
                ?: self::str($response, './res:bookingRecordId/res:reservation/res:controlNumber', $node);

            $confirmNbr = self::str($response, './res:globalBookingInfo/res:bookingInfo/res:reservation/res:controlNumber', $node)
                ?: self::str($response, './res:globalBookingInfo/res:bookingConfirmationNumber/res:reservation/res:controlNumber', $node);

            // The reply nests the hotel reference under hotelPropertyInfo;
            // markerGlobalBookingInfo is the request-side element name.
            $hotelRefBase = './res:globalBookingInfo/res:hotelPropertyInfo/res:hotelReference';
            $chainCode = self::str($response, $hotelRefBase.'/res:chainCode', $node)
                ?: self::str($response, './res:globalBookingInfo/res:markerGlobalBookingInfo/res:hotelReference/res:chainCode', $node);
            $cityCode = self::str($response, $hotelRefBase.'/res:cityCode', $node)
                ?: self::str($response, './res:globalBookingInfo/res:markerGlobalBookingInfo/res:hotelReference/res:cityCode', $node);
            $hotelCode = self::str($response, $hotelRefBase.'/res:hotelCode', $node)
                ?: self::str($response, './res:globalBookingInfo/res:markerGlobalBookingInfo/res:hotelReference/res:hotelCode', $node);

            $results[] = new SellRoomResult(
                bookingCode: $bookingCode,
                bookingReference: $bookingRef ?: null,
                confirmationNumber: $confirmNbr ?: null,
                chainCode: $chainCode,
                cityCode: $cityCode,
                hotelCode: $chainCode.$cityCode.$hotelCode,
                hotelName: self::str($response, './res:globalBookingInfo/res:hotelPropertyInfo/res:hotelName', $node),
            );
        }

        return $results;
    }
}
