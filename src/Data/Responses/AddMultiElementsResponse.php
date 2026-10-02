<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;

final class AddMultiElementsResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     * @param  TravelerReference[]  $travelers
     * @param  PnrSegment[]  $segments
     */
    public function __construct(
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly ?string $pnrNumber,
        public readonly string $travelAgentRef,
        public readonly array $travelers,
        public readonly array $segments,
        public readonly string $ratePlanCode,
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

        $hasErrors = count($errors) > 0;

        $pnrNumber = self::str($response, '//res:pnrHeader/res:reservationInfo/res:reservation/res:controlNumber') ?: null;

        $travelAgentRef = self::str(
            $response,
            "//res:dataElementsIndiv/res:elementManagementData[./res:segmentName/text() = 'AP']/res:reference[./res:qualifier/text() = 'OT']/res:number"
        );

        $travelers = self::parseTravelers($response);
        $segments = self::parseSegments($response, $travelers);

        // Target rateCode rather than its parent: string() over <negotiated>
        // would also pick up whitespace between child elements.
        $ratePlanCode = self::str($response, '//res:originDestinationDetails/res:itineraryInfo/res:hotelProduct/res:negotiated/res:rateCode')
            ?: self::str($response, '//res:originDestinationDetails/res:itineraryInfo/res:hotelProduct/res:negotiated');

        return new self(
            hasErrors: $hasErrors,
            errors: $errors,
            pnrNumber: $pnrNumber,
            travelAgentRef: $travelAgentRef,
            travelers: $travelers,
            segments: $segments,
            ratePlanCode: $ratePlanCode,
            raw: $response,
        );
    }

    /**
     * Find a traveler reference by name.
     */
    public function findTravelerByName(string $firstName, string $surname): ?TravelerReference
    {
        $firstName = mb_strtoupper($firstName);
        $surname = mb_strtoupper($surname);

        foreach ($this->travelers as $traveler) {
            if (mb_strtoupper($traveler->firstName) === $firstName && mb_strtoupper($traveler->surname) === $surname) {
                return $traveler;
            }
        }

        return null;
    }

    /**
     * Check if a segment has been deleted (for cancel operations).
     */
    public function isSegmentDeleted(string $segmentNumber): bool
    {
        foreach ($this->segments as $segment) {
            if ($segment->segmentNumber === $segmentNumber) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return TravelerReference[]
     */
    private static function parseTravelers(AmadeusResponse $response): array
    {
        $travelers = [];
        $travelerNodes = self::nodes($response, '//res:travellerInfo');

        foreach ($travelerNodes as $node) {
            $referenceNumber = self::str($response, './res:elementManagementPassenger/res:reference/res:number', $node);
            $referenceQualifier = self::str($response, './res:elementManagementPassenger/res:reference/res:qualifier', $node);
            $firstName = self::str($response, './res:passengerData/res:travellerInformation/res:passenger/res:firstName', $node);
            $surname = self::str($response, './res:passengerData/res:travellerInformation/res:traveller/res:surname', $node);
            $type = self::str($response, './res:passengerData/res:travellerInformation/res:passenger/res:type', $node);

            if ($firstName === '' && $surname === '') {
                continue;
            }

            $travelers[] = new TravelerReference(
                referenceNumber: $referenceNumber,
                referenceQualifier: $referenceQualifier,
                firstName: $firstName,
                surname: $surname,
                type: $type,
            );
        }

        return $travelers;
    }

    /**
     * Build a lookup map of reference number => TravelerReference.
     *
     * @param  TravelerReference[]  $travelers
     * @return array<string, TravelerReference>
     */
    private static function buildTravelerLookup(array $travelers): array
    {
        $lookup = [];
        foreach ($travelers as $traveler) {
            $lookup[$traveler->referenceNumber] = $traveler;
        }

        return $lookup;
    }

    /**
     * Resolve companion reference numbers into CompanionInfo objects
     * using the traveler lookup.
     *
     * @param  string[]  $companionNumbers
     * @param  array<string, TravelerReference>  $travelerLookup
     * @return CompanionInfo[]
     */
    private static function resolveCompanions(array $companionNumbers, array $travelerLookup): array
    {
        $companions = [];

        foreach ($companionNumbers as $refNumber) {
            if (isset($travelerLookup[$refNumber])) {
                $traveler = $travelerLookup[$refNumber];
                $companions[] = new CompanionInfo(
                    referenceNumber: $refNumber,
                    firstName: $traveler->firstName,
                    surname: $traveler->surname,
                    type: $traveler->type,
                );
            }
        }

        return $companions;
    }

    /**
     * @param  TravelerReference[]  $travelers
     * @return PnrSegment[]
     */
    private static function parseSegments(AmadeusResponse $response, array $travelers): array
    {
        $travelerLookup = self::buildTravelerLookup($travelers);
        $segments = [];
        $segmentNodes = self::nodes($response, "//res:originDestinationDetails/res:itineraryInfo[./res:elementManagementItinerary/res:segmentName/text() = 'HHL']");

        foreach ($segmentNodes as $node) {
            $segmentNumber = self::str($response, "./res:elementManagementItinerary/res:reference[./res:qualifier/text() = 'ST']/res:number", $node);
            $confirmation = self::str($response, './res:hotelReservationInfo/res:cancelOrConfirmNbr/res:reservation/res:controlNumber', $node);
            $passengerRef = self::str($response, "./res:referenceForSegment/res:reference[./res:qualifier/text() = 'HOP']/res:number", $node);

            // Hotel code components
            $hotelRefNode = self::nodes($response, './res:hotelReservationInfo/res:hotelPropertyInfo/res:hotelReference', $node)->item(0);
            $chainCode = $hotelRefNode ? self::str($response, './res:chainCode', $hotelRefNode) : '';
            $cityCode = $hotelRefNode ? self::str($response, './res:cityCode', $hotelRefNode) : '';
            $hotelCode = $hotelRefNode ? self::str($response, './res:hotelCode', $hotelRefNode) : '';

            // Companion references (POT qualifier — note trailing space in Amadeus response)
            $companionNodes = self::nodes($response, "./res:referenceForSegment/res:reference[./res:qualifier/text() = 'POT ' or ./res:qualifier/text() = 'POT']/res:number", $node);
            $companionNumbers = [];
            foreach ($companionNodes as $compNode) {
                $companionNumbers[] = trim($compNode->textContent);
            }

            // Resolve companion names from traveler data
            $companions = self::resolveCompanions($companionNumbers, $travelerLookup);

            $segments[] = new PnrSegment(
                segmentNumber: $segmentNumber,
                confirmationNumber: $confirmation,
                passengerReference: $passengerRef,
                chainCode: $chainCode,
                cityCode: $cityCode,
                hotelCode: $chainCode . $cityCode . $hotelCode,
                companionReferences: $companionNumbers,
                companions: $companions,
            );
        }

        return $segments;
    }
}
