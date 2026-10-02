<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

/**
 * Represents an HHL (hotel) segment within a PNR.
 */
final readonly class PnrSegment
{
    /**
     * @param  string[]  $companionReferences  Passenger reference numbers (POT qualifier)
     * @param  CompanionInfo[]  $companions  Resolved companion info with names
     * @param  string  $start  Check-in (Y-m-d) from requestedDates; '' when missing
     * @param  string  $end  Check-out (Y-m-d) from requestedDates; '' when missing
     * @param  string  $ratePlanCode  hotelProduct/negotiated/rateCode of this segment
     */
    public function __construct(
        public string $segmentNumber,
        public string $confirmationNumber,
        public string $passengerReference,
        public string $chainCode,
        public string $cityCode,
        public string $hotelCode,
        public array $companionReferences,
        public array $companions = [],
        public string $start = '',
        public string $end = '',
        public string $ratePlanCode = '',
    ) {}
}
