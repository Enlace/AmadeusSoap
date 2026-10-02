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
    ) {}
}
