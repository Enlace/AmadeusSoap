<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

/**
 * Resolved companion information — links a passenger reference number
 * to the traveler's name from the travellerInfo nodes.
 */
final readonly class CompanionInfo
{
    public function __construct(
        public string $referenceNumber,
        public string $firstName,
        public string $surname,
        public string $type,
    ) {}
}
