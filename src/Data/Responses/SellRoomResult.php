<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

/**
 * Represents a single room booking result from Hotel_Sell.
 */
final readonly class SellRoomResult
{
    public function __construct(
        public string $bookingCode,
        public ?string $bookingReference,
        public ?string $confirmationNumber,
        public string $chainCode,
        public string $cityCode,
        public string $hotelCode,
        public string $hotelName = '',
    ) {}
}
