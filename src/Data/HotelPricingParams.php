<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;

final readonly class HotelPricingParams
{
    use ValidatesParams;

    public function __construct(
        public string $start,
        public string $end,
        public string $hotelCode,
        public string $ratePlanCode,
        public string $bookingCode,
        public string $roomTypeCode,
        public string $quantity,
        public string $isPerRoom,
        public string $guestCount,
        public array $children = [],
    ) {}

    public static function fromArray(array $data): self
    {
        self::validateRequired($data, [
            'start',
            'end',
            'hotel_code',
            'rate_plan_code',
            'booking_code',
            'room_type_code',
            'quantity',
            'guest_count',
        ], 'HotelPricingParams');

        self::validateDates($data, ['start', 'end'], 'HotelPricingParams');

        return new self(
            start: $data['start'],
            end: $data['end'],
            hotelCode: $data['hotel_code'],
            ratePlanCode: $data['rate_plan_code'],
            bookingCode: $data['booking_code'],
            roomTypeCode: $data['room_type_code'],
            quantity: (string) $data['quantity'],
            isPerRoom: $data['is_per_room'] ?? 'true',
            guestCount: (string) $data['guest_count'],
            children: $data['children'] ?? [],
        );
    }
}
