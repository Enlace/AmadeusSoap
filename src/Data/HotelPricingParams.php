<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;
use Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult;

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

    /**
     * Price a rate from a single-hotel search: hotel, dates, codes and
     * occupancy come from the room stay. $overrides wins over all of them.
     */
    public static function fromRoomStay(RoomStayResult $roomStay, array $overrides = []): self
    {
        return self::fromArray(array_merge([
            'start' => $roomStay->start,
            'end' => $roomStay->end,
            'hotel_code' => $roomStay->hotelCode,
            'rate_plan_code' => $roomStay->ratePlanCode,
            'booking_code' => $roomStay->bookingCode,
            'room_type_code' => $roomStay->roomTypeCode,
            'quantity' => $roomStay->numberOfUnits ?: '1',
            'guest_count' => (string) max(1, $roomStay->adults),
            'children' => $roomStay->children,
        ], $overrides));
    }

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
