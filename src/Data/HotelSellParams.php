<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;

final readonly class HotelSellParams
{
    use ValidatesParams;

    public function __construct(
        public string $travelAgentRef,
        public array $roomStayData,
    ) {}

    public static function fromArray(array $data): self
    {
        self::validateRequired($data, ['travelAgentRef'], 'HotelSellParams');

        $travelAgentRef = $data['travelAgentRef'];
        $rooms = [];

        foreach ($data as $key => $value) {
            if ($key !== 'travelAgentRef' && is_array($value)) {
                $rooms[] = $value;
            }
        }

        // If no multi-dimensional rooms found, the data itself is a single room
        if (empty($rooms) && isset($data['chainCode'])) {
            $rooms[] = $data;
        }

        return new self(
            travelAgentRef: $travelAgentRef,
            roomStayData: $rooms,
        );
    }
}
