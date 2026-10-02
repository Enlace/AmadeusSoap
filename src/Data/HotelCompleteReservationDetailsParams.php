<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;

final readonly class HotelCompleteReservationDetailsParams
{
    use ValidatesParams;

    public function __construct(
        public string $pnrNumber,
        public string $segmentNumber,
    ) {}

    public static function fromArray(array $data): self
    {
        $data = self::acceptSnakeCase($data);

        self::validateRequired($data, ['pnrNumber', 'segmentNumber'], 'HotelCompleteReservationDetailsParams');

        return new self(
            pnrNumber: $data['pnrNumber'],
            segmentNumber: $data['segmentNumber'],
        );
    }
}
