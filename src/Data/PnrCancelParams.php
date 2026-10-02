<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;

final readonly class PnrCancelParams
{
    use ValidatesParams;

    public function __construct(
        public string|array $segmentNumber,
    ) {}

    public static function fromArray(array $data): self
    {
        self::validateRequired($data, ['segmentNumber'], 'PnrCancelParams');

        return new self(
            segmentNumber: $data['segmentNumber'],
        );
    }
}
