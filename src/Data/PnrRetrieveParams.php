<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;

final readonly class PnrRetrieveParams
{
    use ValidatesParams;

    public function __construct(
        public string $pnrNumber,
    ) {}

    public static function fromArray(array $data): self
    {
        self::validateRequired($data, ['pnrNumber'], 'PnrRetrieveParams');

        return new self(
            pnrNumber: $data['pnrNumber'],
        );
    }
}
