<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class Tax
{
    public function __construct(
        public ?string $code,
        public ?float $percent,
        public ?float $amount,
        public ?string $currencyCode,
        public ?string $chargeUnit,
    ) {}
}
