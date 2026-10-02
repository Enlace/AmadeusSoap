<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class RoomTotal
{
    public function __construct(
        public float $amountBeforeTax,
        public float $amountAfterTax,
        public string $currencyCode,
    ) {}
}
