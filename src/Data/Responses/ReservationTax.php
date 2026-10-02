<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

final readonly class ReservationTax
{
    public function __construct(
        public float $amount,
        public float $percentage,
        public string $timeUnit,
        public bool $includedInAmount,
        public ?string $beginDate,
        public ?string $endDate,
    ) {}
}
