<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class DailyRate
{
    public function __construct(
        public string $effectiveDate,
        public string $expireDate,
        public float $amountBeforeTax,
    ) {}
}
