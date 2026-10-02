<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class CurrencyConversion
{
    public function __construct(
        public string $sourceCurrencyCode,
        public string $requestedCurrencyCode,
        public float $rateConversion,
    ) {}
}
