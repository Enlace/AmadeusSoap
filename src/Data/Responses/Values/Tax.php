<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class Tax
{
    /**
     * @param  string|null  $type  Inclusive or Exclusive, when the reply says
     */
    public function __construct(
        public ?string $code,
        public ?float $percent,
        public ?float $amount,
        public ?string $currencyCode,
        public ?string $chargeUnit,
        public ?string $type = null,
    ) {}
}
