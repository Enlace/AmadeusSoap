<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class CancelPenalty
{
    public function __construct(
        public bool $nonRefundable,
        public float $amount,
        public string $currencyCode,
        public ?string $absoluteDeadline,
        /** @var string[] */
        public array $descriptions,
    ) {}
}
