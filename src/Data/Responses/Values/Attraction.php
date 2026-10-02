<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class Attraction
{
    public function __construct(
        public string $name,
        public string $categoryCode,
        /** @var RefPoint[] */
        public array $refPoints,
    ) {}
}
