<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class RefPoint
{
    public function __construct(
        public string $name,
        public string $distance,
        public string $unitOfMeasureCode,
        public string $toFrom,
    ) {}
}
