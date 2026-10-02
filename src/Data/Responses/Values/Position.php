<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class Position
{
    public function __construct(
        public string $latitude,
        public string $longitude,
    ) {}
}
