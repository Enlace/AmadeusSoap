<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class HotelImage
{
    public function __construct(
        public string $category,
        public string $url,
        public string $description,
        public string $dimensionCategory,
    ) {}
}
