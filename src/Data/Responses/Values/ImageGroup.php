<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class ImageGroup
{
    public function __construct(
        public string $infoCode,
        public string $additionalDetailCode,
        /** @var HotelImage[] */
        public array $items,
    ) {}
}
