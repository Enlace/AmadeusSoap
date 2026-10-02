<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class GuestRoom
{
    public function __construct(
        public string $roomTypeCode,
        public string $name,
        /** @var string[] */
        public array $amenityCodes,
    ) {}
}
