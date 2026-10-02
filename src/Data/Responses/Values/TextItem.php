<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class TextItem
{
    public function __construct(
        public string $infoCode,
        public string $additionalDetailCode,
        public string $description,
    ) {}
}
