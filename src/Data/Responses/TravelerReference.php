<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

final readonly class TravelerReference
{
    public function __construct(
        public string $referenceNumber,
        public string $referenceQualifier,
        public string $firstName,
        public string $surname,
        public string $type,
    ) {}
}
