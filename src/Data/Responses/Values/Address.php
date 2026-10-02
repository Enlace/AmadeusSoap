<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class Address
{
    public function __construct(
        public string $addressLine,
        public string $cityName,
        public string $postalCode,
        public string $countryCode,
        public string $countryName,
        public string $stateCode,
        public string $stateName,
        public string $useType,
    ) {}
}
