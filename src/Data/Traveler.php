<?php

namespace Aldogtz\AmadeusSoap\Data;

/**
 * Passenger written into a PNR by addMultiElements('create').
 */
final readonly class Traveler
{
    /**
     * @param  string  $type  Amadeus passenger type: ADT (adult), CHD, INF…
     */
    public function __construct(
        public string $surname,
        public string $firstName,
        public string $type = 'ADT',
    ) {}

    /**
     * The params PNR_AddMultiElements takes for one passenger.
     *
     * @return array{surname: string, name: string, type: string}
     */
    public function toArray(): array
    {
        return ['surname' => $this->surname, 'name' => $this->firstName, 'type' => $this->type];
    }
}
