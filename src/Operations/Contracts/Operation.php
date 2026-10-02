<?php

namespace Aldogtz\AmadeusSoap\Operations\Contracts;

/**
 * Contract for all Amadeus SOAP operations.
 *
 * Every operation class must declare the Amadeus operation name
 * it targets and be able to build the SOAP body array.
 */
interface Operation
{
    /**
     * Get the Amadeus SOAP operation name (e.g. 'Hotel_MultiSingleAvailability').
     */
    public function getOperationName(): string;

    /**
     * Build the SOAP body array for this operation.
     *
     * @return array<string, mixed>
     */
    public function build(): array;
}
