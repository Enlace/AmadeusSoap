<?php

namespace Aldogtz\AmadeusSoap\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Dispatched just before a SOAP operation is sent to Amadeus.
 *
 * Useful for logging, metrics, or adding operation-specific hooks.
 */
class OperationStarting
{
    use Dispatchable;

    public function __construct(
        public readonly string $operation,
        public readonly bool $isStateful,
        public readonly float $startedAt,
    ) {}
}
