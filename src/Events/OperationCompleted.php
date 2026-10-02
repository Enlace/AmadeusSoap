<?php

namespace Aldogtz\AmadeusSoap\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Dispatched after a SOAP operation completes successfully.
 *
 * Useful for logging response times, metrics, and auditing.
 */
class OperationCompleted
{
    use Dispatchable;

    public readonly float $durationMs;

    public function __construct(
        public readonly string $operation,
        public readonly bool $isStateful,
        public readonly float $startedAt,
        public readonly float $completedAt,
    ) {
        $this->durationMs = ($completedAt - $startedAt) * 1000;
    }
}
