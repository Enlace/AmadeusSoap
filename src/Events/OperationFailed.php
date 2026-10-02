<?php

namespace Aldogtz\AmadeusSoap\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Dispatched when a SOAP operation fails with an exception.
 *
 * Useful for alerting, error tracking, and circuit breaker patterns.
 */
class OperationFailed
{
    use Dispatchable;

    public readonly float $durationMs;

    public function __construct(
        public readonly string $operation,
        public readonly \Throwable $exception,
        public readonly float $startedAt,
        public readonly float $failedAt,
    ) {
        $this->durationMs = ($failedAt - $startedAt) * 1000;
    }
}
