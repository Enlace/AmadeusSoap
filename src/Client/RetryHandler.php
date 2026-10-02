<?php

namespace Aldogtz\AmadeusSoap\Client;

use Aldogtz\AmadeusSoap\Exceptions\ConnectionException;

/**
 * Handles retry logic with exponential backoff for transient SOAP errors.
 *
 * Only ConnectionException errors (timeouts, SSL, DNS) are retried.
 * Business-logic errors (SoapFaultException) are never retried.
 */
class RetryHandler
{
    public function __construct(
        protected bool $enabled = false,
        protected int $maxAttempts = 3,
        protected int $baseDelayMs = 500,
        protected float $multiplier = 2.0,
        protected int $maxDelayMs = 5000,
    ) {}

    /**
     * Execute a callable with retry logic.
     *
     * @template T
     *
     * @param  callable(): T  $callback
     * @return T
     *
     * @throws ConnectionException  When all retry attempts are exhausted.
     * @throws \Throwable           For non-retryable exceptions (passes through immediately).
     */
    public function execute(callable $callback): mixed
    {
        if (! $this->enabled || $this->maxAttempts <= 1) {
            return $callback();
        }

        $lastException = null;

        for ($attempt = 1; $attempt <= $this->maxAttempts; $attempt++) {
            try {
                return $callback();
            } catch (ConnectionException $e) {
                $lastException = $e;

                // Don't sleep after the last attempt
                if ($attempt < $this->maxAttempts) {
                    $this->sleep($this->calculateDelay($attempt));
                }
            }
            // All other exceptions pass through immediately (not retried)
        }

        throw $lastException;
    }

    /**
     * Calculate the delay in milliseconds for a given attempt (1-indexed).
     *
     * Uses exponential backoff: baseDelay * multiplier^(attempt - 1)
     * Capped at maxDelayMs.
     */
    public function calculateDelay(int $attempt): int
    {
        $delay = (int) ($this->baseDelayMs * ($this->multiplier ** ($attempt - 1)));

        return min($delay, $this->maxDelayMs);
    }

    /**
     * Sleep for the given number of milliseconds.
     *
     * Extracted for testability — can be overridden in tests.
     */
    protected function sleep(int $milliseconds): void
    {
        usleep($milliseconds * 1000);
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getMaxAttempts(): int
    {
        return $this->maxAttempts;
    }
}
