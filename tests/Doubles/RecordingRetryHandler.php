<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Aldogtz\AmadeusSoap\Client\RetryHandler;

/**
 * RetryHandler that records the backoff delays instead of sleeping through
 * them, so retry behaviour can be asserted without slowing the suite down.
 */
class RecordingRetryHandler extends RetryHandler
{
    /** @var int[] milliseconds slept, in order */
    public array $delays = [];

    protected function sleep(int $milliseconds): void
    {
        $this->delays[] = $milliseconds;
    }
}
