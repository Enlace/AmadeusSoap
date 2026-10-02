<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Aldogtz\AmadeusSoap\Testing\ReplaySoapClient as BaseReplaySoapClient;

/**
 * The shipped replay client, plus a knob the package's own tests need.
 */
class ReplaySoapClient extends BaseReplaySoapClient
{
    /**
     * When set, returned by __getLastResponse() instead of the real capture,
     * e.g. '' to simulate a client built with trace disabled.
     */
    public ?string $lastResponseOverride = null;

    public function __getLastResponse(): ?string
    {
        return $this->lastResponseOverride ?? parent::__getLastResponse();
    }
}
