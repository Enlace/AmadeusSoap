<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Aldogtz\AmadeusSoap\Testing\ReplaySoapClient as BaseReplaySoapClient;
use Aldogtz\AmadeusSoap\Testing\ReplaySoapClientFactory as BaseReplaySoapClientFactory;

/**
 * Hands out the tests' ReplaySoapClient (with lastResponseOverride).
 */
class ReplaySoapClientFactory extends BaseReplaySoapClientFactory
{
    public function client(string $wsdlPath): ReplaySoapClient
    {
        return $this->create($wsdlPath);
    }

    protected function newClient(string $wsdlPath): BaseReplaySoapClient
    {
        return new ReplaySoapClient($wsdlPath, [
            'trace' => true,
            'exceptions' => true,
            'cache_wsdl' => WSDL_CACHE_NONE,
        ]);
    }
}
