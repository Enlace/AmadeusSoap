<?php

namespace Aldogtz\AmadeusSoap\Testing;

use Aldogtz\AmadeusSoap\Client\AmadeusSoapClient;
use Aldogtz\AmadeusSoap\Client\SoapClientFactory;

/**
 * Hands out a single ReplaySoapClient, so one reply queue serves every
 * operation regardless of the WSDL it belongs to.
 */
class ReplaySoapClientFactory extends SoapClientFactory
{
    protected ?ReplaySoapClient $client = null;

    public function create(string $wsdlPath): AmadeusSoapClient
    {
        return $this->client ??= $this->newClient($wsdlPath);
    }

    public function client(string $wsdlPath): ReplaySoapClient
    {
        return $this->create($wsdlPath);
    }

    protected function newClient(string $wsdlPath): ReplaySoapClient
    {
        return new ReplaySoapClient($wsdlPath, [
            'trace' => true,
            'exceptions' => true,
            'cache_wsdl' => WSDL_CACHE_NONE,
        ]);
    }
}
