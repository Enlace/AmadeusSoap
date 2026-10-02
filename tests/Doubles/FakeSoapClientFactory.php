<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Aldogtz\AmadeusSoap\Client\AmadeusSoapClient;
use Aldogtz\AmadeusSoap\Client\SoapClientFactory;

/**
 * Hands the transport a FakeSoapClient instead of a real one and records
 * which WSDL path it was asked for.
 */
class FakeSoapClientFactory extends SoapClientFactory
{
    /** @var string[] */
    public array $requestedPaths = [];

    public function __construct(public FakeSoapClient $client)
    {
        parent::__construct([]);
    }

    public function create(string $wsdlPath): AmadeusSoapClient
    {
        $this->requestedPaths[] = $wsdlPath;

        return $this->client;
    }
}
