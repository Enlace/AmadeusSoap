<?php

namespace Aldogtz\AmadeusSoap\Services;

use SoapClient;

class AmadeusSoap
{
    protected $client;

    public function __construct(String $wsdl)
    {
        $this->client = new SoapClient($wsdl, [
            'trace' => true,
            'exception' => true,
        ]);
    }
}