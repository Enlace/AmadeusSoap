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

    public function test()
    {
        return $this->client->__getFunctions();
    }

    public static function __callStatic($name, $arguments)
    {
        return["método" => $name, "argumentos" => $arguments];
    }
}