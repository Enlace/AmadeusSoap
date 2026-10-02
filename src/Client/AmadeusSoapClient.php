<?php

namespace Aldogtz\AmadeusSoap\Client;

use SoapClient;
use SoapHeader;

class AmadeusSoapClient extends SoapClient
{
    /** @var SoapHeader[] */
    protected array $pendingHeaders = [];

    public function setHeaders(array $headers): void
    {
        $this->pendingHeaders = $headers;
    }

    public function __call($functionName, $arguments): mixed
    {
        return parent::__soapCall(
            $functionName,
            $arguments,
            null,
            $this->pendingHeaders
        );
    }
}
