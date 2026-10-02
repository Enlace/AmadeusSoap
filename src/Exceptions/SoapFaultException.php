<?php

namespace Aldogtz\AmadeusSoap\Exceptions;

use SoapFault;

class SoapFaultException extends AmadeusSoapException
{
    protected ?string $lastRequest;

    protected ?string $lastResponse;

    public function __construct(
        SoapFault $fault,
        ?string $lastRequest = null,
        ?string $lastResponse = null,
    ) {
        $this->lastRequest = $lastRequest;
        $this->lastResponse = $lastResponse;

        parent::__construct($fault->getMessage(), (int) $fault->getCode(), $fault);
    }

    public function getLastRequest(): ?string
    {
        return $this->lastRequest;
    }

    public function getLastResponse(): ?string
    {
        return $this->lastResponse;
    }

    public function getSoapFault(): SoapFault
    {
        return $this->getPrevious();
    }
}
