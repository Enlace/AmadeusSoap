<?php

namespace Aldogtz\AmadeusSoap\Exceptions;

use SoapFault;

class AuthenticationException extends AmadeusSoapException
{
    protected ?string $lastRequest = null;

    protected ?string $lastResponse = null;

    public static function fromSoapFault(
        SoapFault $fault,
        ?string $lastRequest = null,
        ?string $lastResponse = null,
    ): self {
        $exception = new self(
            "Amadeus authentication failed: {$fault->getMessage()}",
            (int) $fault->getCode(),
            $fault,
        );

        $exception->lastRequest = $lastRequest;
        $exception->lastResponse = $lastResponse;

        return $exception;
    }

    public function getLastRequest(): ?string
    {
        return $this->lastRequest;
    }

    public function getLastResponse(): ?string
    {
        return $this->lastResponse;
    }

    public function getSoapFault(): ?SoapFault
    {
        $previous = $this->getPrevious();

        return $previous instanceof SoapFault ? $previous : null;
    }
}
