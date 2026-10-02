<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Aldogtz\AmadeusSoap\Client\AmadeusSoapClient;
use SoapFault;
use SoapHeader;

/**
 * Stand-in for AmadeusSoapClient that records what the transport did to it
 * and never touches the network.
 *
 * Built in non-WSDL mode so construction performs no I/O.
 */
class FakeSoapClient extends AmadeusSoapClient
{
    /** @var SoapHeader[] */
    public array $capturedHeaders = [];

    /** @var string[] */
    public array $calledOperations = [];

    /** @var mixed[] */
    public array $capturedArguments = [];

    public int $callCount = 0;

    /** Thrown on every call until cleared. */
    public ?SoapFault $faultToThrow = null;

    /** Faults thrown one per call, in order — anything left over falls back to $faultToThrow. */
    public array $faultSequence = [];

    public ?string $requestXml = '<soap:Envelope><soap:Body><Request/></soap:Body></soap:Envelope>';

    public ?string $responseXml = '<soap:Envelope><soap:Body><Reply/></soap:Body></soap:Envelope>';

    public function __construct()
    {
        parent::__construct(null, [
            'location' => 'http://localhost/soap',
            'uri' => 'urn:amadeus-soap-test',
            'trace' => true,
        ]);
    }

    public function setHeaders(array $headers): void
    {
        $this->capturedHeaders = $headers;

        parent::setHeaders($headers);
    }

    public function __call($functionName, $arguments): mixed
    {
        $this->callCount++;
        $this->calledOperations[] = $functionName;
        $this->capturedArguments[] = $arguments;

        $fault = array_shift($this->faultSequence) ?? $this->faultToThrow;

        if ($fault !== null) {
            throw $fault;
        }

        return null;
    }

    public function __getLastRequest(): ?string
    {
        return $this->requestXml;
    }

    public function __getLastResponse(): ?string
    {
        return $this->responseXml;
    }

    /** Look up a captured header by its local name. */
    public function header(string $name): ?SoapHeader
    {
        foreach ($this->capturedHeaders as $header) {
            if ($header->name === $name) {
                return $header;
            }
        }

        return null;
    }

    /** @return string[] local names of every captured header, in order */
    public function headerNames(): array
    {
        return array_map(fn (SoapHeader $header) => $header->name, $this->capturedHeaders);
    }
}
