<?php

namespace Aldogtz\AmadeusSoap\Testing;

use Aldogtz\AmadeusSoap\Client\AmadeusSoapClient;
use RuntimeException;

/**
 * SoapClient that never touches the network: it records every request and
 * answers with queued reply XML (FIFO). Everything above the HTTP layer —
 * WSDL handling, headers, envelope serialization — is the real thing.
 */
class ReplaySoapClient extends AmadeusSoapClient
{
    /** @var string[] */
    protected array $responses = [];

    /** @var array<int, array{operation: string, action: string, location: string, xml: string}> */
    public array $requests = [];

    protected string $currentOperation = '';

    public function __call($functionName, $arguments): mixed
    {
        $this->currentOperation = (string) $functionName;

        return parent::__call($functionName, $arguments);
    }

    public function queueResponse(string $xml): static
    {
        $this->responses[] = $xml;

        return $this;
    }

    public function pendingResponses(): int
    {
        return count($this->responses);
    }

    public function __doRequest(string $request, string $location, string $action, int $version, bool $oneWay = false, ?string $uriParserClass = null): ?string
    {
        $this->requests[] = [
            'operation' => $this->currentOperation,
            'action' => $action,
            'location' => $location,
            'xml' => $request,
        ];

        if ($this->responses === []) {
            throw new RuntimeException("Unexpected Amadeus call (no reply queued): {$this->currentOperation}");
        }

        return array_shift($this->responses);
    }
}
