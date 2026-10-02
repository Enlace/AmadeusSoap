<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Aldogtz\AmadeusSoap\Client\AmadeusSoapClient;
use RuntimeException;

/**
 * SoapClient that never touches the network: it records every request and
 * answers with queued response XML (FIFO). Everything above the HTTP layer —
 * WSDL handling, headers, envelope serialization — is the real thing.
 */
class ReplaySoapClient extends AmadeusSoapClient
{
    /** @var string[] */
    protected array $responses = [];

    /** @var array<int, array{action: string, location: string, xml: string}> */
    public array $requests = [];

    /**
     * When set, returned by __getLastResponse() instead of the real capture,
     * e.g. '' to simulate a client built with trace disabled.
     */
    public ?string $lastResponseOverride = null;

    public function __getLastResponse(): ?string
    {
        return $this->lastResponseOverride ?? parent::__getLastResponse();
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
        $this->requests[] = ['action' => $action, 'location' => $location, 'xml' => $request];

        if ($this->responses === []) {
            throw new RuntimeException("Unexpected SOAP call (nothing queued): {$action}");
        }

        return array_shift($this->responses);
    }
}
