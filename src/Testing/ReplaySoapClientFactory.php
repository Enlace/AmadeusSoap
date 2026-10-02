<?php

namespace Aldogtz\AmadeusSoap\Testing;

use Aldogtz\AmadeusSoap\Client\AmadeusSoapClient;
use Aldogtz\AmadeusSoap\Client\SoapClientFactory;

/**
 * Hands out a single ReplaySoapClient, so one reply queue serves every
 * operation regardless of the WSDL it belongs to.
 *
 * The client is built on the first call, not before: replies queued with
 * queue() wait here until then, so a fake nobody calls costs no SoapClient.
 */
class ReplaySoapClientFactory extends SoapClientFactory
{
    protected ?ReplaySoapClient $client = null;

    /** @var string[] */
    protected array $pending = [];

    public function create(string $wsdlPath): AmadeusSoapClient
    {
        if ($this->client === null) {
            $this->client = $this->newClient($wsdlPath);

            foreach ($this->pending as $xml) {
                $this->client->queueResponse($xml);
            }
            $this->pending = [];
        }

        return $this->client;
    }

    public function client(string $wsdlPath): ReplaySoapClient
    {
        return $this->create($wsdlPath);
    }

    /**
     * The client, once a call (or client()) built it.
     */
    public function current(): ?ReplaySoapClient
    {
        return $this->client;
    }

    public function queue(string $xml): void
    {
        if ($this->client !== null) {
            $this->client->queueResponse($xml);
        } else {
            $this->pending[] = $xml;
        }
    }

    public function pendingResponses(): int
    {
        return $this->client?->pendingResponses() ?? count($this->pending);
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
