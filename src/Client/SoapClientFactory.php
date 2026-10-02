<?php

namespace Aldogtz\AmadeusSoap\Client;

class SoapClientFactory
{
    /** @var array<string, AmadeusSoapClient> */
    protected array $pool = [];

    public function __construct(
        protected array $options = [],
    ) {}

    /**
     * Get or create a SoapClient for the given WSDL path.
     *
     * SoapClient construction is expensive (~50-200ms) because it parses
     * the WSDL, resolves types, and builds the stream context. Pooling
     * by WSDL path avoids recreating clients for the same WSDL across
     * multiple operations in a single request lifecycle.
     */
    public function create(string $wsdlPath): AmadeusSoapClient
    {
        if (isset($this->pool[$wsdlPath])) {
            return $this->pool[$wsdlPath];
        }

        $defaults = [
            'trace' => true,
            'exception' => true,
            'cache_wsdl' => WSDL_CACHE_MEMORY,
            'stream_context' => stream_context_create([
                'http' => [
                    'protocol_version' => '1.0',
                    'header' => 'Connection: Close',
                ],
            ]),
        ];

        $options = array_merge($defaults, $this->options);

        $client = new AmadeusSoapClient($wsdlPath, $options);
        $this->pool[$wsdlPath] = $client;

        return $client;
    }

    /**
     * Flush the client pool. Useful for testing or long-running processes.
     */
    public function flush(): void
    {
        $this->pool = [];
    }

    /**
     * Get the number of cached clients.
     */
    public function poolSize(): int
    {
        return count($this->pool);
    }
}
