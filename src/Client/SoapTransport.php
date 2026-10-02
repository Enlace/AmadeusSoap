<?php

namespace Aldogtz\AmadeusSoap\Client;

use Aldogtz\AmadeusSoap\Exceptions\AuthenticationException;
use Aldogtz\AmadeusSoap\Exceptions\ConnectionException;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Headers\HeaderBuilder;
use Aldogtz\AmadeusSoap\Wsdl\OperationMetadata;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use SoapFault;
use SoapVar;

class SoapTransport
{
    protected ?AmadeusSoapClient $client = null;

    public function __construct(
        protected SoapClientFactory $factory,
        protected HeaderBuilder $headerBuilder,
        protected WsdlManager $wsdlManager,
        protected ?RetryHandler $retryHandler = null,
    ) {}

    /**
     * Execute a SOAP operation.
     *
     * @throws SoapFaultException
     * @throws AuthenticationException
     * @throws ConnectionException
     */
    public function call(
        string $operation,
        SoapVar $body,
        OperationMetadata $metadata,
        bool $isStateful,
        bool $hasSessionBody,
    ): string {
        $execute = fn () => $this->doCall($operation, $body, $metadata, $isStateful, $hasSessionBody);

        // Wrap in retry handler if configured — only ConnectionException is retried
        if ($this->retryHandler !== null) {
            return $this->retryHandler->execute($execute);
        }

        return $execute();
    }

    /**
     * The actual SOAP call — extracted so RetryHandler can re-invoke it.
     */
    protected function doCall(
        string $operation,
        SoapVar $body,
        OperationMetadata $metadata,
        bool $isStateful,
        bool $hasSessionBody,
    ): string {
        $this->client = $this->factory->create($metadata->wsdlPath);

        $headers = $this->headerBuilder->build($metadata, $isStateful, $hasSessionBody);
        $this->client->setHeaders($headers);

        try {
            $this->client->{$operation}($body);
        } catch (SoapFault $e) {
            // Detect authentication failures and throw a specific exception
            if ($this->isAuthenticationError($e)) {
                throw AuthenticationException::fromSoapFault(
                    $e,
                    $this->getLastRequest(),
                    $this->getLastResponse(),
                );
            }

            // Detect connection-level errors (timeouts, SSL, DNS)
            if ($this->isConnectionError($e)) {
                throw $this->buildConnectionException($e, $operation);
            }

            // Use raw (unformatted) XML for exceptions — formatting is
            // expensive and the caller can pretty-print when needed.
            throw new SoapFaultException(
                $e,
                $this->getLastRequest(),
                $this->getLastResponse(),
            );
        }

        return $this->client->__getLastResponse() ?: '';
    }

    /**
     * Forget the last exchange, so getLastRequest()/getLastResponse() return
     * null until the next SOAP call (e.g. after serving a response from cache).
     */
    public function forgetLastExchange(): void
    {
        $this->client = null;
    }

    /**
     * Get the raw (unformatted) last SOAP request XML.
     *
     * This is the fast path — returns the XML string exactly as PHP's
     * SoapClient captured it, with no DOM parsing or re-serialization.
     */
    public function getLastRequest(): ?string
    {
        if ($this->client === null) {
            return null;
        }

        $xml = $this->client->__getLastRequest();

        return empty($xml) ? null : $xml;
    }

    /**
     * Get the raw (unformatted) last SOAP response XML.
     *
     * This is the fast path — returns the XML string exactly as PHP's
     * SoapClient captured it, with no DOM parsing or re-serialization.
     */
    public function getLastResponse(): ?string
    {
        if ($this->client === null) {
            return null;
        }

        $xml = $this->client->__getLastResponse();

        return empty($xml) ? null : $xml;
    }

    /**
     * Get the last SOAP request XML, pretty-printed for logging/debugging.
     *
     * Only call this when you actually need formatted output (e.g. logging
     * is enabled). Each call parses + re-serializes the XML (~5-10ms).
     */
    public function getLastRequestFormatted(): ?string
    {
        $xml = $this->getLastRequest();

        return $xml !== null ? $this->formatXml($xml) : null;
    }

    /**
     * Get the last SOAP response XML, pretty-printed for logging/debugging.
     *
     * Only call this when you actually need formatted output (e.g. logging
     * is enabled). Each call parses + re-serializes the XML (~5-10ms).
     */
    public function getLastResponseFormatted(): ?string
    {
        $xml = $this->getLastResponse();

        return $xml !== null ? $this->formatXml($xml) : null;
    }

    /**
     * Pretty-print an XML string using DOMDocument.
     */
    protected function formatXml(string $xml): string
    {
        $dom = new \DOMDocument('1.0');
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = true;
        $dom->loadXML($xml);

        return $dom->saveXML();
    }

    /**
     * Determine if a SoapFault indicates an authentication/credentials error.
     */
    protected function isAuthenticationError(SoapFault $e): bool
    {
        $message = strtolower($e->getMessage());
        $faultCode = strtolower($e->faultcode ?? '');

        // Amadeus puts its own "code|Category|text" string in faultstring and
        // leaves faultcode as a plain soap:Client, so the Amadeus code has to
        // be read from the message. "authenticat" covers both "authentication"
        // and the "Not authenticated" text Amadeus actually returns.
        return str_contains($message, 'authenticat')
            || str_contains($message, 'unauthorized')
            || str_contains($message, 'invalid credentials')
            || str_contains($message, '|security|')
            || str_contains($faultCode, '11|')
            || str_contains($faultCode, 'sender');
    }

    /**
     * Parse Amadeus' "code|Category|text" faultstring.
     *
     * @return array{code: string, category: string, text: string}|null
     */
    public static function parseAmadeusFault(SoapFault $e): ?array
    {
        if (preg_match('/^\s*(\d+)\|([A-Za-z]*)\|(.*)$/s', $e->getMessage(), $m) !== 1) {
            return null;
        }

        return [
            'code' => $m[1],
            'category' => $m[2],
            'text' => trim($m[3]),
        ];
    }

    /**
     * Determine if a SoapFault is a connection-level error (timeout, SSL, DNS).
     */
    protected function isConnectionError(SoapFault $e): bool
    {
        $message = strtolower($e->getMessage());
        $faultCode = strtolower($e->faultcode ?? '');

        // HTTP faultcode is used by PHP SoapClient for transport errors
        if ($faultCode === 'http') {
            return true;
        }

        return str_contains($message, 'could not connect')
            || str_contains($message, 'connection timed out')
            || str_contains($message, 'connection refused')
            || str_contains($message, 'operation timed out')
            || str_contains($message, 'ssl')
            || str_contains($message, 'tls')
            || str_contains($message, 'certificate')
            || str_contains($message, 'name or service not known')
            || str_contains($message, 'failed to load external entity')
            || str_contains($message, 'error fetching http');
    }

    /**
     * Build a specific ConnectionException based on the SoapFault details.
     */
    protected function buildConnectionException(SoapFault $e, string $operation): ConnectionException
    {
        $message = strtolower($e->getMessage());

        if (str_contains($message, 'timed out') || str_contains($message, 'operation timed out')) {
            return ConnectionException::timeout($operation, $e)
                ->withTransportContext($this->getLastRequest(), $this->getLastResponse());
        }

        if (str_contains($message, 'ssl') || str_contains($message, 'tls') || str_contains($message, 'certificate')) {
            return ConnectionException::sslError($operation, $e->getMessage(), $e)
                ->withTransportContext($this->getLastRequest(), $this->getLastResponse());
        }

        return ConnectionException::failed($operation, $e->getMessage(), $e)
            ->withTransportContext($this->getLastRequest(), $this->getLastResponse());
    }
}
