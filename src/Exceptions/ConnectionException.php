<?php

namespace Aldogtz\AmadeusSoap\Exceptions;

/**
 * Thrown when SOAP transport encounters a network-level error
 * (connection timeout, SSL failure, DNS resolution, etc.).
 */
class ConnectionException extends AmadeusSoapException
{
    protected ?string $lastRequest = null;

    protected ?string $lastResponse = null;

    /**
     * Create from a connection timeout.
     */
    public static function timeout(string $operation, ?\Throwable $previous = null): self
    {
        $exception = new self(
            "Connection timeout during Amadeus operation '{$operation}'.",
            0,
            $previous,
        );

        return $exception;
    }

    /**
     * Create from an SSL/TLS error.
     */
    public static function sslError(string $operation, string $detail, ?\Throwable $previous = null): self
    {
        return new self(
            "SSL/TLS error during Amadeus operation '{$operation}': {$detail}",
            0,
            $previous,
        );
    }

    /**
     * Create from a generic connection failure.
     */
    public static function failed(string $operation, string $reason, ?\Throwable $previous = null): self
    {
        return new self(
            "Connection failed during Amadeus operation '{$operation}': {$reason}",
            0,
            $previous,
        );
    }

    public function withTransportContext(?string $lastRequest, ?string $lastResponse): self
    {
        $this->lastRequest = $lastRequest;
        $this->lastResponse = $lastResponse;

        return $this;
    }

    public function getLastRequest(): ?string
    {
        return $this->lastRequest;
    }

    public function getLastResponse(): ?string
    {
        return $this->lastResponse;
    }
}
