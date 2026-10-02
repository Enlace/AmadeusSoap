<?php

namespace Aldogtz\AmadeusSoap\Logging;

use Illuminate\Support\Facades\Log;

class SoapLogger
{
    public function __construct(
        protected bool $enabled = false,
        protected string $channel = 'stack',
        protected array $operations = [],
        protected string $level = 'debug',
    ) {}

    public function shouldLog(string $operation): bool
    {
        if (! $this->enabled) {
            return false;
        }

        if (empty($this->operations)) {
            return true;
        }

        return in_array($operation, $this->operations);
    }

    public function logRequest(string $operation, ?string $xml): void
    {
        if (! $this->shouldLog($operation)) {
            return;
        }

        Log::channel($this->channel)->log($this->level, "Amadeus SOAP Request [{$operation}]", [
            'operation' => $operation,
            'xml' => $xml,
        ]);
    }

    public function logResponse(string $operation, ?string $xml): void
    {
        if (! $this->shouldLog($operation)) {
            return;
        }

        Log::channel($this->channel)->log($this->level, "Amadeus SOAP Response [{$operation}]", [
            'operation' => $operation,
            'xml' => $xml,
        ]);
    }

    public function logError(string $operation, \Throwable $e): void
    {
        if (! $this->enabled) {
            return;
        }

        Log::channel($this->channel)->error("Amadeus SOAP Error [{$operation}]", [
            'operation' => $operation,
            'message' => $e->getMessage(),
            'exception' => $e,
        ]);
    }
}
