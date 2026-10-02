<?php

namespace Aldogtz\AmadeusSoap\Exceptions;

class SessionException extends AmadeusSoapException
{
    protected ?string $operation = null;

    public static function expired(string $operation): self
    {
        $exception = new self(
            "Amadeus session expired during operation '{$operation}'. The session has been cleared."
        );

        $exception->operation = $operation;

        return $exception;
    }

    public static function invalid(string $operation, string $reason = ''): self
    {
        $message = "Amadeus session invalid during operation '{$operation}'.";

        if ($reason !== '') {
            $message .= " Reason: {$reason}";
        }

        $exception = new self($message);
        $exception->operation = $operation;

        return $exception;
    }

    public function getOperation(): ?string
    {
        return $this->operation;
    }
}
