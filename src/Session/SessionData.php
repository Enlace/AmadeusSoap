<?php

namespace Aldogtz\AmadeusSoap\Session;

use DOMXPath;

final readonly class SessionData
{
    public function __construct(
        public string $sessionId,
        public int $sequenceNumber,
        public string $securityToken,
    ) {}

    public function incrementSequence(): self
    {
        return new self(
            sessionId: $this->sessionId,
            sequenceNumber: $this->sequenceNumber + 1,
            securityToken: $this->securityToken,
        );
    }

    public static function fromResponse(DOMXPath $xpath): ?self
    {
        $status = $xpath->evaluate('string(//awsse:Session/@TransactionStatusCode)');

        if ($status !== 'InSeries') {
            return null;
        }

        $sessionId = $xpath->evaluate('string(//awsse:Session/awsse:SessionId)');
        $sequenceNumber = $xpath->evaluate('string(//awsse:Session/awsse:SequenceNumber)');
        $securityToken = $xpath->evaluate('string(//awsse:Session/awsse:SecurityToken)');

        if (empty($sessionId) || empty($securityToken)) {
            return null;
        }

        return new self(
            sessionId: $sessionId,
            sequenceNumber: (int) $sequenceNumber,
            securityToken: $securityToken,
        );
    }

    public function toArray(): array
    {
        return [
            'sessionId' => $this->sessionId,
            'sequenceNumber' => $this->sequenceNumber,
            'securityToken' => $this->securityToken,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            sessionId: $data['sessionId'],
            sequenceNumber: (int) $data['sequenceNumber'],
            securityToken: $data['securityToken'],
        );
    }

    /**
     * Rebuild from a persisted payload, returning null when it is unusable.
     *
     * Session stores hold data written by earlier deploys and data that can
     * be truncated or partially overwritten. An unusable payload has to read
     * as "no session" so the caller opens a fresh one, rather than raising
     * out of the store.
     */
    public static function tryFromArray(mixed $data): ?self
    {
        if (! is_array($data)) {
            return null;
        }

        $sessionId = $data['sessionId'] ?? null;
        $securityToken = $data['securityToken'] ?? null;
        $sequenceNumber = $data['sequenceNumber'] ?? null;

        if (! is_string($sessionId) || $sessionId === '') {
            return null;
        }

        if (! is_string($securityToken) || $securityToken === '') {
            return null;
        }

        if (! is_int($sequenceNumber) && ! (is_string($sequenceNumber) && is_numeric($sequenceNumber))) {
            return null;
        }

        return new self(
            sessionId: $sessionId,
            sequenceNumber: (int) $sequenceNumber,
            securityToken: $securityToken,
        );
    }
}
