<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Aldogtz\AmadeusSoap\Client\SoapTransport;
use Aldogtz\AmadeusSoap\Wsdl\OperationMetadata;
use SoapVar;

/**
 * Stands in for SoapTransport so the whole booking chain can be driven
 * through AmadeusSoap without a network.
 *
 * Deliberately does not call parent::__construct — every method that touches
 * the real collaborators is overridden.
 */
class FakeTransport extends SoapTransport
{
    /**
     * Queued replies per operation. Operations called more than once in a
     * chain (PNR_AddMultiElements runs for create, end and cancel) consume one
     * entry per call; the last entry repeats once the queue runs dry.
     *
     * @var array<string, list<string>>
     */
    protected array $replies = [];

    /**
     * One entry per call: operation, isStateful, hasSessionBody, body XML.
     *
     * @var array<int, array{operation: string, isStateful: bool, hasSessionBody: bool, body: string}>
     */
    public array $calls = [];

    protected ?string $lastRequest = null;

    protected ?string $lastResponse = null;

    public function __construct() {}

    /**
     * Append a reply for an operation. Loads from tests/Fixtures/responses
     * when given a bare filename. Call repeatedly to script successive calls.
     */
    public function reply(string $operation, string $xmlOrFixture): static
    {
        $this->replies[$operation][] = str_starts_with(ltrim($xmlOrFixture), '<')
            ? $xmlOrFixture
            : file_get_contents(dirname(__DIR__).'/Fixtures/responses/'.$xmlOrFixture);

        return $this;
    }

    public function call(
        string $operation,
        SoapVar $body,
        OperationMetadata $metadata,
        bool $isStateful,
        bool $hasSessionBody,
    ): string {
        $this->calls[] = [
            'operation' => $operation,
            'isStateful' => $isStateful,
            'hasSessionBody' => $hasSessionBody,
            'body' => (string) $body->enc_value,
        ];

        if (empty($this->replies[$operation])) {
            throw new \RuntimeException("FakeTransport has no queued reply for '{$operation}'.");
        }

        // Keep the last reply in place so an operation can be called more
        // times than it was scripted.
        $reply = count($this->replies[$operation]) > 1
            ? array_shift($this->replies[$operation])
            : $this->replies[$operation][0];

        $this->lastRequest = (string) $body->enc_value;
        $this->lastResponse = $reply;

        return $reply;
    }

    /** @return string[] operations called, in order */
    public function operations(): array
    {
        return array_column($this->calls, 'operation');
    }

    /** @return array{operation: string, isStateful: bool, hasSessionBody: bool, body: string}|null */
    public function callTo(string $operation): ?array
    {
        foreach ($this->calls as $call) {
            if ($call['operation'] === $operation) {
                return $call;
            }
        }

        return null;
    }

    public function forgetLastExchange(): void
    {
        $this->lastRequest = null;
        $this->lastResponse = null;
    }

    public function getLastRequest(): ?string
    {
        return $this->lastRequest;
    }

    public function getLastResponse(): ?string
    {
        return $this->lastResponse;
    }

    public function getLastRequestFormatted(): ?string
    {
        return $this->lastRequest;
    }

    public function getLastResponseFormatted(): ?string
    {
        return $this->lastResponse;
    }
}
