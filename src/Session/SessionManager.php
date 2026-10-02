<?php

namespace Aldogtz\AmadeusSoap\Session;

use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Closure;

class SessionManager
{
    protected ?string $overrideKey = null;

    public function __construct(
        protected SessionStore $store,
        protected Closure $keyResolver,
        protected array $statelessOperations = [],
    ) {}

    public function withKey(string $key): static
    {
        $this->overrideKey = $key;

        return $this;
    }

    public function getSessionKey(): string
    {
        if ($this->overrideKey !== null) {
            return $this->overrideKey;
        }

        return (string) ($this->keyResolver)();
    }

    public function hasSession(): bool
    {
        return $this->store->has($this->getSessionKey());
    }

    public function getSessionData(): ?SessionData
    {
        return $this->store->get($this->getSessionKey());
    }

    public function saveSession(SessionData $data): void
    {
        $this->store->put($this->getSessionKey(), $data);
    }

    public function clearSession(): void
    {
        $this->store->forget($this->getSessionKey());
    }

    public function isStatelessOperation(string $operation): bool
    {
        return in_array($operation, $this->statelessOperations);
    }

    public function needsSession(string $operation): bool
    {
        return ! $this->isStatelessOperation($operation);
    }

    public function getStore(): SessionStore
    {
        return $this->store;
    }
}
