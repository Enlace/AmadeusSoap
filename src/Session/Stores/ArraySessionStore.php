<?php

namespace Aldogtz\AmadeusSoap\Session\Stores;

use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionData;

class ArraySessionStore implements SessionStore
{
    protected array $data = [];

    public function get(string $key): ?SessionData
    {
        return $this->data[$key] ?? null;
    }

    public function put(string $key, SessionData $data): void
    {
        $this->data[$key] = $data;
    }

    public function forget(string $key): void
    {
        unset($this->data[$key]);
    }

    public function has(string $key): bool
    {
        return isset($this->data[$key]);
    }

    /**
     * Remove all stored sessions. Useful for testing.
     */
    public function flush(): void
    {
        $this->data = [];
    }

    /**
     * Get the number of stored sessions.
     */
    public function count(): int
    {
        return count($this->data);
    }
}
