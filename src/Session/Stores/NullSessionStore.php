<?php

namespace Aldogtz\AmadeusSoap\Session\Stores;

use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionData;

/**
 * A no-op session store for fully stateless operation.
 *
 * All writes are discarded and reads always return null/false.
 * Useful when Amadeus operations are used in a stateless context
 * (e.g. single-request operations without session continuation).
 */
class NullSessionStore implements SessionStore
{
    public function get(string $key): ?SessionData
    {
        return null;
    }

    public function put(string $key, SessionData $data): void
    {
        // Intentionally empty — no persistence
    }

    public function forget(string $key): void
    {
        // Intentionally empty — nothing to forget
    }

    public function has(string $key): bool
    {
        return false;
    }
}
