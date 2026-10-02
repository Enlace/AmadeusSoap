<?php

namespace Aldogtz\AmadeusSoap\Session\Contracts;

use Aldogtz\AmadeusSoap\Session\SessionData;

interface SessionStore
{
    public function get(string $key): ?SessionData;

    public function put(string $key, SessionData $data): void;

    public function forget(string $key): void;

    public function has(string $key): bool;
}
