<?php

namespace Aldogtz\AmadeusSoap\Session\Stores;

use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionData;
use Illuminate\Support\Facades\Cache;

class CacheSessionStore implements SessionStore
{
    public function __construct(
        protected string $store = 'file',
        protected string $prefix = 'amadeus_session_',
        protected int $ttl = 900,
    ) {}

    public function get(string $key): ?SessionData
    {
        return SessionData::tryFromArray(
            Cache::store($this->store)->get($this->prefix.$key)
        );
    }

    public function put(string $key, SessionData $data): void
    {
        Cache::store($this->store)->put(
            $this->prefix.$key,
            $data->toArray(),
            $this->ttl,
        );
    }

    public function forget(string $key): void
    {
        Cache::store($this->store)->forget($this->prefix.$key);
    }

    public function has(string $key): bool
    {
        // Resolved through get() so an unusable payload reports as "no
        // session". A has()/get() disagreement would make HeaderBuilder send
        // a Start session header with no WS-Security credentials attached.
        return $this->get($key) !== null;
    }
}
