<?php

namespace Aldogtz\AmadeusSoap\Session\Stores;

use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionData;
use Illuminate\Support\Facades\Redis;

class RedisSessionStore implements SessionStore
{
    public function __construct(
        protected string $connection = 'default',
        protected string $prefix = 'amadeus_session_',
        protected int $ttl = 900,
    ) {}

    public function get(string $key): ?SessionData
    {
        $data = Redis::connection($this->connection)->get($this->prefix.$key);

        if (! is_string($data)) {
            return null;
        }

        return SessionData::tryFromArray(json_decode($data, true));
    }

    public function put(string $key, SessionData $data): void
    {
        Redis::connection($this->connection)->setex(
            $this->prefix.$key,
            $this->ttl,
            json_encode($data->toArray())
        );
    }

    public function forget(string $key): void
    {
        Redis::connection($this->connection)->del($this->prefix.$key);
    }

    public function has(string $key): bool
    {
        // Resolved through get() so an unusable payload reports as "no
        // session". A has()/get() disagreement would make HeaderBuilder send
        // a Start session header with no WS-Security credentials attached.
        return $this->get($key) !== null;
    }
}
