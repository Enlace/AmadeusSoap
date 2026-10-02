<?php

namespace Aldogtz\AmadeusSoap\Tests\Doubles;

use Illuminate\Contracts\Cache\Store;
use RuntimeException;

/**
 * Cache store whose every operation fails, like Redis during an outage.
 */
class FailingCacheStore implements Store
{
    protected function fail(): never
    {
        throw new RuntimeException('Cache store unavailable');
    }

    public function get($key)
    {
        $this->fail();
    }

    public function many(array $keys)
    {
        $this->fail();
    }

    public function put($key, $value, $seconds)
    {
        $this->fail();
    }

    public function putMany(array $values, $seconds)
    {
        $this->fail();
    }

    public function increment($key, $value = 1)
    {
        $this->fail();
    }

    public function decrement($key, $value = 1)
    {
        $this->fail();
    }

    public function forever($key, $value)
    {
        $this->fail();
    }

    public function forget($key)
    {
        $this->fail();
    }

    // Part of the Store contract from Laravel 13
    public function touch($key, $seconds)
    {
        $this->fail();
    }

    public function flush()
    {
        $this->fail();
    }

    public function getPrefix()
    {
        return '';
    }
}
