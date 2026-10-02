<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Session;

use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\Stores\NullSessionStore;
use PHPUnit\Framework\TestCase;

class NullSessionStoreTest extends TestCase
{
    public function test_it_always_returns_null(): void
    {
        $store = new NullSessionStore;

        $this->assertNull($store->get('any_key'));
    }

    public function test_it_never_has_sessions(): void
    {
        $store = new NullSessionStore;

        $store->put('user1', new SessionData('sess1', 1, 'tok1'));

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }

    public function test_forget_does_not_error(): void
    {
        $store = new NullSessionStore;

        // Should not throw
        $store->forget('nonexistent');
        $this->assertFalse($store->has('nonexistent'));
    }
}
