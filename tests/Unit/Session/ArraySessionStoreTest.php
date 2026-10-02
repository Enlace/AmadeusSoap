<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Session;

use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\Stores\ArraySessionStore;
use PHPUnit\Framework\TestCase;

class ArraySessionStoreTest extends TestCase
{
    public function test_it_stores_and_retrieves_session(): void
    {
        $store = new ArraySessionStore;
        $session = new SessionData('sess1', 1, 'tok1');

        $store->put('user1', $session);

        $this->assertTrue($store->has('user1'));
        $retrieved = $store->get('user1');
        $this->assertNotNull($retrieved);
        $this->assertEquals('sess1', $retrieved->sessionId);
        $this->assertEquals(1, $retrieved->sequenceNumber);
        $this->assertEquals('tok1', $retrieved->securityToken);
    }

    public function test_it_returns_null_for_missing_key(): void
    {
        $store = new ArraySessionStore;

        $this->assertFalse($store->has('nonexistent'));
        $this->assertNull($store->get('nonexistent'));
    }

    public function test_it_forgets_session(): void
    {
        $store = new ArraySessionStore;
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));

        $this->assertTrue($store->has('user1'));

        $store->forget('user1');

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }

    public function test_it_flushes_all_sessions(): void
    {
        $store = new ArraySessionStore;
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));
        $store->put('user2', new SessionData('sess2', 1, 'tok2'));

        $this->assertEquals(2, $store->count());

        $store->flush();

        $this->assertEquals(0, $store->count());
        $this->assertFalse($store->has('user1'));
        $this->assertFalse($store->has('user2'));
    }

    public function test_it_overwrites_existing_session(): void
    {
        $store = new ArraySessionStore;
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));
        $store->put('user1', new SessionData('sess2', 5, 'tok2'));

        $retrieved = $store->get('user1');
        $this->assertEquals('sess2', $retrieved->sessionId);
        $this->assertEquals(5, $retrieved->sequenceNumber);
    }
}
