<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Session;

use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\Stores\CacheSessionStore;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Facades\Cache;

class CacheSessionStoreTest extends TestCase
{
    protected function store(string $prefix = 'amadeus_session_', int $ttl = 900): CacheSessionStore
    {
        return new CacheSessionStore(store: 'array', prefix: $prefix, ttl: $ttl);
    }

    public function test_it_stores_and_retrieves_a_session(): void
    {
        $store = $this->store();

        $store->put('user1', new SessionData('SESSION-1', 3, 'TOKEN-1'));

        $this->assertTrue($store->has('user1'));

        $session = $store->get('user1');
        $this->assertEquals('SESSION-1', $session->sessionId);
        $this->assertEquals(3, $session->sequenceNumber);
        $this->assertEquals('TOKEN-1', $session->securityToken);
    }

    public function test_a_missing_key_reads_as_no_session(): void
    {
        $store = $this->store();

        $this->assertFalse($store->has('nobody'));
        $this->assertNull($store->get('nobody'));
    }

    public function test_it_forgets_a_session(): void
    {
        $store = $this->store();
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));

        $store->forget('user1');

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }

    public function test_forgetting_a_missing_key_is_a_no_op(): void
    {
        $store = $this->store();

        $store->forget('nobody');

        $this->assertFalse($store->has('nobody'));
    }

    public function test_it_overwrites_an_existing_session(): void
    {
        $store = $this->store();
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));
        $store->put('user1', new SessionData('SESSION-2', 9, 'TOKEN-2'));

        $session = $store->get('user1');
        $this->assertEquals('SESSION-2', $session->sessionId);
        $this->assertEquals(9, $session->sequenceNumber);
        $this->assertEquals('TOKEN-2', $session->securityToken);
    }

    public function test_sessions_for_different_keys_do_not_collide(): void
    {
        $store = $this->store();
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));
        $store->put('user2', new SessionData('SESSION-2', 2, 'TOKEN-2'));

        $this->assertEquals('SESSION-1', $store->get('user1')->sessionId);
        $this->assertEquals('SESSION-2', $store->get('user2')->sessionId);
    }

    public function test_the_prefix_is_applied_to_the_underlying_cache_key(): void
    {
        $this->store()->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));

        $this->assertTrue(Cache::store('array')->has('amadeus_session_user1'));
        $this->assertFalse(Cache::store('array')->has('user1'));
    }

    public function test_two_stores_with_different_prefixes_are_isolated(): void
    {
        $tenantA = $this->store(prefix: 'tenant_a_');
        $tenantB = $this->store(prefix: 'tenant_b_');

        $tenantA->put('user1', new SessionData('SESSION-A', 1, 'TOKEN-A'));

        $this->assertTrue($tenantA->has('user1'));
        $this->assertFalse($tenantB->has('user1'));
        $this->assertNull($tenantB->get('user1'));
    }

    public function test_the_session_is_persisted_as_a_plain_array(): void
    {
        // Stored as an array rather than a serialized object so a payload
        // written by one deploy stays readable by the next.
        $this->store()->put('user1', new SessionData('SESSION-1', 3, 'TOKEN-1'));

        $this->assertSame(
            ['sessionId' => 'SESSION-1', 'sequenceNumber' => 3, 'securityToken' => 'TOKEN-1'],
            Cache::store('array')->get('amadeus_session_user1'),
        );
    }

    public function test_the_configured_ttl_is_handed_to_the_cache(): void
    {
        Cache::shouldReceive('store')->with('array')->once()->andReturnSelf();
        Cache::shouldReceive('put')->once()->with(
            'amadeus_session_user1',
            ['sessionId' => 'SESSION-1', 'sequenceNumber' => 3, 'securityToken' => 'TOKEN-1'],
            120,
        );

        $this->store(ttl: 120)->put('user1', new SessionData('SESSION-1', 3, 'TOKEN-1'));
    }

    public function test_a_session_expires_once_the_ttl_passes(): void
    {
        $store = $this->store(ttl: 60);
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));

        $this->travel(61)->seconds();

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }

    public function test_a_session_survives_until_the_ttl_passes(): void
    {
        $store = $this->store(ttl: 60);
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));

        $this->travel(30)->seconds();

        $this->assertTrue($store->has('user1'));
        $this->assertEquals('SESSION-1', $store->get('user1')->sessionId);
    }

    public function test_a_non_array_payload_reads_as_no_session(): void
    {
        Cache::store('array')->put('amadeus_session_user1', 'not-a-session', 900);

        $this->assertNull($this->store()->get('user1'));
    }

    public function test_an_incomplete_payload_reads_as_no_session(): void
    {
        // A payload written by an older version, or a partially overwritten
        // key, must force a fresh Amadeus session rather than blow up.
        Cache::store('array')->put('amadeus_session_user1', ['sessionId' => 'SESSION-1'], 900);

        $this->assertNull($this->store()->get('user1'));
    }
}
