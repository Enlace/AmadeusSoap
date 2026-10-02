<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature;

use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\Stores\RedisSessionStore;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Facades\Redis;

/**
 * Exercises RedisSessionStore against a real Redis server.
 *
 * Skipped when no server is reachable, so the suite still passes on machines
 * without Redis. Start one with `brew services start redis` (or point
 * REDIS_HOST/REDIS_PORT elsewhere) to run these.
 *
 * Only keys under this run's unique prefix are touched — never FLUSHDB.
 */
class RedisSessionStoreIntegrationTest extends TestCase
{
    protected string $prefix;

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('database.redis.client', 'phpredis');
        $app['config']->set('database.redis.options', ['prefix' => '']);
        $app['config']->set('database.redis.default', [
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'port' => (int) env('REDIS_PORT', 6379),
            'password' => env('REDIS_PASSWORD') ?: null,
            'database' => (int) env('REDIS_DB', 15),
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->prefix = 'amadeus_it_'.uniqid().'_';

        try {
            Redis::connection('default')->ping();
        } catch (\Throwable $e) {
            $this->markTestSkipped('No Redis server reachable: '.$e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        if (isset($this->prefix)) {
            try {
                $keys = Redis::connection('default')->keys($this->prefix.'*');

                foreach ($keys as $key) {
                    Redis::connection('default')->del($key);
                }
            } catch (\Throwable) {
                // server went away; nothing to clean
            }
        }

        parent::tearDown();
    }

    protected function store(int $ttl = 900): RedisSessionStore
    {
        return new RedisSessionStore(connection: 'default', prefix: $this->prefix, ttl: $ttl);
    }

    public function test_a_session_survives_a_round_trip_through_redis(): void
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

    public function test_it_overwrites_an_existing_session(): void
    {
        $store = $this->store();
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));
        $store->put('user1', new SessionData('SESSION-2', 9, 'TOKEN-2'));

        $session = $store->get('user1');
        $this->assertEquals('SESSION-2', $session->sessionId);
        $this->assertEquals(9, $session->sequenceNumber);
    }

    public function test_sessions_for_different_keys_do_not_collide(): void
    {
        $store = $this->store();
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));
        $store->put('user2', new SessionData('SESSION-2', 2, 'TOKEN-2'));

        $this->assertEquals('SESSION-1', $store->get('user1')->sessionId);
        $this->assertEquals('SESSION-2', $store->get('user2')->sessionId);
    }

    public function test_redis_holds_the_session_as_json_under_the_prefixed_key(): void
    {
        $this->store()->put('user1', new SessionData('SESSION-1', 3, 'TOKEN-1'));

        $raw = Redis::connection('default')->get($this->prefix.'user1');

        $this->assertSame(
            ['sessionId' => 'SESSION-1', 'sequenceNumber' => 3, 'securityToken' => 'TOKEN-1'],
            json_decode($raw, true),
        );
    }

    public function test_the_key_carries_the_configured_expiry(): void
    {
        $this->store(ttl: 300)->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));

        $ttl = Redis::connection('default')->ttl($this->prefix.'user1');

        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(300, $ttl);
    }

    public function test_a_short_ttl_expires_the_session(): void
    {
        $store = $this->store(ttl: 1);
        $store->put('user1', new SessionData('SESSION-1', 1, 'TOKEN-1'));

        $this->assertTrue($store->has('user1'));

        sleep(2);

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }

    public function test_a_corrupt_payload_reads_as_no_session(): void
    {
        Redis::connection('default')->setex($this->prefix.'user1', 60, 'not json at all');

        $store = $this->store();

        $this->assertNull($store->get('user1'));
        $this->assertFalse($store->has('user1'));
    }
}
