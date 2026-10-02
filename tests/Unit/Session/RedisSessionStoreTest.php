<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Session;

use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\Stores\RedisSessionStore;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Facades\Redis;
use Mockery;
use Mockery\MockInterface;

/**
 * Contract-level coverage: asserts the exact Redis commands, keys, TTL and
 * payload the store issues, without needing a Redis server.
 *
 * Behaviour against a real server lives in RedisSessionStoreIntegrationTest.
 */
class RedisSessionStoreTest extends TestCase
{
    protected MockInterface $connection;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connection = Mockery::mock();

        Redis::shouldReceive('connection')->andReturn($this->connection);
    }

    protected function store(string $prefix = 'amadeus_session_', int $ttl = 900): RedisSessionStore
    {
        return new RedisSessionStore(connection: 'default', prefix: $prefix, ttl: $ttl);
    }

    protected function payload(string $sessionId = 'SESSION-1', int $sequence = 3, string $token = 'TOKEN-1'): string
    {
        return json_encode([
            'sessionId' => $sessionId,
            'sequenceNumber' => $sequence,
            'securityToken' => $token,
        ]);
    }

    public function test_put_writes_json_with_setex_and_the_configured_ttl(): void
    {
        $this->connection->shouldReceive('setex')
            ->once()
            ->with('amadeus_session_user1', 900, $this->payload());

        $this->store()->put('user1', new SessionData('SESSION-1', 3, 'TOKEN-1'));
    }

    public function test_put_honours_a_custom_ttl(): void
    {
        $this->connection->shouldReceive('setex')
            ->once()
            ->with('amadeus_session_user1', 120, Mockery::any());

        $this->store(ttl: 120)->put('user1', new SessionData('SESSION-1', 3, 'TOKEN-1'));
    }

    public function test_put_honours_a_custom_prefix(): void
    {
        $this->connection->shouldReceive('setex')
            ->once()
            ->with('tenant_a_user1', 900, Mockery::any());

        $this->store(prefix: 'tenant_a_')->put('user1', new SessionData('SESSION-1', 3, 'TOKEN-1'));
    }

    public function test_get_reads_the_prefixed_key_and_rebuilds_the_session(): void
    {
        $this->connection->shouldReceive('get')
            ->once()
            ->with('amadeus_session_user1')
            ->andReturn($this->payload('SESSION-9', 42, 'TOKEN-9'));

        $session = $this->store()->get('user1');

        $this->assertEquals('SESSION-9', $session->sessionId);
        $this->assertEquals(42, $session->sequenceNumber);
        $this->assertEquals('TOKEN-9', $session->securityToken);
    }

    public function test_get_returns_null_for_a_missing_key(): void
    {
        $this->connection->shouldReceive('get')->once()->andReturn(null);

        $this->assertNull($this->store()->get('user1'));
    }

    public function test_get_returns_null_when_phpredis_reports_a_miss_as_false(): void
    {
        // Laravel normalises this to null, but the raw client returns false;
        // the store must not treat it as a payload either way.
        $this->connection->shouldReceive('get')->once()->andReturn(false);

        $this->assertNull($this->store()->get('user1'));
    }

    public function test_get_returns_null_for_invalid_json(): void
    {
        $this->connection->shouldReceive('get')->once()->andReturn('{not json');

        $this->assertNull($this->store()->get('user1'));
    }

    public function test_get_returns_null_for_a_json_scalar(): void
    {
        $this->connection->shouldReceive('get')->once()->andReturn('"just-a-string"');

        $this->assertNull($this->store()->get('user1'));
    }

    public function test_get_returns_null_for_an_incomplete_payload(): void
    {
        // Written by an older deploy, or truncated — must force a fresh
        // session instead of raising out of the store.
        $this->connection->shouldReceive('get')
            ->once()
            ->andReturn(json_encode(['sessionId' => 'SESSION-1']));

        $this->assertNull($this->store()->get('user1'));
    }

    public function test_forget_deletes_the_prefixed_key(): void
    {
        $this->connection->shouldReceive('del')->once()->with('amadeus_session_user1');

        $this->store()->forget('user1');
    }

    public function test_has_is_true_when_a_usable_payload_exists(): void
    {
        $this->connection->shouldReceive('get')->once()->andReturn($this->payload());

        $this->assertTrue($this->store()->has('user1'));
    }

    public function test_has_is_false_when_the_key_is_missing(): void
    {
        $this->connection->shouldReceive('get')->once()->andReturn(null);

        $this->assertFalse($this->store()->has('user1'));
    }

    public function test_has_is_false_for_an_unusable_payload(): void
    {
        // has() and get() have to agree: a true from has() with a null from
        // get() makes HeaderBuilder send a Start session with no credentials.
        $this->connection->shouldReceive('get')->twice()->andReturn('{not json');

        $store = $this->store();

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }
}
