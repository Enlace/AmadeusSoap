<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Session;

use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use PHPUnit\Framework\TestCase;

class SessionManagerTest extends TestCase
{
    protected function createManager(?SessionData $initialData = null): SessionManager
    {
        $store = new class($initialData) implements SessionStore
        {
            private array $data = [];

            public function __construct(?SessionData $initialData)
            {
                if ($initialData) {
                    $this->data['test'] = $initialData;
                }
            }

            public function get(string $key): ?SessionData
            {
                return $this->data[$key] ?? null;
            }

            public function put(string $key, SessionData $data): void
            {
                $this->data[$key] = $data;
            }

            public function forget(string $key): void
            {
                unset($this->data[$key]);
            }

            public function has(string $key): bool
            {
                return isset($this->data[$key]);
            }
        };

        return new SessionManager($store, fn () => 'test', ['Hotel_DescriptiveInfo']);
    }

    public function test_it_resolves_session_key(): void
    {
        $manager = $this->createManager();
        $this->assertEquals('test', $manager->getSessionKey());
    }

    public function test_it_allows_key_override(): void
    {
        $manager = $this->createManager();
        $manager->withKey('custom');
        $this->assertEquals('custom', $manager->getSessionKey());
    }

    public function test_using_key_scopes_the_override_to_the_callback(): void
    {
        $manager = $this->createManager();
        $manager->withKey('custom');

        $seen = $manager->usingKey('job:1', fn () => $manager->getSessionKey());

        $this->assertSame('job:1', $seen);
        $this->assertSame('custom', $manager->getSessionKey());
    }

    public function test_using_key_restores_the_key_when_the_callback_throws(): void
    {
        $manager = $this->createManager();

        try {
            $manager->usingKey('job:1', fn () => throw new \RuntimeException('boom'));
        } catch (\RuntimeException) {
        }

        $this->assertSame('test', $manager->getSessionKey());
    }

    public function test_it_detects_no_session(): void
    {
        $manager = $this->createManager();
        $this->assertFalse($manager->hasSession());
    }

    public function test_it_detects_existing_session(): void
    {
        $manager = $this->createManager(new SessionData('sess1', 1, 'tok1'));
        $this->assertTrue($manager->hasSession());
    }

    public function test_it_saves_and_retrieves_session(): void
    {
        $manager = $this->createManager();
        $session = new SessionData('sess2', 1, 'tok2');
        $manager->saveSession($session);

        $retrieved = $manager->getSessionData();
        $this->assertNotNull($retrieved);
        $this->assertEquals('sess2', $retrieved->sessionId);
    }

    public function test_it_clears_session(): void
    {
        $manager = $this->createManager(new SessionData('sess1', 1, 'tok1'));
        $this->assertTrue($manager->hasSession());

        $manager->clearSession();
        $this->assertFalse($manager->hasSession());
    }

    public function test_it_identifies_stateless_operations(): void
    {
        $manager = $this->createManager();
        $this->assertTrue($manager->isStatelessOperation('Hotel_DescriptiveInfo'));
        $this->assertFalse($manager->isStatelessOperation('Hotel_Sell'));
    }
}
