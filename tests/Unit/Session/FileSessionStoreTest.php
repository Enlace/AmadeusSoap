<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Session;

use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\Stores\FileSessionStore;
use PHPUnit\Framework\TestCase;

class FileSessionStoreTest extends TestCase
{
    protected string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir().'/amadeus_test_'.uniqid();
    }

    protected function tearDown(): void
    {
        // Clean up temp files
        if (is_dir($this->tempDir)) {
            $files = glob($this->tempDir.'/*');
            foreach ($files as $file) {
                unlink($file);
            }
            rmdir($this->tempDir);
        }

        parent::tearDown();
    }

    public function test_it_creates_directory_if_not_exists(): void
    {
        $this->assertDirectoryDoesNotExist($this->tempDir);

        new FileSessionStore($this->tempDir);

        $this->assertDirectoryExists($this->tempDir);
    }

    public function test_it_stores_and_retrieves_session(): void
    {
        $store = new FileSessionStore($this->tempDir);
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
        $store = new FileSessionStore($this->tempDir);

        $this->assertFalse($store->has('nonexistent'));
        $this->assertNull($store->get('nonexistent'));
    }

    public function test_it_forgets_session(): void
    {
        $store = new FileSessionStore($this->tempDir);
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));

        $this->assertTrue($store->has('user1'));

        $store->forget('user1');

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }

    public function test_it_expires_sessions_by_ttl(): void
    {
        $store = new FileSessionStore($this->tempDir, 'amadeus_session_', 1);
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));

        $this->assertTrue($store->has('user1'));

        // Wait for TTL to expire
        sleep(2);

        $this->assertFalse($store->has('user1'));
        $this->assertNull($store->get('user1'));
    }

    public function test_it_sanitizes_key_for_filesystem(): void
    {
        $store = new FileSessionStore($this->tempDir);
        $session = new SessionData('sess1', 1, 'tok1');

        // Key with special characters
        $store->put('user/1:test@email.com', $session);

        $this->assertTrue($store->has('user/1:test@email.com'));
        $retrieved = $store->get('user/1:test@email.com');
        $this->assertEquals('sess1', $retrieved->sessionId);
    }

    public function test_a_corrupt_file_reads_as_no_session(): void
    {
        $store = new FileSessionStore($this->tempDir);
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));

        file_put_contents($this->tempDir.'/amadeus_session_user1.json', 'not json at all');

        $this->assertNull($store->get('user1'));
        $this->assertFalse($store->has('user1'));
    }

    public function test_an_incomplete_file_payload_reads_as_no_session(): void
    {
        $store = new FileSessionStore($this->tempDir);
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));

        file_put_contents(
            $this->tempDir.'/amadeus_session_user1.json',
            json_encode(['sessionId' => 'sess1']),
        );

        $this->assertNull($store->get('user1'));
        $this->assertFalse($store->has('user1'));
    }

    public function test_it_overwrites_existing_session(): void
    {
        $store = new FileSessionStore($this->tempDir);
        $store->put('user1', new SessionData('sess1', 1, 'tok1'));
        $store->put('user1', new SessionData('sess2', 5, 'tok2'));

        $retrieved = $store->get('user1');
        $this->assertEquals('sess2', $retrieved->sessionId);
        $this->assertEquals(5, $retrieved->sequenceNumber);
    }
}
