<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Session;

use Aldogtz\AmadeusSoap\Session\SessionData;
use PHPUnit\Framework\TestCase;

class SessionDataTest extends TestCase
{
    public function test_it_can_be_created(): void
    {
        $data = new SessionData('sess123', 1, 'token456');

        $this->assertEquals('sess123', $data->sessionId);
        $this->assertEquals(1, $data->sequenceNumber);
        $this->assertEquals('token456', $data->securityToken);
    }

    public function test_it_can_increment_sequence(): void
    {
        $data = new SessionData('sess123', 1, 'token456');
        $incremented = $data->incrementSequence();

        $this->assertEquals(2, $incremented->sequenceNumber);
        $this->assertEquals('sess123', $incremented->sessionId);
        $this->assertEquals('token456', $incremented->securityToken);
    }

    public function test_it_can_be_serialized_to_array(): void
    {
        $data = new SessionData('sess123', 1, 'token456');
        $array = $data->toArray();

        $this->assertEquals([
            'sessionId' => 'sess123',
            'sequenceNumber' => 1,
            'securityToken' => 'token456',
        ], $array);
    }

    public function test_it_can_be_created_from_array(): void
    {
        $data = SessionData::fromArray([
            'sessionId' => 'sess123',
            'sequenceNumber' => 3,
            'securityToken' => 'token456',
        ]);

        $this->assertEquals('sess123', $data->sessionId);
        $this->assertEquals(3, $data->sequenceNumber);
        $this->assertEquals('token456', $data->securityToken);
    }

    public function test_try_from_array_accepts_a_complete_payload(): void
    {
        $data = SessionData::tryFromArray([
            'sessionId' => 'sess123',
            'sequenceNumber' => 3,
            'securityToken' => 'token456',
        ]);

        $this->assertEquals('sess123', $data->sessionId);
        $this->assertEquals(3, $data->sequenceNumber);
        $this->assertEquals('token456', $data->securityToken);
    }

    public function test_try_from_array_round_trips_to_array(): void
    {
        $original = new SessionData('sess123', 7, 'token456');

        $this->assertEquals($original, SessionData::tryFromArray($original->toArray()));
    }

    public function test_try_from_array_accepts_a_numeric_string_sequence(): void
    {
        // JSON written by a client that stringifies numbers
        $data = SessionData::tryFromArray([
            'sessionId' => 'sess123',
            'sequenceNumber' => '4',
            'securityToken' => 'token456',
        ]);

        $this->assertSame(4, $data->sequenceNumber);
    }

    public function test_try_from_array_accepts_a_zero_sequence(): void
    {
        $data = SessionData::tryFromArray([
            'sessionId' => 'sess123',
            'sequenceNumber' => 0,
            'securityToken' => 'token456',
        ]);

        $this->assertSame(0, $data->sequenceNumber);
    }

    /**
     * @dataProvider unusablePayloads
     */
    public function test_try_from_array_rejects_unusable_payloads(mixed $payload): void
    {
        $this->assertNull(SessionData::tryFromArray($payload));
    }

    public static function unusablePayloads(): array
    {
        return [
            'null' => [null],
            'string' => ['not-a-session'],
            'int' => [42],
            'empty array' => [[]],
            'missing sequenceNumber' => [['sessionId' => 'sess123', 'securityToken' => 'token456']],
            'missing sessionId' => [['sequenceNumber' => 1, 'securityToken' => 'token456']],
            'missing securityToken' => [['sessionId' => 'sess123', 'sequenceNumber' => 1]],
            'empty sessionId' => [['sessionId' => '', 'sequenceNumber' => 1, 'securityToken' => 'token456']],
            'empty securityToken' => [['sessionId' => 'sess123', 'sequenceNumber' => 1, 'securityToken' => '']],
            'null sessionId' => [['sessionId' => null, 'sequenceNumber' => 1, 'securityToken' => 'token456']],
            'non-numeric sequenceNumber' => [['sessionId' => 'sess123', 'sequenceNumber' => 'abc', 'securityToken' => 'token456']],
            'array sessionId' => [['sessionId' => ['nested'], 'sequenceNumber' => 1, 'securityToken' => 'token456']],
        ];
    }
}
