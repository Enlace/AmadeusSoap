<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Headers;

use Aldogtz\AmadeusSoap\Headers\HeaderBuilder;
use Aldogtz\AmadeusSoap\Security\AmaSecurityHeader;
use Aldogtz\AmadeusSoap\Security\WsSecurityHeader;
use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Session\Stores\ArraySessionStore;
use Aldogtz\AmadeusSoap\Wsdl\OperationMetadata;
use PHPUnit\Framework\TestCase;
use SoapHeader;

class HeaderBuilderTest extends TestCase
{
    protected ArraySessionStore $store;

    protected SessionManager $sessionManager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->store = new ArraySessionStore;
        $this->sessionManager = new SessionManager(
            store: $this->store,
            keyResolver: fn () => 'test-key',
            statelessOperations: ['Hotel_DescriptiveInfo'],
        );
    }

    protected function builder(): HeaderBuilder
    {
        return new HeaderBuilder(
            security: new WsSecurityHeader('test_user', 'test_pass'),
            amaSecurity: new AmaSecurityHeader('TEST01'),
            sessionManager: $this->sessionManager,
        );
    }

    protected function metadata(): OperationMetadata
    {
        return new OperationMetadata(
            name: 'Hotel_MultiSingleAvailability',
            wsdlId: 'abc123',
            wsdlPath: '/tmp/hotel.wsdl',
            version: '11.0',
            inputMessageName: 'Hotel_MultiSingleAvailability_11_0',
            outputMessageName: 'Hotel_MultiSingleAvailabilityReply_11_0',
            soapAction: 'http://webservices.amadeus.com/HOTMSAR_11_0',
            serviceEndpoint: 'https://nodeD1.test.webservices.amadeus.com/1ASIWTEST',
            rootElement: 'Hotel_MultiSingleAvailability',
            responseRootElement: 'Hotel_MultiSingleAvailabilityReply',
            responseNamespace: 'http://xml.amadeus.com/HOTMSAR_11_0',
        );
    }

    /** @param SoapHeader[] $headers */
    protected function names(array $headers): array
    {
        return array_map(fn (SoapHeader $header) => $header->name, $headers);
    }

    /** @param SoapHeader[] $headers */
    protected function find(array $headers, string $name): ?SoapHeader
    {
        foreach ($headers as $header) {
            if ($header->name === $name) {
                return $header;
            }
        }

        return null;
    }

    public function test_addressing_headers_carry_the_operation_soap_action_and_endpoint(): void
    {
        $headers = $this->builder()->build($this->metadata(), isStateful: false, hasSessionBody: false);

        $this->assertEquals(
            'http://webservices.amadeus.com/HOTMSAR_11_0',
            $this->find($headers, 'Action')->data,
        );
        $this->assertEquals(
            'https://nodeD1.test.webservices.amadeus.com/1ASIWTEST',
            $this->find($headers, 'To')->data,
        );
        $this->assertEquals(
            'http://www.w3.org/2005/08/addressing',
            $this->find($headers, 'Action')->namespace,
        );
    }

    public function test_each_build_gets_a_fresh_message_id(): void
    {
        $first = $this->find($this->builder()->build($this->metadata(), false, false), 'MessageID');
        $second = $this->find($this->builder()->build($this->metadata(), false, false), 'MessageID');

        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            $first->data,
        );
        $this->assertNotEquals($first->data, $second->data);
    }

    public function test_a_stateless_operation_sends_credentials_and_no_session_header(): void
    {
        $headers = $this->builder()->build($this->metadata(), isStateful: false, hasSessionBody: false);

        $this->assertEquals(
            ['MessageID', 'Action', 'To', 'Security', 'AMA_SecurityHostedUser'],
            $this->names($headers),
        );
    }

    public function test_a_stateful_operation_without_a_stored_session_starts_one(): void
    {
        $headers = $this->builder()->build($this->metadata(), isStateful: true, hasSessionBody: false);

        $this->assertEquals(
            ['Session', 'MessageID', 'Action', 'To', 'Security', 'AMA_SecurityHostedUser'],
            $this->names($headers),
        );

        $session = $this->find($headers, 'Session');
        $this->assertStringContainsString('TransactionStatusCode="Start"', $session->data->enc_value);
        $this->assertEquals('http://xml.amadeus.com/2010/06/Session_v3', $session->namespace);
    }

    public function test_an_in_series_call_reuses_the_session_and_drops_the_credentials(): void
    {
        $this->store->put('test-key', new SessionData('SESSION-ID-1', 3, 'TOKEN-ABC'));

        $headers = $this->builder()->build($this->metadata(), isStateful: true, hasSessionBody: true);

        // WS-Security and AMA headers are only sent when opening a session
        $this->assertEquals(['Session', 'MessageID', 'Action', 'To'], $this->names($headers));

        $xml = $this->find($headers, 'Session')->data->enc_value;
        $this->assertStringContainsString('TransactionStatusCode="InSeries"', $xml);
        $this->assertStringContainsString('<ses:SessionId>SESSION-ID-1</ses:SessionId>', $xml);
        $this->assertStringContainsString('<ses:SecurityToken>TOKEN-ABC</ses:SecurityToken>', $xml);
    }

    public function test_the_sequence_number_is_incremented_for_the_outgoing_call(): void
    {
        $this->store->put('test-key', new SessionData('SESSION-ID-1', 3, 'TOKEN-ABC'));

        $xml = $this->find(
            $this->builder()->build($this->metadata(), true, true),
            'Session',
        )->data->enc_value;

        $this->assertStringContainsString('<ses:SequenceNumber>4</ses:SequenceNumber>', $xml);
    }

    public function test_building_headers_does_not_persist_the_incremented_sequence(): void
    {
        // The stored session is only advanced when a response comes back, so
        // two builds off the same stored session produce the same number.
        $this->store->put('test-key', new SessionData('SESSION-ID-1', 3, 'TOKEN-ABC'));

        $this->builder()->build($this->metadata(), true, true);

        $this->assertEquals(3, $this->store->get('test-key')->sequenceNumber);
    }

    public function test_a_stateful_operation_starts_a_new_session_when_the_body_carries_no_session(): void
    {
        // Hotel_MultiSingleAvailability and PNR_Retrieve pass hasSessionBody=false
        // even with a stored session — they must re-send credentials.
        $this->store->put('test-key', new SessionData('SESSION-ID-1', 3, 'TOKEN-ABC'));

        $headers = $this->builder()->build($this->metadata(), isStateful: true, hasSessionBody: false);

        $this->assertEquals(
            ['Session', 'MessageID', 'Action', 'To', 'Security', 'AMA_SecurityHostedUser'],
            $this->names($headers),
        );
        $this->assertStringContainsString(
            'TransactionStatusCode="Start"',
            $this->find($headers, 'Session')->data->enc_value,
        );
    }
}
