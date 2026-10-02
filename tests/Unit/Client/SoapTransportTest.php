<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Client;

use Aldogtz\AmadeusSoap\Client\SoapTransport;
use Aldogtz\AmadeusSoap\Exceptions\AuthenticationException;
use Aldogtz\AmadeusSoap\Exceptions\ConnectionException;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Headers\HeaderBuilder;
use Aldogtz\AmadeusSoap\Security\AmaSecurityHeader;
use Aldogtz\AmadeusSoap\Security\WsSecurityHeader;
use Aldogtz\AmadeusSoap\Session\SessionData;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Session\Stores\ArraySessionStore;
use Aldogtz\AmadeusSoap\Tests\Doubles\FakeSoapClient;
use Aldogtz\AmadeusSoap\Tests\Doubles\FakeSoapClientFactory;
use Aldogtz\AmadeusSoap\Tests\Doubles\RecordingRetryHandler;
use Aldogtz\AmadeusSoap\Wsdl\OperationMetadata;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use PHPUnit\Framework\TestCase;
use SoapFault;
use SoapVar;

class SoapTransportTest extends TestCase
{
    protected FakeSoapClient $client;

    protected FakeSoapClientFactory $factory;

    protected ArraySessionStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = new FakeSoapClient;
        $this->factory = new FakeSoapClientFactory($this->client);
        $this->store = new ArraySessionStore;
    }

    protected function transport(?RecordingRetryHandler $retryHandler = null): SoapTransport
    {
        $sessionManager = new SessionManager(
            store: $this->store,
            keyResolver: fn () => 'test-key',
            statelessOperations: ['Hotel_DescriptiveInfo'],
        );

        return new SoapTransport(
            factory: $this->factory,
            headerBuilder: new HeaderBuilder(
                security: new WsSecurityHeader('test_user', 'test_pass'),
                amaSecurity: new AmaSecurityHeader('TEST01'),
                sessionManager: $sessionManager,
            ),
            wsdlManager: new WsdlManager(dirname(__DIR__, 2).'/Fixtures/wsdl'),
            retryHandler: $retryHandler,
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

    protected function body(): SoapVar
    {
        return new SoapVar('<Hotel_MultiSingleAvailability/>', XSD_ANYXML);
    }

    protected function call(
        bool $isStateful = true,
        bool $hasSessionBody = false,
        ?RecordingRetryHandler $retryHandler = null,
    ): string {
        return $this->transport($retryHandler)->call(
            'Hotel_MultiSingleAvailability',
            $this->body(),
            $this->metadata(),
            $isStateful,
            $hasSessionBody,
        );
    }

    public function test_it_returns_the_raw_response_xml(): void
    {
        $this->client->responseXml = '<soap:Envelope><soap:Body><Reply>ok</Reply></soap:Body></soap:Envelope>';

        $this->assertEquals($this->client->responseXml, $this->call());
    }

    public function test_it_invokes_the_operation_by_name_with_the_body(): void
    {
        $this->call();

        $this->assertEquals(['Hotel_MultiSingleAvailability'], $this->client->calledOperations);
        $this->assertInstanceOf(SoapVar::class, $this->client->capturedArguments[0][0]);
    }

    public function test_it_builds_the_client_from_the_wsdl_path_in_the_metadata(): void
    {
        $this->call();

        $this->assertEquals(['/tmp/hotel.wsdl'], $this->factory->requestedPaths);
    }

    public function test_it_pushes_the_built_headers_onto_the_client_before_calling(): void
    {
        $this->call(isStateful: true, hasSessionBody: false);

        $this->assertEquals(
            ['Session', 'MessageID', 'Action', 'To', 'Security', 'AMA_SecurityHostedUser'],
            $this->client->headerNames(),
        );
        $this->assertEquals(
            'http://webservices.amadeus.com/HOTMSAR_11_0',
            $this->client->header('Action')->data,
        );
    }

    public function test_an_in_series_call_sends_the_stored_session_and_no_credentials(): void
    {
        $this->store->put('test-key', new SessionData('SESSION-ID-1', 7, 'TOKEN-ABC'));

        $this->call(isStateful: true, hasSessionBody: true);

        $this->assertEquals(['Session', 'MessageID', 'Action', 'To'], $this->client->headerNames());
        $this->assertStringContainsString(
            '<ses:SequenceNumber>8</ses:SequenceNumber>',
            $this->client->header('Session')->data->enc_value,
        );
    }

    public function test_a_stateless_call_sends_no_session_header(): void
    {
        $this->call(isStateful: false, hasSessionBody: false);

        $this->assertNotContains('Session', $this->client->headerNames());
    }

    public function test_an_empty_response_becomes_an_empty_string(): void
    {
        $this->client->responseXml = null;

        $this->assertSame('', $this->call());
    }

    public function test_a_business_fault_becomes_a_soap_fault_exception_carrying_the_exchange(): void
    {
        $fault = new SoapFault('Client', 'Invalid hotel code');
        $this->client->faultToThrow = $fault;

        try {
            $this->call();
            $this->fail('Expected SoapFaultException.');
        } catch (SoapFaultException $e) {
            $this->assertEquals('Invalid hotel code', $e->getMessage());
            $this->assertSame($fault, $e->getSoapFault());
            $this->assertEquals($this->client->requestXml, $e->getLastRequest());
            $this->assertEquals($this->client->responseXml, $e->getLastResponse());
        }
    }

    public function test_an_authentication_fault_becomes_an_authentication_exception(): void
    {
        $this->client->faultToThrow = new SoapFault('Client', 'Invalid credentials supplied');

        try {
            $this->call();
            $this->fail('Expected AuthenticationException.');
        } catch (AuthenticationException $e) {
            $this->assertStringContainsString('Amadeus authentication failed', $e->getMessage());
            $this->assertEquals($this->client->requestXml, $e->getLastRequest());
        }
    }

    public function test_an_amadeus_security_fault_code_becomes_an_authentication_exception(): void
    {
        $this->client->faultToThrow = new SoapFault('11|Session', 'Session error');

        $this->expectException(AuthenticationException::class);

        $this->call();
    }

    public function test_an_http_fault_code_becomes_a_connection_exception(): void
    {
        $this->client->faultToThrow = new SoapFault('HTTP', 'Error Fetching http headers');

        try {
            $this->call();
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException $e) {
            $this->assertStringContainsString('Hotel_MultiSingleAvailability', $e->getMessage());
            $this->assertEquals($this->client->requestXml, $e->getLastRequest());
            $this->assertEquals($this->client->responseXml, $e->getLastResponse());
        }
    }

    public function test_a_timeout_is_reported_as_a_timeout(): void
    {
        $this->client->faultToThrow = new SoapFault('HTTP', 'Operation timed out');

        try {
            $this->call();
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException $e) {
            $this->assertStringContainsString('Connection timeout', $e->getMessage());
        }
    }

    public function test_an_ssl_failure_is_reported_as_an_ssl_error(): void
    {
        $this->client->faultToThrow = new SoapFault('HTTP', 'SSL certificate problem: self signed certificate');

        try {
            $this->call();
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException $e) {
            $this->assertStringContainsString('SSL/TLS error', $e->getMessage());
        }
    }

    public function test_a_dns_failure_is_reported_as_a_generic_connection_failure(): void
    {
        $this->client->faultToThrow = new SoapFault('Client', 'php_network_getaddresses: Name or service not known');

        try {
            $this->call();
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException $e) {
            $this->assertStringContainsString('Connection failed', $e->getMessage());
        }
    }

    public function test_connection_errors_are_retried_with_exponential_backoff(): void
    {
        $retryHandler = new RecordingRetryHandler(enabled: true, maxAttempts: 3, baseDelayMs: 100, multiplier: 2.0);
        $this->client->faultToThrow = new SoapFault('HTTP', 'Operation timed out');

        try {
            $this->call(retryHandler: $retryHandler);
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException) {
            $this->assertEquals(3, $this->client->callCount);
            $this->assertEquals([100, 200], $retryHandler->delays);
        }
    }

    public function test_a_call_that_recovers_on_retry_returns_the_response(): void
    {
        $retryHandler = new RecordingRetryHandler(enabled: true, maxAttempts: 3, baseDelayMs: 100);
        $this->client->faultSequence = [new SoapFault('HTTP', 'Operation timed out')];

        $this->assertEquals($this->client->responseXml, $this->call(retryHandler: $retryHandler));
        $this->assertEquals(2, $this->client->callCount);
    }

    public function test_business_faults_are_never_retried(): void
    {
        $retryHandler = new RecordingRetryHandler(enabled: true, maxAttempts: 3, baseDelayMs: 100);
        $this->client->faultToThrow = new SoapFault('Client', 'Invalid hotel code');

        try {
            $this->call(retryHandler: $retryHandler);
            $this->fail('Expected SoapFaultException.');
        } catch (SoapFaultException) {
            $this->assertEquals(1, $this->client->callCount);
            $this->assertEmpty($retryHandler->delays);
        }
    }

    public function test_a_disabled_retry_handler_calls_once(): void
    {
        $retryHandler = new RecordingRetryHandler(enabled: false, maxAttempts: 3);
        $this->client->faultToThrow = new SoapFault('HTTP', 'Operation timed out');

        try {
            $this->call(retryHandler: $retryHandler);
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException) {
            $this->assertEquals(1, $this->client->callCount);
        }
    }

    public function test_the_last_exchange_is_null_before_any_call(): void
    {
        $transport = $this->transport();

        $this->assertNull($transport->getLastRequest());
        $this->assertNull($transport->getLastResponse());
        $this->assertNull($transport->getLastRequestFormatted());
        $this->assertNull($transport->getLastResponseFormatted());
    }

    public function test_the_last_exchange_is_exposed_after_a_call(): void
    {
        $transport = $this->transport();
        $transport->call('Hotel_MultiSingleAvailability', $this->body(), $this->metadata(), true, false);

        $this->assertEquals($this->client->requestXml, $transport->getLastRequest());
        $this->assertEquals($this->client->responseXml, $transport->getLastResponse());
    }

    public function test_the_formatted_exchange_is_pretty_printed(): void
    {
        $this->client->responseXml = '<a><b>c</b></a>';

        $transport = $this->transport();
        $transport->call('Hotel_MultiSingleAvailability', $this->body(), $this->metadata(), true, false);

        $formatted = $transport->getLastResponseFormatted();

        $this->assertStringContainsString("<a>\n  <b>c</b>\n</a>", $formatted);
        // the raw accessor stays untouched
        $this->assertEquals('<a><b>c</b></a>', $transport->getLastResponse());
    }

    public function test_an_empty_last_request_reads_as_null(): void
    {
        $this->client->requestXml = '';

        $transport = $this->transport();
        $transport->call('Hotel_MultiSingleAvailability', $this->body(), $this->metadata(), true, false);

        $this->assertNull($transport->getLastRequest());
    }
}
