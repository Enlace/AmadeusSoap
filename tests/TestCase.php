<?php

namespace Aldogtz\AmadeusSoap\Tests;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\AmadeusSoapServiceProvider;
use Aldogtz\AmadeusSoap\Client\SoapClientFactory;
use Aldogtz\AmadeusSoap\RateFiltering\TwoPhaseSearchService;
use Aldogtz\AmadeusSoap\Testing\AmadeusFake;
use Aldogtz\AmadeusSoap\Tests\Doubles\ReplaySoapClient;
use Aldogtz\AmadeusSoap\Tests\Doubles\ReplaySoapClientFactory;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use ArrayObject;
use DOMDocument;
use DOMElement;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Facade;
use Orchestra\Testbench\TestCase as Orchestra;
use Throwable;

class TestCase extends Orchestra
{
    protected const SOAP_ENVELOPE_NS = 'http://schemas.xmlsoap.org/soap/envelope/';

    /** Directory holding the Amadeus_All.wsdl fakeAmadeus() loads (default: the shipped resources/testing/wsdl). */
    protected ?string $replayWsdlDirectory = null;

    protected function getPackageProviders($app): array
    {
        return [
            AmadeusSoapServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('amadeus-soap.wsdl_path', __DIR__.'/Fixtures/wsdl');
        $app['config']->set('amadeus-soap.username', 'test_user');
        $app['config']->set('amadeus-soap.password', 'test_pass');
        $app['config']->set('amadeus-soap.office_id', 'TEST01');
        $app['config']->set('amadeus-soap.session.driver', 'array');
        $app['config']->set('amadeus-soap.session.connection', 'default');
        $app['config']->set('amadeus-soap.logging.enabled', false);
        $app['config']->set('amadeus-soap.contact_email', 'test@example.com');
        $app['config']->set('cache.default', 'array');
    }

    /**
     * Replace the HTTP layer with a client answering with sanitized TST
     * responses (tests/Fixtures/tst/responses/{name}.xml), in order.
     *
     * Everything above HTTP is real: the WSDL (resources/testing/wsdl, all operations),
     * headers and envelope serialization.
     */
    protected function fakeAmadeus(string ...$responses): ReplaySoapClient
    {
        $wsdlPath = $this->replayWsdlDirectory ?? AmadeusFake::wsdlDirectory();
        $factory = new ReplaySoapClientFactory;

        config(['amadeus-soap.wsdl_path' => $wsdlPath]);
        $this->app->instance(SoapClientFactory::class, $factory);
        $this->app->forgetInstance(WsdlManager::class);
        $this->app->forgetInstance(AmadeusSoap::class);
        $this->app->forgetInstance(TwoPhaseSearchService::class);
        Facade::clearResolvedInstance('amadeus-soap');

        $client = $factory->client($wsdlPath.'/Amadeus_All.wsdl');

        foreach ($responses as $response) {
            $client->queueResponse($this->tstFixture("responses/{$response}.xml"));
        }

        return $client;
    }

    /**
     * Collect exceptions passed to report() (e.g. through rescue()) instead of
     * handling them. Works on every supported Laravel version; the Exceptions
     * facade only exists from Laravel 11.
     *
     * @return ArrayObject<int, Throwable>
     */
    protected function recordReportedExceptions(): ArrayObject
    {
        $reported = new ArrayObject;
        $handler = $this->app->make(ExceptionHandler::class);

        $this->app->instance(ExceptionHandler::class, new class($handler, $reported) implements ExceptionHandler
        {
            public function __construct(
                private ExceptionHandler $handler,
                private ArrayObject $reported,
            ) {}

            public function report(Throwable $e)
            {
                $this->reported->append($e);
            }

            public function shouldReport(Throwable $e)
            {
                return true;
            }

            public function render($request, Throwable $e)
            {
                return $this->handler->render($request, $e);
            }

            public function renderForConsole($output, Throwable $e)
            {
                $this->handler->renderForConsole($output, $e);
            }
        });

        return $reported;
    }

    /**
     * @param  ArrayObject<int, Throwable>  $reported
     * @param  class-string<Throwable>  $class
     */
    protected function assertReported(ArrayObject $reported, string $class, ?string $message = null): void
    {
        foreach ($reported as $e) {
            if ($e instanceof $class && ($message === null || $e->getMessage() === $message)) {
                $this->addToAssertionCount(1);

                return;
            }
        }

        $this->fail("No {$class} was reported".($message !== null ? " with message '{$message}'" : ''));
    }

    protected function tstFixture(string $path): string
    {
        $file = __DIR__.'/Fixtures/tst/'.$path;

        $this->assertFileExists($file);

        return file_get_contents($file);
    }

    /**
     * Assert a sent request has the same SOAP Body as a request captured
     * from Amadeus TST (tests/Fixtures/tst/requests/{name}.xml), ignoring
     * formatting and attribute order.
     */
    protected function assertSoapBodyMatchesFixture(string $request, string $sentXml): void
    {
        $this->assertSame(
            $this->canonicalBody($this->tstFixture("requests/{$request}.xml")),
            $this->canonicalBody($sentXml),
            "The request body differs from the TST capture '{$request}'.",
        );
    }

    /**
     * Canonical XML of the SOAP Body element (or of the root element when
     * the document is a bare body).
     */
    protected function canonicalBody(string $xml): string
    {
        $dom = new DOMDocument;
        $dom->preserveWhiteSpace = false;
        $dom->loadXML($xml);

        $element = $dom->documentElement;
        $body = $dom->getElementsByTagNameNS(self::SOAP_ENVELOPE_NS, 'Body')->item(0);

        foreach ($body?->childNodes ?? [] as $node) {
            if ($node instanceof DOMElement) {
                $element = $node;
                break;
            }
        }

        return $element->C14N(true);
    }

    /**
     * Value of a header element (by local name) in a sent SOAP request.
     */
    protected function soapHeader(string $sentXml, string $localName, ?string $attribute = null): ?string
    {
        $dom = new DOMDocument;
        $dom->loadXML($sentXml);

        $header = $dom->getElementsByTagNameNS(self::SOAP_ENVELOPE_NS, 'Header')->item(0);

        foreach ($header?->getElementsByTagName('*') ?? [] as $node) {
            if ($node->localName === $localName) {
                return $attribute !== null ? $node->getAttribute($attribute) : trim($node->textContent);
            }
        }

        return null;
    }
}
