<?php

namespace Aldogtz\AmadeusSoap\Testing;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Client\SoapClientFactory;
use Aldogtz\AmadeusSoap\RateFiltering\TwoPhaseSearchService;
use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Assert as PHPUnit;

/**
 * Answers Amadeus calls with queued reply XML, in order, without any network
 * access. Installed by Amadeus::fake().
 *
 * Only the HTTP exchange is replaced: params validation, request building,
 * headers, session handling and reply parsing all run for real, against the
 * test WSDL shipped in resources/testing/wsdl. Sessions are kept in memory
 * (array driver) and the response cache is off.
 */
class AmadeusFake
{
    public function __construct(
        protected ReplaySoapClient $client,
    ) {}

    /**
     * Point the package at the replay client and return the fake.
     *
     * @param  string[]  $replies  Reply XML, served in call order
     */
    public static function install(Application $app, array $replies = []): self
    {
        $config = $app['config'];
        $config->set('amadeus-soap.wsdl_path', self::wsdlDirectory());
        $config->set('amadeus-soap.session.driver', 'array');
        $config->set('amadeus-soap.cache.enabled', false);

        // The security headers need credentials, even fake ones
        foreach (['username' => 'fake-user', 'password' => 'fake-password', 'office_id' => 'FAKE00000'] as $key => $value) {
            if (blank($config->get("amadeus-soap.{$key}"))) {
                $config->set("amadeus-soap.{$key}", $value);
            }
        }

        $factory = new ReplaySoapClientFactory;
        $app->instance(SoapClientFactory::class, $factory);

        foreach ([WsdlManager::class, SessionStore::class, SessionManager::class, AmadeusSoap::class, TwoPhaseSearchService::class] as $abstract) {
            $app->forgetInstance($abstract);
        }
        Facade::clearResolvedInstance('amadeus-soap');

        return (new self($factory->client(self::wsdlDirectory().'/Amadeus_All.wsdl')))->push(...$replies);
    }

    /**
     * Directory of the WSDL the fake loads (every supported operation).
     */
    public static function wsdlDirectory(): string
    {
        return dirname(__DIR__, 2).'/resources/testing/wsdl';
    }

    /**
     * Queue reply XML (a SOAP envelope), served in call order.
     */
    public function push(string ...$replies): static
    {
        foreach ($replies as $reply) {
            $this->client->queueResponse($reply);
        }

        return $this;
    }

    /**
     * Queue replies read from files.
     */
    public function pushFile(string ...$paths): static
    {
        foreach ($paths as $path) {
            if (! is_file($path)) {
                throw new \InvalidArgumentException("Amadeus reply fixture not found: {$path}");
            }

            $this->client->queueResponse((string) file_get_contents($path));
        }

        return $this;
    }

    /**
     * Queue a SOAP fault, e.g. pushFault('11|Session|') for an expired session.
     * Amadeus puts its code in the faultstring, as code|Category|text.
     */
    public function pushFault(string $faultString, string $faultCode = 'soap:Client'): static
    {
        $faultString = htmlspecialchars($faultString, ENT_XML1);
        $faultCode = htmlspecialchars($faultCode, ENT_XML1);

        return $this->push(<<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <soap:Fault>
                        <faultcode>{$faultCode}</faultcode>
                        <faultstring>{$faultString}</faultstring>
                    </soap:Fault>
                </soap:Body>
            </soap:Envelope>
            XML);
    }

    /**
     * Every request sent so far, in order.
     *
     * @return array<int, array{operation: string, action: string, location: string, xml: string}>
     */
    public function requests(): array
    {
        return $this->client->requests;
    }

    /**
     * Requests sent for one operation (e.g. Hotel_Sell), in order.
     *
     * @return array<int, array{operation: string, action: string, location: string, xml: string}>
     */
    public function sent(string $operation): array
    {
        return array_values(array_filter(
            $this->client->requests,
            fn (array $request) => $request['operation'] === $operation,
        ));
    }

    public function pendingReplies(): int
    {
        return $this->client->pendingResponses();
    }

    /**
     * @param  (callable(string $xml): bool)|null  $callback  Receives each request's XML
     */
    public function assertSent(string $operation, ?callable $callback = null): static
    {
        $matching = array_filter(
            $this->sent($operation),
            fn (array $request) => $callback === null || $callback($request['xml']),
        );

        PHPUnit::assertNotEmpty(
            $matching,
            $callback === null
                ? "No {$operation} request was sent."
                : "No {$operation} request matching the callback was sent.",
        );

        return $this;
    }

    public function assertNotSent(string $operation): static
    {
        PHPUnit::assertEmpty($this->sent($operation), "An unexpected {$operation} request was sent.");

        return $this;
    }

    public function assertSentCount(int $count): static
    {
        PHPUnit::assertCount($count, $this->client->requests, "Expected {$count} Amadeus requests, ".count($this->client->requests).' were sent.');

        return $this;
    }

    public function assertNothingSent(): static
    {
        return $this->assertSentCount(0);
    }

    /**
     * Every queued reply was used.
     */
    public function assertNoPendingReplies(): static
    {
        PHPUnit::assertSame(0, $this->pendingReplies(), $this->pendingReplies().' queued Amadeus replies were never requested.');

        return $this;
    }
}
