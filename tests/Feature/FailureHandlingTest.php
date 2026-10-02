<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Events\OperationFailed;
use Aldogtz\AmadeusSoap\Exceptions\AuthenticationException;
use Aldogtz\AmadeusSoap\Exceptions\XmlParseException;
use Aldogtz\AmadeusSoap\Tests\Doubles\FailingCacheStore;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use RuntimeException;

class FailureHandlingTest extends TestCase
{
    /**
     * Response cache and monitoring enabled on a store that always fails.
     */
    protected function useFailingStores($app): void
    {
        $app['cache']->extend('failing', fn ($app) => $app['cache']->repository(new FailingCacheStore));
        $app['config']->set('cache.stores.failing', ['driver' => 'failing']);

        $app['config']->set('amadeus-soap.cache.enabled', true);
        $app['config']->set('amadeus-soap.cache.store', 'failing');
        $app['config']->set('amadeus-soap.monitoring.enabled', true);
        $app['config']->set('amadeus-soap.monitoring.store', 'failing');
    }

    protected function cityParams(): array
    {
        return ['hotel_city_code' => 'MTY', 'start' => '2026-08-30', 'end' => '2026-08-31'];
    }

    #[DefineEnvironment('useFailingStores')]
    public function test_a_cache_outage_turns_into_misses(): void
    {
        $reported = $this->recordReportedExceptions();
        $client = $this->fakeAmadeus('hotel-search-multi', 'hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $first = $amadeus->hotelSearch('multi', $this->cityParams());
        $second = $amadeus->hotelSearch('multi', $this->cityParams());

        $this->assertTrue($first->ok);
        $this->assertTrue($second->ok);
        $this->assertCount(2, $client->requests);
        $this->assertReported($reported, RuntimeException::class, 'Cache store unavailable');
    }

    #[DefineEnvironment('useFailingStores')]
    public function test_a_monitoring_outage_does_not_fail_a_sell_amadeus_completed(): void
    {
        $reported = $this->recordReportedExceptions();
        $this->fakeAmadeus('hotel-search-single', 'hotel-sell');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', ['hotel_code' => 'HIMTY8D2', 'rate_code' => [], 'start' => '2026-08-30', 'end' => '2026-08-31']);
        $sell = $amadeus->hotelSell([
            'travelAgentRef' => '1',
            'chainCode' => 'HI',
            'cityCode' => 'MTY',
            'hotelCode' => 'HIMTY8D2',
            'bookingCode' => 'STN57JU',
            'passengerReference' => ['type' => 'BHO', 'value' => '2'],
            'paymentType' => '1',
            'vendorCode' => 'AX',
            'cardNumber' => '378282246310005',
            'securityId' => '0000',
            'expiryDate' => '1230',
            'surname' => 'TRAVELER',
            'firstName' => 'TEST',
        ]);

        // The room was sold: the caller must get the confirmation, not an exception
        $this->assertFalse($sell->hasErrors);
        $this->assertSame('10000001', $sell->confirmationNumber);
        $this->assertReported($reported, RuntimeException::class, 'Cache store unavailable');
    }

    public function test_unparseable_replies_dispatch_operation_failed(): void
    {
        Event::fake([OperationFailed::class]);
        $client = $this->fakeAmadeus('hotel-search-multi');
        // SoapClient accepted the reply, but nothing usable was captured (trace off)
        $client->lastResponseOverride = '';

        try {
            $this->app->make(AmadeusSoap::class)->hotelSearch('multi', $this->cityParams());
            $this->fail('Expected XmlParseException');
        } catch (XmlParseException) {
            // expected
        }

        Event::assertDispatched(
            OperationFailed::class,
            fn (OperationFailed $event) => $event->exception instanceof XmlParseException
                && $event->operation === 'Hotel_MultiSingleAvailability',
        );
    }

    public function test_authentication_failures_dispatch_operation_failed(): void
    {
        Event::fake([OperationFailed::class]);
        $client = $this->fakeAmadeus();
        $client->queueResponse(<<<'XML'
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <soap:Fault>
                        <faultcode>soap:Client</faultcode>
                        <faultstring>Security: Authentication failed</faultstring>
                    </soap:Fault>
                </soap:Body>
            </soap:Envelope>
            XML);

        try {
            $this->app->make(AmadeusSoap::class)->hotelSearch('multi', $this->cityParams());
            $this->fail('Expected AuthenticationException');
        } catch (AuthenticationException) {
            // expected
        }

        Event::assertDispatched(
            OperationFailed::class,
            fn (OperationFailed $event) => $event->exception instanceof AuthenticationException
                && $event->operation === 'Hotel_MultiSingleAvailability',
        );
    }
}
