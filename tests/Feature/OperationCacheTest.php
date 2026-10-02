<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Cache\OperationCache;
use Aldogtz\AmadeusSoap\Events\OperationCompleted;
use Aldogtz\AmadeusSoap\Testing\AmadeusFake;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Facades\Event;

class OperationCacheTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('amadeus-soap.cache.enabled', true);
    }

    protected function cityParams(array $overrides = []): array
    {
        return array_merge(['hotel_city_code' => 'MTY', 'start' => '2026-08-30', 'end' => '2026-08-31'], $overrides);
    }

    public function test_a_repeated_stateless_search_is_served_from_cache(): void
    {
        $client = $this->fakeAmadeus('hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $first = $amadeus->hotelSearch('multi', $this->cityParams());
        $second = $amadeus->hotelSearch('multi', $this->cityParams());

        $this->assertCount(1, $client->requests);
        $this->assertSame($first->raw->getRawXml(), $second->raw->getRawXml());
        $this->assertCount(5, $second->hotels);
    }

    public function test_cache_hits_do_not_dispatch_operation_events(): void
    {
        $this->fakeAmadeus('hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);
        $amadeus->hotelSearch('multi', $this->cityParams());

        Event::fake([OperationCompleted::class]);
        $amadeus->hotelSearch('multi', $this->cityParams());

        Event::assertNotDispatched(OperationCompleted::class);
    }

    public function test_different_searches_are_cached_separately(): void
    {
        $client = $this->fakeAmadeus('hotel-search-multi', 'hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('multi', $this->cityParams());
        $amadeus->hotelSearch('multi', $this->cityParams(['end' => '2026-09-01']));

        $this->assertCount(2, $client->requests);
    }

    public function test_stateful_searches_are_never_cached(): void
    {
        // Single-hotel search opens the session that pricing and sell continue
        $client = $this->fakeAmadeus('hotel-search-single', 'signout', 'hotel-search-single');
        $amadeus = $this->app->make(AmadeusSoap::class);
        $params = ['hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => []];

        $amadeus->hotelSearch('single', $params);
        $amadeus->hotelSearch('single', $params);

        // search, sign-out of the replaced session, search again
        $this->assertCount(3, $client->requests);
        $this->assertStringContainsString('Hotel_MultiSingleAvailability', $client->requests[2]['action']);
        $this->assertTrue($amadeus->session()->hasSession());
    }

    public function test_descriptive_info_is_cached(): void
    {
        $client = $this->fakeAmadeus('hotel-descriptive-info');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelDescriptiveInfo(['hotelCode' => 'YZMTY045']);
        $cached = $amadeus->hotelDescriptiveInfo(['hotelCode' => 'YZMTY045']);

        $this->assertCount(1, $client->requests);
        $this->assertSame('YZMTY045', $cached->hotels[0]->hotelCode);
    }

    public function test_responses_with_errors_are_not_cached(): void
    {
        $error = <<<'XML'
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                        <Errors><Error Code="424" Type="12">NO AVAILABILITY</Error></Errors>
                    </OTA_HotelAvailRS>
                </soap:Body>
            </soap:Envelope>
            XML;
        $client = $this->fakeAmadeus();
        $client->queueResponse($error)->queueResponse($this->tstFixture('responses/hotel-search-multi.xml'));
        $amadeus = $this->app->make(AmadeusSoap::class);

        $failed = $amadeus->hotelSearch('multi', $this->cityParams());
        $retried = $amadeus->hotelSearch('multi', $this->cityParams());

        $this->assertTrue($failed->hasErrors);
        $this->assertTrue($retried->ok);
        $this->assertCount(2, $client->requests);
    }

    public function test_flush_invalidates_cached_responses(): void
    {
        $client = $this->fakeAmadeus('hotel-search-multi', 'hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('multi', $this->cityParams());
        $this->app->make(OperationCache::class)->flush();
        $amadeus->hotelSearch('multi', $this->cityParams());

        $this->assertCount(2, $client->requests);
    }

    public function test_a_cache_hit_leaves_no_last_exchange_behind(): void
    {
        $this->fakeAmadeus('hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('multi', $this->cityParams());
        $this->assertNotNull($amadeus->getLastResponse());

        $amadeus->hotelSearch('multi', $this->cityParams());
        $this->assertNull($amadeus->getLastRequest());
        $this->assertNull($amadeus->getLastResponse());
    }

    public function test_entries_are_not_shared_across_amadeus_endpoints(): void
    {
        // Same office ID and WSDL directory path, but the WSDL behind it points
        // at another environment (e.g. TST and production sharing a Redis)
        $dir = sys_get_temp_dir().'/amadeus-wsdl-'.bin2hex(random_bytes(4));
        $wsdl = file_get_contents(AmadeusFake::wsdlDirectory().'/Amadeus_All.wsdl');
        $production = str_replace('nodeD2.test.webservices.amadeus.com/1ASIWTEST', 'production.webservices.amadeus.test/1ASIWPROD', $wsdl, $replaced);
        $this->assertSame(1, $replaced);

        mkdir($dir);
        $this->replayWsdlDirectory = $dir;

        try {
            file_put_contents("{$dir}/Amadeus_All.wsdl", $wsdl);
            $this->fakeAmadeus('hotel-search-multi');
            $this->app->make(AmadeusSoap::class)->hotelSearch('multi', $this->cityParams());

            file_put_contents("{$dir}/Amadeus_All.wsdl", $production);
            $client = $this->fakeAmadeus('hotel-search-multi');
            $this->app->make(AmadeusSoap::class)->hotelSearch('multi', $this->cityParams());

            $this->assertCount(1, $client->requests);
            $this->assertStringContainsString('1ASIWPROD', $client->requests[0]['location']);
        } finally {
            @unlink("{$dir}/Amadeus_All.wsdl");
            @rmdir($dir);
        }
    }

    public function test_nothing_is_cached_when_the_cache_is_disabled(): void
    {
        config(['amadeus-soap.cache.enabled' => false]);
        $client = $this->fakeAmadeus('hotel-search-multi', 'hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('multi', $this->cityParams());
        $amadeus->hotelSearch('multi', $this->cityParams());

        $this->assertCount(2, $client->requests);
    }
}
