<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Cache;

use Aldogtz\AmadeusSoap\Cache\OperationCache;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use PHPUnit\Framework\TestCase;

class OperationCacheTest extends TestCase
{
    protected Repository $store;

    protected function setUp(): void
    {
        $this->store = new Repository(new ArrayStore);
    }

    protected function makeCache(string $scope = 'TEST01'): OperationCache
    {
        return new OperationCache(
            store: $this->store,
            ttls: ['Hotel_MultiSingleAvailability' => 300, 'Hotel_Sell' => 0],
            scope: $scope,
        );
    }

    public function test_it_stores_and_returns_response_xml(): void
    {
        $cache = $this->makeCache();

        $cache->put('Hotel_MultiSingleAvailability', '<OTA_HotelAvailRQ/>', '<reply/>');

        $this->assertSame('<reply/>', $cache->get('Hotel_MultiSingleAvailability', '<OTA_HotelAvailRQ/>'));
    }

    public function test_it_misses_for_a_different_request_body(): void
    {
        $cache = $this->makeCache();

        $cache->put('Hotel_MultiSingleAvailability', '<OTA_HotelAvailRQ Start="1"/>', '<reply/>');

        $this->assertNull($cache->get('Hotel_MultiSingleAvailability', '<OTA_HotelAvailRQ Start="2"/>'));
    }

    public function test_operations_without_positive_ttl_are_not_cacheable(): void
    {
        $cache = $this->makeCache();

        $cache->put('Hotel_Sell', '<Hotel_Sell/>', '<reply/>');
        $cache->put('PNR_AddMultiElements', '<PNR/>', '<reply/>');

        $this->assertFalse($cache->isCacheable('Hotel_Sell'));
        $this->assertFalse($cache->isCacheable('PNR_AddMultiElements'));
        $this->assertNull($cache->get('Hotel_Sell', '<Hotel_Sell/>'));
        $this->assertNull($cache->get('PNR_AddMultiElements', '<PNR/>'));
    }

    public function test_entries_are_isolated_per_office(): void
    {
        $this->makeCache('OFFICE_A')->put('Hotel_MultiSingleAvailability', '<rq/>', '<reply-a/>');

        $this->assertNull($this->makeCache('OFFICE_B')->get('Hotel_MultiSingleAvailability', '<rq/>'));
        $this->assertSame('<reply-a/>', $this->makeCache('OFFICE_A')->get('Hotel_MultiSingleAvailability', '<rq/>'));
    }

    public function test_flush_invalidates_existing_entries_without_tags(): void
    {
        $cache = $this->makeCache();
        $cache->put('Hotel_MultiSingleAvailability', '<rq/>', '<old/>');

        $cache->flush();

        $this->assertNull($cache->get('Hotel_MultiSingleAvailability', '<rq/>'));

        $cache->put('Hotel_MultiSingleAvailability', '<rq/>', '<new/>');
        $this->assertSame('<new/>', $cache->get('Hotel_MultiSingleAvailability', '<rq/>'));
    }
}
