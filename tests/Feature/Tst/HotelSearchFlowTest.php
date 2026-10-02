<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterCriteria;
use Aldogtz\AmadeusSoap\RateFiltering\TwoPhaseSearchService;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use DOMDocument;

/**
 * Hotel search, local rate filtering and the two-phase service against
 * sanitized Amadeus TST traffic.
 */
class HotelSearchFlowTest extends TestCase
{
    protected function stayDates(): array
    {
        return ['start' => '2026-08-30', 'end' => '2026-08-31'];
    }

    /**
     * Attribute value of the first element with the given local name in a sent request.
     */
    protected function attributeOf(string $sentXml, string $localName, string $attribute): ?string
    {
        $dom = new DOMDocument;
        $dom->loadXML($sentXml);

        foreach ($dom->getElementsByTagName('*') as $node) {
            if ($node->localName === $localName) {
                return $node->hasAttribute($attribute) ? $node->getAttribute($attribute) : null;
            }
        }

        return null;
    }

    public function test_multi_city_search_sends_the_request_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('hotel-search-multi');

        $response = $this->app->make(AmadeusSoap::class)
            ->hotelSearch('multi', ['hotel_city_code' => 'MTY', ...$this->stayDates()]);

        $this->assertSoapBodyMatchesFixture('hotel-search-multi', $client->requests[0]['xml']);

        $this->assertTrue($response->ok);
        $this->assertSame(
            ['CPMTYE71', 'HIMTYB27', 'RTMTYNOV', 'YZMTY045', 'HIMTY8D2'],
            array_map(fn ($hotel) => $hotel->hotelCode, $response->hotels),
        );
        $this->assertSame(3687.0, $response->hotels[3]->total->amountAfterTax);
        $this->assertSame('USD', $response->currencyConversions[0]->sourceCurrencyCode);
    }

    public function test_multi_city_search_is_stateless(): void
    {
        $client = $this->fakeAmadeus('hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('multi', ['hotel_city_code' => 'MTY', ...$this->stayDates()]);

        $this->assertNull($this->soapHeader($client->requests[0]['xml'], 'Session'));
        $this->assertNotNull($this->soapHeader($client->requests[0]['xml'], 'UsernameToken'));
    }

    public function test_descriptive_info_sends_the_request_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('hotel-descriptive-info');

        $response = $this->app->make(AmadeusSoap::class)->hotelDescriptiveInfo(['hotelCode' => 'YZMTY045']);

        $this->assertSoapBodyMatchesFixture('hotel-descriptive-info', $client->requests[0]['xml']);
        $this->assertFalse($response->hasErrors);
        $this->assertSame('YZMTY045', $response->hotels[0]->hotelCode);
        $this->assertNotEmpty($response->hotels[0]->imageGroups);
    }

    public function test_all_rates_strategy_disables_best_only(): void
    {
        $client = $this->fakeAmadeus('hotel-search-multi');

        $this->app->make(AmadeusSoap::class)->hotelSearch('multi', [
            'hotel_city_code' => 'MTY',
            'rate_strategy' => 'all_rates',
            ...$this->stayDates(),
        ]);

        $this->assertSame('false', $this->attributeOf($client->requests[0]['xml'], 'HotelSearchCriteria', 'BestOnlyIndicator'));
    }

    public function test_configured_defaults_apply_when_the_call_does_not_set_them(): void
    {
        config([
            'amadeus-soap.search_cache_level.default' => 'VeryRecent',
            'amadeus-soap.rate_filtering.default_strategy' => 'all_rates',
        ]);
        $client = $this->fakeAmadeus('hotel-search-multi', 'hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('multi', ['hotel_city_code' => 'MTY', ...$this->stayDates()]);
        $amadeus->hotelSearch('multi', ['hotel_city_code' => 'MTY', 'search_cache_level' => 'Live', ...$this->stayDates()]);

        $this->assertSame('VeryRecent', $this->attributeOf($client->requests[0]['xml'], 'OTA_HotelAvailRQ', 'SearchCacheLevel'));
        $this->assertSame('false', $this->attributeOf($client->requests[0]['xml'], 'HotelSearchCriteria', 'BestOnlyIndicator'));
        $this->assertSame('Live', $this->attributeOf($client->requests[1]['xml'], 'OTA_HotelAvailRQ', 'SearchCacheLevel'));
    }

    public function test_an_invalid_search_cache_level_fails_before_calling_amadeus(): void
    {
        $client = $this->fakeAmadeus();

        try {
            $this->app->make(AmadeusSoap::class)->hotelSearch('multi', [
                'hotel_city_code' => 'MTY',
                'search_cache_level' => 'SlightlyLessRecent',
            ]);
            $this->fail('Expected InvalidParameterException');
        } catch (InvalidParameterException $e) {
            $this->assertArrayHasKey('search_cache_level', $e->getValidationErrors());
        }

        $this->assertSame([], $client->requests);
    }

    public function test_rate_filter_criteria_narrow_down_the_real_room_stays(): void
    {
        $this->fakeAmadeus('hotel-search-single');

        $response = $this->app->make(AmadeusSoap::class)->hotelSearch('single', [
            'hotel_code' => 'YZMTY045',
            'rate_code' => [],
            'rate_filter_criteria' => [
                'rate_plan_codes' => ['57J'],
                'max_rates' => 3,
            ],
            ...$this->stayDates(),
        ]);

        // TST returned 8 room stays (4 × 57J, 4 × M85); the 3 cheapest 57J remain
        $this->assertSame(
            ['1KN57JU', 'ND257JU', 'STN57JU'],
            array_map(fn ($roomStay) => $roomStay->bookingCode, $response->roomStays),
        );
        $this->assertSame(8, $response->raw->query('//res:RoomStay')->length);
    }

    public function test_refundability_is_unknown_when_the_reply_only_describes_the_penalty(): void
    {
        $this->fakeAmadeus('hotel-search-multi');

        $response = $this->app->make(AmadeusSoap::class)
            ->hotelSearch('multi', ['hotel_city_code' => 'MTY', ...$this->stayDates()]);

        $byPlan = [];
        foreach ($response->roomStays as $roomStay) {
            $byPlan[$roomStay->ratePlanCode] = $roomStay;
        }

        // RAFNOV: 100% penalty "not refundable" in text, no @NonRefundable
        $this->assertNull($byPlan['RAFNOV']->nonRefundable);
        $this->assertFalse($byPlan['57J']->nonRefundable);
    }

    public function test_rate_filter_criteria_require_a_hotel_code(): void
    {
        $client = $this->fakeAmadeus();

        $this->expectException(InvalidParameterException::class);

        try {
            $this->app->make(AmadeusSoap::class)->hotelSearch('multi', [
                'hotel_city_code' => 'MTY',
                'rate_filter_criteria' => ['max_rates' => 1],
                ...$this->stayDates(),
            ]);
        } finally {
            $this->assertSame([], $client->requests);
        }
    }

    public function test_two_phase_quick_search_lists_best_rates_with_the_listing_cache_level(): void
    {
        config(['amadeus-soap.search_cache_level.listing' => 'LessRecent']);
        $client = $this->fakeAmadeus('hotel-search-multi');

        $response = $this->app->make(TwoPhaseSearchService::class)
            ->quickSearch(['hotel_city_code' => 'MTY', 'rate_strategy' => 'all_rates', ...$this->stayDates()]);

        $request = $client->requests[0]['xml'];
        $this->assertSame('LessRecent', $this->attributeOf($request, 'OTA_HotelAvailRQ', 'SearchCacheLevel'));
        $this->assertSame('true', $this->attributeOf($request, 'HotelSearchCriteria', 'BestOnlyIndicator'));
        $this->assertCount(5, $response->hotels);
    }

    public function test_two_phase_detailed_rates_searches_one_hotel_and_filters_locally(): void
    {
        // The second single-hotel search signs the first session out before starting its own
        $client = $this->fakeAmadeus('hotel-search-single', 'signout', 'hotel-search-single');
        $service = $this->app->make(TwoPhaseSearchService::class);
        $params = ['rate_code' => [], ...$this->stayDates()];

        $cheapest = $service->detailedRates('YZMTY045', $params, new RateFilterCriteria(maxRates: 1));
        $fresh = $service->detailedRates('YZMTY045', $params, fresh: true);

        $this->assertSame('YZMTY045', $this->attributeOf($client->requests[0]['xml'], 'HotelRef', 'HotelCode'));
        $this->assertSame('VeryRecent', $this->attributeOf($client->requests[0]['xml'], 'OTA_HotelAvailRQ', 'SearchCacheLevel'));
        $this->assertSame('Live', $this->attributeOf($client->requests[2]['xml'], 'OTA_HotelAvailRQ', 'SearchCacheLevel'));

        $this->assertCount(1, $cheapest->roomStays);
        $this->assertSame(3687.0, $cheapest->roomStays[0]->total->amountAfterTax);
        $this->assertCount(8, $fresh->roomStays);
    }
}
