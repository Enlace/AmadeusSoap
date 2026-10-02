<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\HotelSearchParams;
use Aldogtz\AmadeusSoap\Headers\BodyBuilder;
use Aldogtz\AmadeusSoap\Operations\HotelSearch;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterStrategy;
use PHPUnit\Framework\TestCase;

class HotelSearchTest extends TestCase
{
    public function test_it_builds_geo_search(): void
    {
        $params = new HotelSearchParams(
            type: 'multi',
            start: '2026-03-01',
            end: '2026-03-05',
            latitude: '25.67507',
            longitude: '-100.31847',
        );

        $operation = new HotelSearch($params);
        $body = $operation->build();

        $this->assertArrayHasKey('AvailRequestSegments', $body);
        $criterion = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion'];
        $this->assertArrayHasKey('Position', $criterion);
        $this->assertEquals('2567507', $criterion['Position']['_attributes']['Latitude']);
    }

    public function test_it_builds_hotel_code_search(): void
    {
        $params = new HotelSearchParams(
            type: 'single',
            start: '2026-03-01',
            end: '2026-03-05',
            hotelCode: 'MTYABC',
        );

        $operation = new HotelSearch($params);
        $body = $operation->build();

        $criterion = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion'];
        $this->assertArrayHasKey('HotelRef', $criterion);
        $this->assertEquals('MTYABC', $criterion['HotelRef']['_attributes']['HotelCode']);
    }

    public function test_it_includes_rate_plan_codes(): void
    {
        $params = new HotelSearchParams(
            type: 'multi',
            start: '2026-03-01',
            end: '2026-03-05',
            latitude: '25.67507',
            longitude: '-100.31847',
            rateCode: ['RAC', 'ENF'],
        );

        $operation = new HotelSearch($params);
        $body = $operation->build();

        $criterion = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion'];
        $this->assertArrayHasKey('RatePlanCandidates', $criterion);
        $candidates = $criterion['RatePlanCandidates']['RatePlanCandidate'];
        $this->assertCount(2, $candidates);
    }

    public function test_it_returns_correct_operation_name(): void
    {
        $params = new HotelSearchParams();
        $operation = new HotelSearch($params);

        $this->assertEquals('Hotel_MultiSingleAvailability', $operation->getOperationName());
    }

    public function test_it_builds_children_guest_counts(): void
    {
        $params = new HotelSearchParams(
            type: 'multi',
            start: '2026-03-01',
            end: '2026-03-05',
            latitude: '25.67507',
            longitude: '-100.31847',
            guestCount: '2',
            children: [
                ['age' => '5', 'count' => '1'],
            ],
        );

        $operation = new HotelSearch($params);
        $body = $operation->build();

        $guestCounts = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RoomStayCandidates']['RoomStayCandidate']['GuestCounts']['GuestCount'];
        $this->assertCount(2, $guestCounts); // 1 child + 1 adult
    }

    public function test_an_empty_rate_code_omits_the_rate_plan_filter(): void
    {
        // Filtering a single-hotel search by a converted rate plan code gets
        // "RATE NOT LOADED" (Amadeus Error Code 842); [] drops the filter so
        // whatever the property has loaded comes back.
        $params = HotelSearchParams::fromArray([
            'type' => 'single',
            'hotel_code' => 'RTMTYNOV',
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'rate_code' => [],
        ]);

        $body = (new HotelSearch($params))->build();
        $criterion = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion'];

        $this->assertArrayNotHasKey('RatePlanCandidates', $criterion);
    }

    public function test_rate_codes_are_sent_when_given(): void
    {
        $params = HotelSearchParams::fromArray([
            'type' => 'single',
            'hotel_code' => 'RTMTYNOV',
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'rate_code' => ['RAC', 'NRF'],
        ]);

        $body = (new HotelSearch($params))->build();
        $candidates = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RatePlanCandidates']['RatePlanCandidate'];

        $this->assertCount(2, $candidates);
        $this->assertEquals('RAC', $candidates[0]['_attributes']['RatePlanCode']);
        $this->assertEquals('NRF', $candidates[1]['_attributes']['RatePlanCode']);
    }
    public function test_request_options_are_root_attributes(): void
    {
        $params = new HotelSearchParams(
            hotelCityCode: 'MTY',
            searchCacheLevel: 'VeryRecent',
            sortOrder: 'PA',
        );

        $body = (new HotelSearch($params))->build();
        $xml = BodyBuilder::build($body, 'OTA_HotelAvailRQ')->enc_value;

        $this->assertStringContainsString('SearchCacheLevel="VeryRecent"', $xml);
        $this->assertStringContainsString('SortOrder="PA"', $xml);
        $this->assertStringContainsString('MaxResponses="96"', $xml);
        $this->assertStringNotContainsString('<SearchCacheLevel>', $xml);
    }

    public function test_best_only_indicator_follows_the_rate_strategy(): void
    {
        $bestOnly = (new HotelSearch(new HotelSearchParams(hotelCityCode: 'MTY')))->build();
        $allRates = (new HotelSearch(new HotelSearchParams(hotelCityCode: 'MTY', rateStrategy: RateFilterStrategy::ALL_RATES)))->build();

        $criteria = fn (array $body) => $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['_attributes'];

        $this->assertEquals('true', $criteria($bestOnly)['BestOnlyIndicator']);
        $this->assertEquals('false', $criteria($allRates)['BestOnlyIndicator']);
    }

}
