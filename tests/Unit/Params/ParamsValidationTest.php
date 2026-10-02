<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Params;

use Aldogtz\AmadeusSoap\Cache\SearchCacheLevel;
use Aldogtz\AmadeusSoap\Data\HotelCompleteReservationDetailsParams;
use Aldogtz\AmadeusSoap\Data\HotelDescriptiveInfoParams;
use Aldogtz\AmadeusSoap\Data\HotelPricingParams;
use Aldogtz\AmadeusSoap\Data\HotelSearchParams;
use Aldogtz\AmadeusSoap\Data\HotelSellParams;
use Aldogtz\AmadeusSoap\Data\PnrCancelParams;
use Aldogtz\AmadeusSoap\Data\PnrRetrieveParams;
use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterCriteria;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterStrategy;
use PHPUnit\Framework\TestCase;

class ParamsValidationTest extends TestCase
{
    // --- HotelSearchParams ---

    public function test_hotel_search_requires_search_criterion(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('hotel_city_code');

        HotelSearchParams::fromArray([]);
    }

    public function test_hotel_search_passes_with_city_code(): void
    {
        $params = HotelSearchParams::fromArray(['hotel_city_code' => 'MTY']);

        $this->assertEquals('MTY', $params->hotelCityCode);
    }

    public function test_hotel_search_passes_with_hotel_code(): void
    {
        $params = HotelSearchParams::fromArray(['hotel_code' => 'MTYHLT']);

        $this->assertEquals('MTYHLT', $params->hotelCode);
    }

    public function test_hotel_search_passes_with_coordinates(): void
    {
        $params = HotelSearchParams::fromArray([
            'latitude' => '25.6866',
            'longitude' => '-100.3161',
        ]);

        $this->assertEquals('25.6866', $params->latitude);
    }

    public function test_hotel_search_passes_with_hotel_name(): void
    {
        $params = HotelSearchParams::fromArray(['hotel_name' => 'Hilton']);

        $this->assertEquals('Hilton', $params->hotelName);
    }

    public function test_hotel_search_validates_date_format(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('YYYY-MM-DD');

        HotelSearchParams::fromArray([
            'hotel_city_code' => 'MTY',
            'start' => 'invalid-date',
        ]);
    }

    public function test_hotel_search_defaults_to_live_best_only_without_filter(): void
    {
        $params = HotelSearchParams::fromArray(['hotel_city_code' => 'MTY']);

        $this->assertEquals('Live', $params->searchCacheLevel);
        $this->assertSame(RateFilterStrategy::BEST_ONLY, $params->rateStrategy);
        $this->assertNull($params->rateFilterCriteria);
    }

    public function test_hotel_search_accepts_cache_level_and_strategy_as_value_or_enum(): void
    {
        $fromValues = HotelSearchParams::fromArray([
            'hotel_city_code' => 'MTY',
            'search_cache_level' => 'VeryRecent',
            'rate_strategy' => 'all_rates',
        ]);
        $fromEnums = HotelSearchParams::fromArray([
            'hotel_city_code' => 'MTY',
            'search_cache_level' => SearchCacheLevel::LESS_RECENT,
            'rate_strategy' => RateFilterStrategy::ALL_RATES,
        ]);

        $this->assertEquals('VeryRecent', $fromValues->searchCacheLevel);
        $this->assertSame(RateFilterStrategy::ALL_RATES, $fromValues->rateStrategy);
        $this->assertEquals('LessRecent', $fromEnums->searchCacheLevel);
        $this->assertSame(RateFilterStrategy::ALL_RATES, $fromEnums->rateStrategy);
    }

    public function test_hotel_search_rejects_cache_levels_amadeus_does_not_accept(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('search_cache_level: must be one of: Live, VeryRecent, LessRecent');

        HotelSearchParams::fromArray(['hotel_city_code' => 'MTY', 'search_cache_level' => 'SlightlyLessRecent']);
    }

    public function test_hotel_search_rejects_unknown_rate_strategy(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('rate_strategy: must be one of: best_only, all_rates');

        HotelSearchParams::fromArray(['hotel_city_code' => 'MTY', 'rate_strategy' => 'two_phase']);
    }

    public function test_hotel_search_builds_rate_filter_criteria_from_array(): void
    {
        $params = HotelSearchParams::fromArray([
            'hotel_code' => 'MTYHLT',
            'rate_filter_criteria' => ['refundable_only' => true, 'max_rates' => 3],
        ]);

        $this->assertInstanceOf(RateFilterCriteria::class, $params->rateFilterCriteria);
        $this->assertTrue($params->rateFilterCriteria->refundableOnly);
        $this->assertSame(3, $params->rateFilterCriteria->maxRates);
    }

    public function test_hotel_search_rejects_rate_filter_criteria_without_hotel_code(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('rate_filter_criteria: requires hotel_code');

        HotelSearchParams::fromArray(['hotel_city_code' => 'MTY', 'rate_filter_criteria' => ['max_rates' => 1]]);
    }

    public function test_hotel_search_rejects_invalid_rate_filter_criteria(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('rate_filter_criteria');

        HotelSearchParams::fromArray(['hotel_code' => 'MTYHLT', 'rate_filter_criteria' => 'refundable']);
    }

    // --- HotelPricingParams ---

    public function test_hotel_pricing_requires_all_fields(): void
    {
        $this->expectException(InvalidParameterException::class);

        HotelPricingParams::fromArray([]);
    }

    public function test_hotel_pricing_reports_specific_missing_fields(): void
    {
        try {
            HotelPricingParams::fromArray(['start' => '2026-03-01', 'end' => '2026-03-03']);
            $this->fail('Expected InvalidParameterException');
        } catch (InvalidParameterException $e) {
            $errors = $e->getValidationErrors();
            $this->assertArrayHasKey('hotel_code', $errors);
            $this->assertArrayHasKey('rate_plan_code', $errors);
            $this->assertArrayHasKey('booking_code', $errors);
            $this->assertArrayNotHasKey('start', $errors);
        }
    }

    public function test_hotel_pricing_validates_date_format(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('YYYY-MM-DD');

        HotelPricingParams::fromArray([
            'start' => '03/01/2026',
            'end' => '2026-03-03',
            'hotel_code' => 'MTYHLT',
            'rate_plan_code' => 'RAC',
            'booking_code' => 'ABCDE',
            'room_type_code' => 'A1K',
            'quantity' => '1',
            'guest_count' => '1',
        ]);
    }

    public function test_hotel_pricing_passes_with_valid_data(): void
    {
        $params = HotelPricingParams::fromArray([
            'start' => '2026-03-01',
            'end' => '2026-03-03',
            'hotel_code' => 'MTYHLT',
            'rate_plan_code' => 'RAC',
            'booking_code' => 'ABCDE',
            'room_type_code' => 'A1K',
            'quantity' => '1',
            'guest_count' => '1',
        ]);

        $this->assertEquals('MTYHLT', $params->hotelCode);
        $this->assertEquals('2026-03-01', $params->start);
    }

    // --- HotelDescriptiveInfoParams ---

    public function test_hotel_descriptive_info_requires_hotel_code(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('hotelCode');

        HotelDescriptiveInfoParams::fromArray([]);
    }

    public function test_hotel_descriptive_info_passes_with_code(): void
    {
        $params = HotelDescriptiveInfoParams::fromArray(['hotelCode' => 'MTYHLT']);

        $this->assertEquals('MTYHLT', $params->hotelCode);
    }

    // --- HotelCompleteReservationDetailsParams ---

    public function test_hcrd_requires_both_fields(): void
    {
        $this->expectException(InvalidParameterException::class);

        HotelCompleteReservationDetailsParams::fromArray([]);
    }

    public function test_hcrd_passes_with_valid_data(): void
    {
        $params = HotelCompleteReservationDetailsParams::fromArray([
            'pnrNumber' => 'ABC123',
            'segmentNumber' => '2',
        ]);

        $this->assertEquals('ABC123', $params->pnrNumber);
        $this->assertEquals('2', $params->segmentNumber);
    }

    // --- HotelSellParams ---

    public function test_hotel_sell_requires_travel_agent_ref(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('travelAgentRef');

        HotelSellParams::fromArray([]);
    }

    // --- PnrRetrieveParams ---

    public function test_pnr_retrieve_requires_pnr_number(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('pnrNumber');

        PnrRetrieveParams::fromArray([]);
    }

    public function test_pnr_retrieve_rejects_empty_pnr(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('pnrNumber');

        PnrRetrieveParams::fromArray(['pnrNumber' => '']);
    }

    public function test_pnr_retrieve_passes_with_valid_data(): void
    {
        $params = PnrRetrieveParams::fromArray(['pnrNumber' => 'ABC123']);

        $this->assertEquals('ABC123', $params->pnrNumber);
    }

    // --- PnrCancelParams ---

    public function test_pnr_cancel_requires_segment_number(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('segmentNumber');

        PnrCancelParams::fromArray([]);
    }

    public function test_pnr_cancel_passes_with_single_segment(): void
    {
        $params = PnrCancelParams::fromArray(['segmentNumber' => '2']);

        $this->assertEquals('2', $params->segmentNumber);
    }

    public function test_pnr_cancel_passes_with_array_segments(): void
    {
        $params = PnrCancelParams::fromArray(['segmentNumber' => ['2', '3']]);

        $this->assertEquals(['2', '3'], $params->segmentNumber);
    }

    // --- InvalidParameterException ---

    public function test_exception_exposes_validation_errors(): void
    {
        try {
            HotelPricingParams::fromArray([]);
            $this->fail('Expected InvalidParameterException');
        } catch (InvalidParameterException $e) {
            $errors = $e->getValidationErrors();
            $this->assertNotEmpty($errors);
            $this->assertIsArray($errors);
            // All required fields should be listed
            $this->assertArrayHasKey('start', $errors);
            $this->assertArrayHasKey('end', $errors);
            $this->assertArrayHasKey('hotel_code', $errors);
        }
    }
}
