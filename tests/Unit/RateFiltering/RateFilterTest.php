<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\RateFiltering;

use Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult;
use Aldogtz\AmadeusSoap\Data\Responses\Values\MealsIncluded;
use Aldogtz\AmadeusSoap\Data\Responses\Values\RoomTotal;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilter;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterCriteria;
use PHPUnit\Framework\TestCase;

class RateFilterTest extends TestCase
{
    protected function roomStay(
        string $bookingCode,
        ?float $total,
        string $ratePlanCode = 'RAC',
        ?bool $nonRefundable = false,
        string $breakfast = '0',
    ): RoomStayResult {
        return new RoomStayResult(
            rph: $bookingCode,
            roomType: 'S1K',
            roomTypeCode: '*1K',
            bookingCode: $bookingCode,
            ratePlanCode: $ratePlanCode,
            ratePlanCategory: 'Converted:BAR:P',
            guaranteeCode: '31',
            numberOfUnits: '1',
            nonRefundable: $nonRefundable,
            total: $total === null ? null : new RoomTotal($total, $total, 'MXN'),
            currency: 'MXN',
            start: '2026-08-30',
            end: '2026-08-31',
            dailyRates: [],
            amenities: [],
            meals: new MealsIncluded(mealPlanCodes: '', breakfast: $breakfast, mealPlanIndicator: ''),
        );
    }

    /**
     * @param  RoomStayResult[]  $roomStays
     * @return string[]
     */
    protected function apply(RateFilterCriteria $criteria, array $roomStays): array
    {
        return array_map(fn (RoomStayResult $r) => $r->bookingCode, (new RateFilter($criteria))->apply($roomStays));
    }

    public function test_without_criteria_it_only_sorts_by_price(): void
    {
        $result = $this->apply(new RateFilterCriteria, [
            $this->roomStay('B', 300),
            $this->roomStay('A', 100),
            $this->roomStay('C', 200),
        ]);

        $this->assertSame(['A', 'C', 'B'], $result);
    }

    public function test_refundability_filters(): void
    {
        $roomStays = [
            $this->roomStay('FLEX', 200),
            $this->roomStay('NRF', 150, nonRefundable: true),
        ];

        $this->assertSame(['FLEX'], $this->apply(new RateFilterCriteria(refundableOnly: true), $roomStays));
        $this->assertSame(['NRF'], $this->apply(new RateFilterCriteria(nonRefundableOnly: true), $roomStays));
    }

    public function test_unknown_refundability_passes_neither_refundability_filter(): void
    {
        // e.g. a 100% penalty described only in text, without @NonRefundable
        $roomStays = [$this->roomStay('UNKNOWN', 100, nonRefundable: null)];

        $this->assertSame([], $this->apply(new RateFilterCriteria(refundableOnly: true), $roomStays));
        $this->assertSame([], $this->apply(new RateFilterCriteria(nonRefundableOnly: true), $roomStays));
        $this->assertSame(['UNKNOWN'], $this->apply(new RateFilterCriteria, $roomStays));
    }

    public function test_a_missing_after_tax_amount_is_not_the_cheapest_price(): void
    {
        // AmountAfterTax absent from the reply parses as 0.0
        $result = $this->apply(new RateFilterCriteria(maxRates: 1), [
            $this->roomStay('BEFORE_TAX_ONLY', 0.0),
            $this->roomStay('PRICED', 2176),
        ]);

        $this->assertSame(['PRICED'], $result);
    }

    public function test_breakfast_accepts_both_ota_boolean_forms(): void
    {
        $result = $this->apply(new RateFilterCriteria(breakfastIncluded: true), [
            $this->roomStay('ONE', 100, breakfast: '1'),
            $this->roomStay('TRUE', 110, breakfast: 'true'),
            $this->roomStay('ZERO', 90, breakfast: '0'),
            $this->roomStay('EMPTY', 80, breakfast: ''),
        ]);

        $this->assertSame(['ONE', 'TRUE'], $result);
    }

    public function test_rate_plan_codes_filter(): void
    {
        $result = $this->apply(new RateFilterCriteria(ratePlanCodes: ['57J']), [
            $this->roomStay('A', 100, ratePlanCode: 'M85'),
            $this->roomStay('B', 120, ratePlanCode: '57J'),
        ]);

        $this->assertSame(['B'], $result);
    }

    public function test_min_price_difference_drops_near_duplicates(): void
    {
        $result = $this->apply(new RateFilterCriteria(minPriceDifference: 50), [
            $this->roomStay('E', 300),
            $this->roomStay('A', 100),
            $this->roomStay('B', 120),
            $this->roomStay('C', 160),
            $this->roomStay('D', 190),
        ]);

        // B and D are less than 50 above the previous kept rate (A and C)
        $this->assertSame(['A', 'C', 'E'], $result);
    }

    public function test_descending_sort_and_max_rates(): void
    {
        $roomStays = [
            $this->roomStay('A', 100),
            $this->roomStay('B', 300),
            $this->roomStay('C', 200),
        ];

        $this->assertSame(
            ['B', 'C'],
            $this->apply(new RateFilterCriteria(maxRates: 2, sortBy: RateFilterCriteria::SORT_PRICE_DESC), $roomStays),
        );
        $this->assertSame(['A'], $this->apply(new RateFilterCriteria(maxRates: 1), $roomStays));
    }

    public function test_room_stays_without_price_are_kept_and_sorted_last(): void
    {
        $roomStays = [
            $this->roomStay('UNPRICED', null),
            $this->roomStay('A', 100),
            $this->roomStay('B', 120),
        ];

        $this->assertSame(['A', 'UNPRICED'], $this->apply(new RateFilterCriteria(minPriceDifference: 50), $roomStays));
        $this->assertSame(['B', 'A', 'UNPRICED'], $this->apply(new RateFilterCriteria(sortBy: RateFilterCriteria::SORT_PRICE_DESC), $roomStays));
    }
}
