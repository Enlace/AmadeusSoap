<?php

namespace Aldogtz\AmadeusSoap\RateFiltering;

use Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult;

/**
 * Applies RateFilterCriteria to the room stays of a single-hotel search.
 *
 * Order: filter → sort by price → drop near-duplicate prices → apply the
 * requested sort → cap at maxRates. Prices are after-tax totals; room stays
 * without one are never dropped as near-duplicates and sort after priced ones.
 */
final class RateFilter
{
    public function __construct(
        private readonly RateFilterCriteria $criteria,
    ) {}

    /**
     * @param  RoomStayResult[]  $roomStays
     * @return RoomStayResult[]
     */
    public function apply(array $roomStays): array
    {
        $rates = array_values(array_filter($roomStays, $this->matches(...)));

        usort($rates, fn (RoomStayResult $a, RoomStayResult $b) => $this->price($a) <=> $this->price($b));

        if ($this->criteria->minPriceDifference !== null) {
            $rates = $this->dropNearDuplicates($rates, $this->criteria->minPriceDifference);
        }

        if ($this->criteria->sortBy === RateFilterCriteria::SORT_PRICE_DESC) {
            usort($rates, fn (RoomStayResult $a, RoomStayResult $b) => $this->price($b, -PHP_FLOAT_MAX) <=> $this->price($a, -PHP_FLOAT_MAX));
        }

        if ($this->criteria->maxRates !== null) {
            $rates = array_slice($rates, 0, $this->criteria->maxRates);
        }

        return $rates;
    }

    private function matches(RoomStayResult $roomStay): bool
    {
        // Rates whose refundability Amadeus does not state pass neither filter
        if ($this->criteria->refundableOnly && $roomStay->nonRefundable !== false) {
            return false;
        }

        if ($this->criteria->nonRefundableOnly && $roomStay->nonRefundable !== true) {
            return false;
        }

        // OTA booleans arrive as "1"/"0" or "true"/"false"
        if ($this->criteria->breakfastIncluded
            && ! in_array(strtolower($roomStay->meals->breakfast), ['1', 'true'], true)) {
            return false;
        }

        if ($this->criteria->ratePlanCodes !== []
            && ! in_array($roomStay->ratePlanCode, $this->criteria->ratePlanCodes, true)) {
            return false;
        }

        return true;
    }

    /**
     * @param  RoomStayResult[]  $sortedAsc
     * @return RoomStayResult[]
     */
    private function dropNearDuplicates(array $sortedAsc, float $minDifference): array
    {
        $kept = [];
        $lastPrice = null;

        foreach ($sortedAsc as $rate) {
            $price = $this->afterTaxPrice($rate);

            if ($price === null || $lastPrice === null || $price - $lastPrice >= $minDifference) {
                $kept[] = $rate;
                $lastPrice = $price ?? $lastPrice;
            }
        }

        return $kept;
    }

    private function price(RoomStayResult $roomStay, float $missing = PHP_FLOAT_MAX): float
    {
        return $this->afterTaxPrice($roomStay) ?? $missing;
    }

    /**
     * After-tax total, or null when unknown. A missing AmountAfterTax parses
     * as 0.0, which must not make the rate look like the cheapest.
     */
    private function afterTaxPrice(RoomStayResult $roomStay): ?float
    {
        $amount = $roomStay->total?->amountAfterTax;

        return $amount !== null && $amount > 0 ? $amount : null;
    }
}
