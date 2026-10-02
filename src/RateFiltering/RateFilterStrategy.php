<?php

namespace Aldogtz\AmadeusSoap\RateFiltering;

/**
 * How many rates Amadeus returns per hotel in a multi-hotel search
 * (HotelSearchCriteria@BestOnlyIndicator).
 *
 * Single-hotel searches don't set it: they return every rate matching the
 * requested rate codes (rate_code); narrow those down locally with
 * RateFilterCriteria.
 */
enum RateFilterStrategy: string
{
    /**
     * Only the best (lowest) rate per hotel: smallest and fastest response.
     */
    case BEST_ONLY = 'best_only';

    /**
     * Every available rate per hotel: largest and slowest response.
     */
    case ALL_RATES = 'all_rates';

    /**
     * @return string[]
     */
    public static function values(): array
    {
        return array_column(self::cases(), 'value');
    }
}
