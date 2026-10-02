<?php

namespace Aldogtz\AmadeusSoap\RateFiltering;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Cache\SearchCacheLevel;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;

/**
 * Two-phase hotel search: a light listing first, full rates on demand.
 *
 * Phase 1 (quickSearch) is a multi-hotel search returning only the best rate
 * per hotel. Phase 2 (detailedRates) is a single-hotel search returning every
 * rate for the requested rate codes, optionally narrowed down locally with
 * RateFilterCriteria.
 *
 * Phase 2 is stateful: it starts the Amadeus session that pricing and sell
 * continue, and every call starts a new one (signing the stored session out).
 * Call it for the hotel the user is about to book, right before pricing —
 * not in a loop over several hotels.
 */
class TwoPhaseSearchService
{
    public function __construct(
        protected AmadeusSoap $amadeus,
        protected string $listingCacheLevel = SearchCacheLevel::VERY_RECENT->value,
        protected string $detailsCacheLevel = SearchCacheLevel::VERY_RECENT->value,
    ) {}

    /**
     * Phase 1: multi-hotel listing with the best rate per hotel.
     *
     * An explicit search_cache_level in $params wins over the listing default.
     */
    public function quickSearch(array $params): HotelSearchResponse
    {
        return $this->amadeus->hotelSearch('multi', array_merge(
            ['search_cache_level' => $this->listingCacheLevel],
            $params,
            ['rate_strategy' => RateFilterStrategy::BEST_ONLY],
        ));
    }

    /**
     * Phase 2: the rates of one hotel for the requested rate_code, filtered
     * locally when criteria are given.
     *
     * @param  bool  $fresh  Force Live availability (e.g. right before pricing).
     */
    public function detailedRates(
        string $hotelCode,
        array $params,
        ?RateFilterCriteria $criteria = null,
        bool $fresh = false,
    ): HotelSearchResponse {
        $overrides = ['hotel_code' => $hotelCode];

        if ($fresh) {
            $overrides['search_cache_level'] = SearchCacheLevel::LIVE->value;
        }

        if ($criteria !== null) {
            $overrides['rate_filter_criteria'] = $criteria;
        }

        return $this->amadeus->hotelSearch('single', array_merge(
            ['search_cache_level' => $this->detailsCacheLevel],
            $params,
            $overrides,
        ));
    }
}
