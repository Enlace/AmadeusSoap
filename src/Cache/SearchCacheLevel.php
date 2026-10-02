<?php

namespace Aldogtz\AmadeusSoap\Cache;

/**
 * Amadeus server-side availability cache (OTA_HotelAvailRQ@SearchCacheLevel).
 *
 * These are the only values the Amadeus schema accepts. Cached levels answer
 * faster with slightly older availability; use Live before pricing and sell.
 */
enum SearchCacheLevel: string
{
    /** Real-time availability straight from the provider. */
    case LIVE = 'Live';

    /** Availability cached by Amadeus a few minutes ago. */
    case VERY_RECENT = 'VeryRecent';

    /** Older cached availability: fastest, least accurate. */
    case LESS_RECENT = 'LessRecent';

    /**
     * @return string[]
     */
    public static function values(): array
    {
        return array_column(self::cases(), 'value');
    }
}
