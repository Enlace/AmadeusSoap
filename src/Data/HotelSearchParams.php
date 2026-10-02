<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Cache\SearchCacheLevel;
use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;
use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterCriteria;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterStrategy;
use Illuminate\Support\Carbon;

final readonly class HotelSearchParams
{
    use ValidatesParams;

    public function __construct(
        public string $type = 'multi',
        public ?string $start = null,
        public ?string $end = null,
        public string $quantity = '1',
        public string $guestCount = '1',
        public array $children = [],
        public ?string $hotelCode = null,
        public ?string $hotelCityCode = null,
        public ?string $hotelName = null,
        public ?string $chainCode = null,
        public ?string $latitude = null,
        public ?string $longitude = null,
        public string $distance = '15',
        public string $infoSource = 'Distribution',
        public string $searchCacheLevel = 'Live',
        public string $maxResponses = '96',
        public string|array $rateCode = 'RAC',
        public ?string $currency = 'MXN',
        public ?string $sortOrder = null,
        public ?int $rating = null,
        public ?string $maxRate = null,
        public ?string $minRate = null,
        public ?string $moreDataEchoToken = null,
        // BestOnlyIndicator for multi-hotel searches
        public RateFilterStrategy $rateStrategy = RateFilterStrategy::BEST_ONLY,
        // Local filtering of the returned room stays
        public ?RateFilterCriteria $rateFilterCriteria = null,
    ) {}

    public static function fromArray(array $data): self
    {
        // At least one search criterion must be provided
        $hasHotelCode = ! empty($data['hotel_code']);
        $hasCityCode = ! empty($data['hotel_city_code']);
        $hasHotelName = ! empty($data['hotel_name']);
        $hasCoords = ! empty($data['latitude']) && ! empty($data['longitude']);

        if (! $hasHotelCode && ! $hasCityCode && ! $hasHotelName && ! $hasCoords) {
            self::validateRequired($data, ['hotel_city_code'], 'HotelSearchParams');
        }

        // Validate dates when explicitly provided
        $dateFields = [];
        if (isset($data['start'])) {
            $dateFields[] = 'start';
        }
        if (isset($data['end'])) {
            $dateFields[] = 'end';
        }
        if (! empty($dateFields)) {
            self::validateDates($data, $dateFields, 'HotelSearchParams');
        }

        $searchCacheLevel = self::resolveEnum($data, 'search_cache_level', SearchCacheLevel::class, SearchCacheLevel::LIVE, 'HotelSearchParams');
        $rateStrategy = self::resolveEnum($data, 'rate_strategy', RateFilterStrategy::class, RateFilterStrategy::BEST_ONLY, 'HotelSearchParams');
        $rateFilterCriteria = self::resolveRateFilterCriteria($data['rate_filter_criteria'] ?? null);

        // Room stays of different hotels (and currencies) can't be ranked together
        if ($rateFilterCriteria !== null && ! $hasHotelCode) {
            throw InvalidParameterException::forValidation('HotelSearchParams', [
                'rate_filter_criteria' => 'requires hotel_code: it filters the rates of a single hotel',
            ]);
        }

        return new self(
            type: $data['type'] ?? 'multi',
            start: $data['start'] ?? Carbon::now()->toDateString(),
            end: $data['end'] ?? Carbon::now()->addDays(7)->toDateString(),
            quantity: (string) ($data['quantity'] ?? '1'),
            guestCount: (string) ($data['guest_count'] ?? '1'),
            children: $data['children'] ?? [],
            hotelCode: $data['hotel_code'] ?? null,
            hotelCityCode: $data['hotel_city_code'] ?? null,
            hotelName: $data['hotel_name'] ?? null,
            chainCode: $data['chain_code'] ?? null,
            latitude: isset($data['latitude']) ? (string) $data['latitude'] : null,
            longitude: isset($data['longitude']) ? (string) $data['longitude'] : null,
            distance: (string) ($data['distance'] ?? '15'),
            infoSource: $data['info_source'] ?? 'Distribution',
            searchCacheLevel: $searchCacheLevel->value,
            maxResponses: (string) ($data['max_responses'] ?? '96'),
            rateCode: $data['rate_code'] ?? 'RAC',
            currency: $data['currency'] ?? $data['Currency'] ?? 'MXN',
            sortOrder: $data['sort_order'] ?? null,
            rating: isset($data['rating']) ? (int) $data['rating'] : null,
            maxRate: $data['max_rate'] ?? null,
            minRate: $data['min_rate'] ?? null,
            moreDataEchoToken: $data['more_data_echo_token'] ?? null,
            rateStrategy: $rateStrategy,
            rateFilterCriteria: $rateFilterCriteria,
        );
    }

    /**
     * @throws InvalidParameterException
     */
    private static function resolveRateFilterCriteria(mixed $criteria): ?RateFilterCriteria
    {
        if ($criteria === null || $criteria instanceof RateFilterCriteria) {
            return $criteria;
        }

        if (is_array($criteria)) {
            return RateFilterCriteria::fromArray($criteria);
        }

        throw InvalidParameterException::forValidation('HotelSearchParams', [
            'rate_filter_criteria' => 'must be an array or a RateFilterCriteria instance, got '.get_debug_type($criteria),
        ]);
    }
}
