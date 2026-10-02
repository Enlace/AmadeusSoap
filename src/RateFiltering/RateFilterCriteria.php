<?php

namespace Aldogtz\AmadeusSoap\RateFiltering;

use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;

/**
 * Criteria to narrow down the rates (room stays) of a single-hotel search.
 *
 * Filtering happens locally on the parsed response (see RateFilter): Amadeus
 * has no request-side filter for refundability or breakfast.
 */
final readonly class RateFilterCriteria
{
    public const SORT_PRICE_ASC = 'price_asc';

    public const SORT_PRICE_DESC = 'price_desc';

    /**
     * @param  string[]  $ratePlanCodes  Keep only these rate plan codes (empty = any).
     */
    public function __construct(
        public bool $refundableOnly = false,
        public bool $nonRefundableOnly = false,
        public bool $breakfastIncluded = false,
        public array $ratePlanCodes = [],
        /** Maximum number of rates to keep, applied after sorting. */
        public ?int $maxRates = null,
        /** Drop rates less than this amount above the previous kept (cheaper) rate. */
        public ?float $minPriceDifference = null,
        public string $sortBy = self::SORT_PRICE_ASC,
    ) {}

    /**
     * @throws InvalidParameterException
     */
    public static function fromArray(array $data): self
    {
        $errors = [];

        $refundableOnly = self::flag($data, 'refundable_only', $errors);
        $nonRefundableOnly = self::flag($data, 'non_refundable_only', $errors);
        $breakfastIncluded = self::flag($data, 'breakfast_included', $errors);

        if ($refundableOnly && $nonRefundableOnly) {
            $errors['refundable_only'] = 'cannot be combined with non_refundable_only';
        }

        $sortBy = $data['sort_by'] ?? self::SORT_PRICE_ASC;
        if (! in_array($sortBy, [self::SORT_PRICE_ASC, self::SORT_PRICE_DESC], true)) {
            $errors['sort_by'] = "must be 'price_asc' or 'price_desc', got '{$sortBy}'";
        }

        if (isset($data['max_rates']) && (int) $data['max_rates'] < 1) {
            $errors['max_rates'] = 'must be at least 1';
        }

        if (isset($data['min_price_difference']) && (float) $data['min_price_difference'] < 0) {
            $errors['min_price_difference'] = 'must not be negative';
        }

        if (! empty($errors)) {
            throw InvalidParameterException::forValidation('RateFilterCriteria', $errors);
        }

        return new self(
            refundableOnly: $refundableOnly,
            nonRefundableOnly: $nonRefundableOnly,
            breakfastIncluded: $breakfastIncluded,
            ratePlanCodes: array_values((array) ($data['rate_plan_codes'] ?? [])),
            maxRates: isset($data['max_rates']) ? (int) $data['max_rates'] : null,
            minPriceDifference: isset($data['min_price_difference']) ? (float) $data['min_price_difference'] : null,
            sortBy: $sortBy,
        );
    }

    /**
     * Boolean flag that may come from a query string ("false" must be false).
     *
     * @param  array<string, string>  $errors
     */
    private static function flag(array $data, string $key, array &$errors): bool
    {
        if (! isset($data[$key])) {
            return false;
        }

        $value = filter_var($data[$key], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        if ($value === null) {
            $errors[$key] = 'must be a boolean';

            return false;
        }

        return $value;
    }
}
