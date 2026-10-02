<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\RateFiltering;

use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterCriteria;
use PHPUnit\Framework\TestCase;

class RateFilterCriteriaTest extends TestCase
{
    public function test_defaults(): void
    {
        $criteria = RateFilterCriteria::fromArray([]);

        $this->assertFalse($criteria->refundableOnly);
        $this->assertFalse($criteria->breakfastIncluded);
        $this->assertSame([], $criteria->ratePlanCodes);
        $this->assertNull($criteria->maxRates);
        $this->assertNull($criteria->minPriceDifference);
        $this->assertSame(RateFilterCriteria::SORT_PRICE_ASC, $criteria->sortBy);
    }

    public function test_it_maps_array_keys(): void
    {
        $criteria = RateFilterCriteria::fromArray([
            'refundable_only' => true,
            'breakfast_included' => true,
            'rate_plan_codes' => '57J',
            'max_rates' => '5',
            'min_price_difference' => '50',
            'sort_by' => 'price_desc',
        ]);

        $this->assertTrue($criteria->refundableOnly);
        $this->assertTrue($criteria->breakfastIncluded);
        $this->assertSame(['57J'], $criteria->ratePlanCodes);
        $this->assertSame(5, $criteria->maxRates);
        $this->assertSame(50.0, $criteria->minPriceDifference);
        $this->assertSame(RateFilterCriteria::SORT_PRICE_DESC, $criteria->sortBy);
    }

    public function test_boolean_strings_from_query_strings_are_parsed(): void
    {
        $criteria = RateFilterCriteria::fromArray([
            'refundable_only' => 'false',
            'non_refundable_only' => '0',
            'breakfast_included' => 'true',
        ]);

        $this->assertFalse($criteria->refundableOnly);
        $this->assertFalse($criteria->nonRefundableOnly);
        $this->assertTrue($criteria->breakfastIncluded);
    }

    public function test_it_rejects_non_boolean_flags(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('breakfast_included: must be a boolean');

        RateFilterCriteria::fromArray(['breakfast_included' => 'sometimes']);
    }

    public function test_it_reports_every_invalid_field(): void
    {
        try {
            RateFilterCriteria::fromArray([
                'refundable_only' => true,
                'non_refundable_only' => true,
                'sort_by' => 'popularity',
                'max_rates' => 0,
                'min_price_difference' => -1,
            ]);
            $this->fail('Expected InvalidParameterException');
        } catch (InvalidParameterException $e) {
            $this->assertSame(
                ['refundable_only', 'sort_by', 'max_rates', 'min_price_difference'],
                array_keys($e->getValidationErrors()),
            );
        }
    }
}
