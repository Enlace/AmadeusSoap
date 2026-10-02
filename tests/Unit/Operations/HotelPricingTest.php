<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\HotelPricingParams;
use Aldogtz\AmadeusSoap\Operations\HotelPricing;
use PHPUnit\Framework\TestCase;

class HotelPricingTest extends TestCase
{
    public function test_it_returns_correct_operation_name(): void
    {
        $params = HotelPricingParams::fromArray([
            'start' => '2026-03-01', 'end' => '2026-03-03',
            'hotel_code' => 'MTYHLT', 'rate_plan_code' => 'RAC',
            'booking_code' => 'A1K', 'room_type_code' => 'A1K',
            'quantity' => '1', 'guest_count' => '1',
        ]);
        $operation = new HotelPricing($params);

        $this->assertEquals('Hotel_EnhancedPricing', $operation->getOperationName());
    }

    public function test_it_builds_pricing_body(): void
    {
        $params = HotelPricingParams::fromArray([
            'start' => '2026-03-01', 'end' => '2026-03-05',
            'hotel_code' => 'MTYHLT', 'rate_plan_code' => 'RAC',
            'booking_code' => 'ABCDE', 'room_type_code' => 'A1K',
            'quantity' => '2', 'guest_count' => '3',
        ]);
        $operation = new HotelPricing($params);
        $body = $operation->build();

        $criterion = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion'];
        $this->assertEquals('MTYHLT', $criterion['HotelRef']['_attributes']['HotelCode']);
        $this->assertEquals('2026-03-01', $criterion['StayDateRange']['_attributes']['Start']);
        $this->assertEquals('2026-03-05', $criterion['StayDateRange']['_attributes']['End']);
        $this->assertEquals('RAC', $criterion['RatePlanCandidates']['RatePlanCandidate']['_attributes']['RatePlanCode']);
        $this->assertEquals('ABCDE', $criterion['RoomStayCandidates']['RoomStayCandidate']['_attributes']['BookingCode']);
        $this->assertEquals('A1K', $criterion['RoomStayCandidates']['RoomStayCandidate']['_attributes']['RoomTypeCode']);
        $this->assertEquals('2', $criterion['RoomStayCandidates']['RoomStayCandidate']['_attributes']['Quantity']);
    }

    public function test_it_includes_children_counts(): void
    {
        $params = HotelPricingParams::fromArray([
            'start' => '2026-03-01', 'end' => '2026-03-03',
            'hotel_code' => 'MTYHLT', 'rate_plan_code' => 'RAC',
            'booking_code' => 'A1K', 'room_type_code' => 'A1K',
            'quantity' => '1', 'guest_count' => '2',
            'children' => [['age' => '5', 'count' => '1']],
        ]);
        $operation = new HotelPricing($params);
        $body = $operation->build();

        $guestCounts = $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RoomStayCandidates']['RoomStayCandidate']['GuestCounts']['GuestCount'];
        $this->assertCount(2, $guestCounts);
    }
}
