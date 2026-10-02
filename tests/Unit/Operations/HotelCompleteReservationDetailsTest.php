<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\HotelCompleteReservationDetailsParams;
use Aldogtz\AmadeusSoap\Operations\HotelCompleteReservationDetails;
use PHPUnit\Framework\TestCase;

class HotelCompleteReservationDetailsTest extends TestCase
{
    public function test_it_returns_correct_operation_name(): void
    {
        $params = HotelCompleteReservationDetailsParams::fromArray(['pnrNumber' => 'ABC123', 'segmentNumber' => '2']);
        $operation = new HotelCompleteReservationDetails($params);

        $this->assertEquals('Hotel_CompleteReservationDetails', $operation->getOperationName());
    }

    public function test_it_builds_retrieval_body(): void
    {
        $params = HotelCompleteReservationDetailsParams::fromArray(['pnrNumber' => 'ABC123', 'segmentNumber' => '2']);
        $operation = new HotelCompleteReservationDetails($params);
        $body = $operation->build();

        $this->assertArrayHasKey('retrievalKeyGroup', $body);
        $this->assertEquals('ABC123', $body['retrievalKeyGroup']['retrievalKey']['reservation']['controlNumber']);
        $this->assertEquals('2', $body['retrievalKeyGroup']['tattooID']['referenceDetails']['value']);
        $this->assertEquals('S', $body['retrievalKeyGroup']['tattooID']['referenceDetails']['type']);
    }
}
